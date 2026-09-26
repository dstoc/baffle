//! Rama implementation of the proxy-runtime boundary.
//!
//! The backend serves directly from Baffle's private Unix socket. It
//! accepts only CONNECT requests, authorizes the CONNECT authority before
//! dialing, and fails closed if TLS inspection cannot be established.

use std::{
    collections::HashMap,
    ffi::CString,
    fs, io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{ffi::OsStrExt, fs::PermissionsExt},
    },
    path::{Component, Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex, OnceLock},
    task::{Context, Poll},
    time::Duration,
};

use super::{ProxyRuntimeError, ProxyRuntimeEvent, RuntimeId};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rama::{
    Layer, Service,
    extensions::{Extensions, ExtensionsRef},
    http::proxy::mitm::HttpMitmRelay,
    io::{BridgeIo, peek::PeekTimeoutPolicy},
    rt::Executor,
    tcp::TcpStream as RamaTcpStream,
    tls::{
        KeyLogIntent,
        boring::{
            client::{BoringClientConfigExt as _, TlsConnectorData},
            proxy::TlsMitmRelay,
        },
        client::{ServerVerifyMode, TlsClientConfig},
        server::peek_client_hello_from_input_with_timeout_policy,
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpStream, UnixListener},
    sync::Semaphore,
    task::{AbortHandle, JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

use crate::{
    ca::ManagedCa,
    config::{HeaderInjection, InjectionFormat, RuleMode, SessionConfig},
    policy::{AuthorizationError, Destination, RequestFacts, SessionPolicy},
    secrets::{ResolvedSecrets, SecretValue},
    telemetry::Metrics,
};

const MAX_CONNECT_HEADER_BYTES: usize = 16 * 1024;

/// An opaque proxy session served directly on its private Unix socket.
pub struct ProxyRuntime {
    runtime_id: RuntimeId,
    socket_path: PathBuf,
    cancellation: CancellationToken,
    task_abort: AbortHandle,
    task: JoinHandle<()>,
    metrics: Arc<Metrics>,
}

impl ProxyRuntime {
    /// Bind and start one runtime from a validated session configuration.
    ///
    /// Success means the private Unix socket is bound. The returned handle owns
    /// all runtime tasks until bounded shutdown or cancellation on drop.
    pub async fn start(
        runtime_id: RuntimeId,
        session: SessionConfig,
        ca: Arc<ManagedCa>,
        socket_path: PathBuf,
        max_connections: usize,
        events: tokio::sync::mpsc::UnboundedSender<ProxyRuntimeEvent>,
    ) -> Result<Self, ProxyRuntimeError> {
        Self::start_with_metrics(
            runtime_id,
            session,
            Arc::new(ResolvedSecrets::default()),
            ca,
            socket_path,
            max_connections,
            Duration::from_secs(30),
            Arc::new(Metrics::default()),
            events,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn start_with_metrics(
        runtime_id: RuntimeId,
        session: SessionConfig,
        secrets: Arc<ResolvedSecrets>,
        ca: Arc<ManagedCa>,
        socket_path: PathBuf,
        max_connections: usize,
        io_timeout: Duration,
        metrics: Arc<Metrics>,
        events: tokio::sync::mpsc::UnboundedSender<ProxyRuntimeEvent>,
    ) -> Result<Self, ProxyRuntimeError> {
        let (unix_listener, socket_guard) =
            bind_unix_listener(&socket_path).map_err(ProxyRuntimeError::BindSocket)?;

        let policy = Arc::new(SessionPolicy::compile(&session));
        let cancellation = CancellationToken::new();
        let mut proxy_task = tokio::spawn(run_proxy(
            unix_listener,
            socket_guard,
            ProxySettings {
                policy,
                secrets,
                ca,
                permits: Arc::new(Semaphore::new(max_connections)),
                cancellation: cancellation.clone(),
                metrics: Arc::clone(&metrics),
                io_timeout,
            },
        ));
        let task_abort = proxy_task.abort_handle();
        let event_id = runtime_id.clone();
        let task = tokio::spawn(async move {
            let result = map_proxy_join((&mut proxy_task).await);
            if result.is_err() {
                tracing::error!(
                    event = "session_lifecycle",
                    session_id = %event_id.as_str(),
                    state = "failed",
                    "Rama proxy session task failed"
                );
            }
            let _ = events.send(ProxyRuntimeEvent {
                runtime_id: event_id,
                result,
            });
        });

        Ok(Self {
            runtime_id,
            socket_path,
            cancellation,
            task_abort,
            task,
            metrics,
        })
    }

    pub fn runtime_id(&self) -> &RuntimeId {
        &self.runtime_id
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Cancel ingress, drain active work, then abort after the grace period.
    pub async fn shutdown(mut self, grace: Duration) {
        tracing::info!(
            event = "session_lifecycle",
            session_id = %self.runtime_id.as_str(),
            state = "stopping",
            "Rama proxy session shutdown started"
        );
        self.cancellation.cancel();
        if tokio::time::timeout(grace, &mut self.task).await.is_err() {
            self.metrics.forced_shutdown();
            self.task_abort.abort();
            let _ = (&mut self.task).await;
        }
    }
}

impl Drop for ProxyRuntime {
    fn drop(&mut self) {
        self.cancellation.cancel();
        // If the session owner is cancelled while awaiting graceful shutdown,
        // do not detach the proxy connection tasks.
        self.task_abort.abort();
    }
}

fn map_proxy_join(
    result: Result<Result<(), ProxyRuntimeError>, tokio::task::JoinError>,
) -> Result<(), ProxyRuntimeError> {
    result.map_err(|error| ProxyRuntimeError::Task(error.to_string()))?
}

struct ProxySettings {
    policy: Arc<SessionPolicy>,
    secrets: Arc<ResolvedSecrets>,
    ca: Arc<ManagedCa>,
    permits: Arc<Semaphore>,
    cancellation: CancellationToken,
    metrics: Arc<Metrics>,
    io_timeout: Duration,
}

async fn run_proxy(
    listener: UnixListener,
    socket_guard: UnixSocketGuard,
    settings: ProxySettings,
) -> Result<(), ProxyRuntimeError> {
    let ProxySettings {
        policy,
        secrets,
        ca,
        permits,
        cancellation,
        metrics,
        io_timeout,
    } = settings;
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    return Err(ProxyRuntimeError::Task(error.to_string()));
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(ProxyRuntimeError::BindSocket)?;
                let permit = match Arc::clone(&permits).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => continue,
                };
                let policy = Arc::clone(&policy);
                let secrets = Arc::clone(&secrets);
                let ca = Arc::clone(&ca);
                let metrics = Arc::clone(&metrics);
                connections.spawn(async move {
                    let _permit = permit;
                    metrics.connection_started();
                    let _guard = ConnectionGuard(Arc::clone(&metrics));
                    if let Err(error) = handle_client(stream, policy, secrets, ca, metrics, io_timeout).await {
                        tracing::debug!(?error, "Rama connection closed after a proxy error");
                    }
                });
            }
        }
    }
    drop(listener);
    drop(socket_guard);
    while connections.join_next().await.is_some() {}
    Ok(())
}

async fn handle_client<S>(
    mut client: S,
    policy: Arc<SessionPolicy>,
    secrets: Arc<ResolvedSecrets>,
    ca: Arc<ManagedCa>,
    metrics: Arc<Metrics>,
    io_timeout: Duration,
) -> Result<(), ProxyRuntimeError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let parsed = match tokio::time::timeout(io_timeout, read_connect_request(&mut client)).await {
        Ok(Ok(parsed)) => parsed,
        Ok(Err(error)) => {
            let _ = client
                .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                .await;
            return Err(ProxyRuntimeError::Run(error.to_string()));
        }
        Err(_) => {
            let _ = client
                .write_all(b"HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\n")
                .await;
            return Ok(());
        }
    };

    let host_headers = parsed.host.as_deref().into_iter().collect::<Vec<_>>();
    let (mode, destination) =
        match policy.authorize_connect_authority(&parsed.authority, &host_headers) {
            Ok(authorized) => authorized,
            Err(_) => {
                metrics.denied_request();
                let _ = client
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
                    .await;
                return Ok(());
            }
        };
    if parsed.has_body {
        metrics.denied_request();
        let _ = client
            .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            .await;
        return Ok(());
    }

    if mode == RuleMode::Tunnel {
        return handle_tunnel(client, destination, io_timeout, &metrics).await;
    }

    // Read and bind TLS identity before dialing. After CONNECT succeeds, any
    // malformed or unauthorized ClientHello closes the client connection.
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(|error| ProxyRuntimeError::Run(error.to_string()))?;

    let client = RamaIo::new(client);
    let (client, client_hello) = match peek_client_hello_from_input_with_timeout_policy(
        client,
        Some(io_timeout),
        PeekTimeoutPolicy::FailClosed,
    )
    .await
    {
        Ok((client, Some(client_hello))) => (client, client_hello),
        Ok((_, None)) => {
            metrics.interception_error();
            return Err(ProxyRuntimeError::Run(
                "interception-required CONNECT did not contain a TLS ClientHello".into(),
            ));
        }
        Err(error) => {
            metrics.interception_error();
            return Err(ProxyRuntimeError::Run(format!(
                "could not inspect TLS ClientHello: {error}"
            )));
        }
    };
    let sni = client_hello.ext_server_name().map(ToString::to_string);
    if !policy.permits_tls_interception_authority(&parsed.authority, sni.as_deref()) {
        metrics.denied_request();
        return Err(ProxyRuntimeError::Run(
            "TLS SNI does not match the authorized CONNECT authority".into(),
        ));
    }

    let egress = match tokio::time::timeout(
        io_timeout,
        TcpStream::connect((destination.host.as_str(), destination.port)),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            metrics.upstream_failure();
            return Err(ProxyRuntimeError::Run(error.to_string()));
        }
        Err(_) => {
            metrics.upstream_failure();
            return Ok(());
        }
    };
    #[cfg(feature = "benchmark-tcp-nodelay")]
    if benchmark_tcp_nodelay_enabled("proxy-egress") {
        egress
            .set_nodelay(true)
            .map_err(|error| ProxyRuntimeError::Run(error.to_string()))?;
    }

    let (certificate, private_key) = ca.runtime_signing_material();
    // Preserve the inspected ClientHello's ALPN and TLS parameters for the
    // upstream connection. Bind the verification identity to the authorized
    // CONNECT target rather than any client-supplied alternate identity.
    let egress_config = TlsClientConfig::new_from_client_hello(&client_hello)
        .with_server_name(rama_host(&destination)?)
        .with_server_verify(ServerVerifyMode::Auto)
        .with_keylog(KeyLogIntent::Disabled);
    // Test runtimes can add a private trust anchor through this helper while
    // production keeps Rama's configured system roots.
    #[cfg(test)]
    let egress_config = match test_upstream_trust_anchor() {
        Some(anchor) => egress_config
            .try_with_server_trust_anchors([anchor])
            .map_err(|error| ProxyRuntimeError::Build(error.to_string()))?,
        None => egress_config,
    };
    #[cfg(baffle_integration_test)]
    let egress_config = match super::integration_test_upstream_root() {
        Ok(Some(anchor)) => egress_config
            .try_with_server_trust_anchors([rama::crypto::pki_types::CertificateDer::from(anchor)])
            .map_err(|error| ProxyRuntimeError::Build(error.to_string()))?,
        Ok(None) => egress_config,
        Err(error) => return Err(ProxyRuntimeError::Build(error)),
    };
    let connector_data = TlsConnectorData::try_from(&egress_config)
        .map_err(|error| ProxyRuntimeError::Build(error.to_string()))?;
    let relay = TlsMitmRelay::new_cached_in_memory(certificate, private_key)
        .with_keylog_intent(KeyLogIntent::Disabled);
    let request_policy = RamaPolicyLayer {
        policy: Arc::clone(&policy),
        connect_authority: parsed.authority.clone(),
        secrets,
        metrics: Arc::clone(&metrics),
    };
    let decrypted = relay
        .handshake(
            BridgeIo(client, RamaTcpStream::new(egress)),
            Some(connector_data),
        )
        .await
        .map_err(|error| {
            metrics.interception_error();
            ProxyRuntimeError::Run(error.to_string())
        })?;
    HttpMitmRelay::new(Executor::default())
        .with_http_middleware(request_policy)
        .serve(decrypted)
        .await
        .map_err(|error| ProxyRuntimeError::Run(error.to_string()))
}

/// Add Rama's connection extensions to a generic Tokio stream. Its TLS
/// relays require this interface even when ingress is a Unix-domain stream.
struct RamaIo<S> {
    inner: S,
    extensions: Extensions,
}

impl<S> RamaIo<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            extensions: Extensions::new(),
        }
    }
}

impl<S> ExtensionsRef for RamaIo<S> {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RamaIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(context, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RamaIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}

#[cfg(test)]
static TEST_UPSTREAM_TRUST_ANCHOR: std::sync::OnceLock<std::sync::Mutex<Option<Vec<u8>>>> =
    std::sync::OnceLock::new();

#[cfg(test)]
fn test_upstream_trust_anchor() -> Option<rama::crypto::pki_types::CertificateDer<'static>> {
    TEST_UPSTREAM_TRUST_ANCHOR
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .expect("test trust anchor lock should not be poisoned")
        .clone()
        .map(rama::crypto::pki_types::CertificateDer::from)
}

#[cfg(test)]
pub(crate) fn set_test_upstream_trust_anchor(anchor: Vec<u8>) {
    *TEST_UPSTREAM_TRUST_ANCHOR
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .expect("test trust anchor lock should not be poisoned") = Some(anchor);
}

fn rama_host(destination: &Destination) -> Result<rama::net::address::Host, ProxyRuntimeError> {
    let domain = rama::net::address::Domain::try_from(destination.host.as_str())
        .map_err(|error| ProxyRuntimeError::Build(error.to_string()))?;
    Ok(rama::net::address::Host::Name(domain))
}

#[derive(Clone)]
struct RamaPolicyLayer {
    policy: Arc<SessionPolicy>,
    connect_authority: String,
    secrets: Arc<ResolvedSecrets>,
    metrics: Arc<Metrics>,
}

impl<S> Layer<S> for RamaPolicyLayer {
    type Service = RamaPolicyService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RamaPolicyService {
            inner: Arc::new(inner),
            policy: Arc::clone(&self.policy),
            connect_authority: self.connect_authority.clone(),
            secrets: Arc::clone(&self.secrets),
            metrics: Arc::clone(&self.metrics),
        }
    }
}

struct RamaPolicyService<S> {
    inner: Arc<S>,
    policy: Arc<SessionPolicy>,
    connect_authority: String,
    secrets: Arc<ResolvedSecrets>,
    metrics: Arc<Metrics>,
}

impl<S> Clone for RamaPolicyService<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            policy: Arc::clone(&self.policy),
            connect_authority: self.connect_authority.clone(),
            secrets: Arc::clone(&self.secrets),
            metrics: Arc::clone(&self.metrics),
        }
    }
}

impl<S> Service<rama::http::Request> for RamaPolicyService<S>
where
    S: Service<rama::http::Request, Output = rama::http::Response> + Send + Sync + 'static,
    S::Error: Into<rama::error::BoxError>,
{
    type Output = rama::http::Response;
    type Error = rama::error::BoxError;

    async fn serve(&self, mut request: rama::http::Request) -> Result<Self::Output, Self::Error> {
        let uri_authority = request.uri().authority().map(|value| value.to_string());
        let mut host_headers = Vec::new();
        for value in request.headers().get_all(rama::http::header::HOST).iter() {
            match value.to_str() {
                Ok(value) => host_headers.push(value.to_owned()),
                Err(_) => return Ok(denied_response(AuthorizationError::InvalidAuthority)),
            }
        }
        let host_headers = host_headers.iter().map(String::as_str).collect::<Vec<_>>();
        let scheme = request.uri().scheme().map(ToString::to_string);
        let path = request
            .uri()
            .path()
            .map(|path| path.to_string())
            .unwrap_or_else(|| "/".to_owned());
        let facts = RequestFacts {
            method: request.method().as_str(),
            scheme: scheme.as_deref(),
            uri_authority: uri_authority.as_deref(),
            path: &path,
            host_headers: &host_headers,
            secure_transport: true,
        };
        let (injections, canonical_path) = match self
            .policy
            .authorize_intercepted_request(&facts, &self.connect_authority)
        {
            Ok(authorized) => authorized,
            Err(error) => {
                self.metrics.denied_request();
                return Ok(denied_response(error));
            }
        };
        if let Some(path) = canonical_path {
            let mut uri = request.uri().clone();
            uri.set_path(path);
            *request.uri_mut() = uri;
        }
        if !injections.is_empty() && request_has_unsupported_upgrade(&request) {
            self.metrics.denied_request();
            return Ok(denied_response(AuthorizationError::Denied));
        }
        if apply_header_injections(&mut request, injections, &self.secrets).is_err() {
            self.metrics.denied_request();
            return Ok(denied_response(AuthorizationError::Denied));
        }
        self.inner.serve(request).await.map_err(Into::into)
    }
}

fn denied_response(error: AuthorizationError) -> rama::http::Response {
    let status = match error {
        AuthorizationError::InvalidAuthority => rama::http::StatusCode::BAD_REQUEST,
        AuthorizationError::Denied => rama::http::StatusCode::FORBIDDEN,
    };
    rama::http::Response::builder()
        .status(status)
        .body(rama::http::Body::empty())
        .expect("static proxy denial response is valid")
}

fn request_has_unsupported_upgrade(request: &rama::http::Request) -> bool {
    use rama::http::header::{CONNECTION, UPGRADE};
    if request.headers().contains_key(UPGRADE) {
        return true;
    }
    request
        .headers()
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
}

fn apply_header_injections(
    request: &mut rama::http::Request,
    injections: &[HeaderInjection],
    secrets: &ResolvedSecrets,
) -> Result<(), ()> {
    let values = injections
        .iter()
        .map(|injection| {
            let name =
                rama::http::HeaderName::try_from(injection.header.as_str()).map_err(|_| ())?;
            let secret = secrets.get(injection.secret.as_str()).ok_or(())?;
            let value = format_injected_secret(injection, secret)?;
            let value = rama::http::HeaderValue::try_from(value).map_err(|_| ())?;
            Ok((name, value))
        })
        .collect::<Result<Vec<_>, ()>>()?;
    for (name, value) in values {
        request.headers_mut().remove(&name);
        request.headers_mut().insert(name, value);
    }
    Ok(())
}

fn format_injected_secret(injection: &HeaderInjection, secret: &SecretValue) -> Result<String, ()> {
    Ok(match injection.format {
        InjectionFormat::Raw => secret.as_str().to_owned(),
        InjectionFormat::Bearer => format!("Bearer {}", secret.as_str()),
        InjectionFormat::BasicPassword => {
            let username = injection.username.as_deref().ok_or(())?;
            format!(
                "Basic {}",
                STANDARD.encode(format!("{username}:{}", secret.as_str()))
            )
        }
    })
}

async fn handle_tunnel<S>(
    mut client: S,
    destination: Destination,
    io_timeout: Duration,
    metrics: &Metrics,
) -> Result<(), ProxyRuntimeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let upstream = match tokio::time::timeout(
        io_timeout,
        TcpStream::connect((destination.host.as_str(), destination.port)),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            metrics.upstream_failure();
            let _ = client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await;
            return Err(ProxyRuntimeError::Run(error.to_string()));
        }
        Err(_) => {
            metrics.upstream_failure();
            let _ = client
                .write_all(b"HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\n\r\n")
                .await;
            return Ok(());
        }
    };
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(|error| ProxyRuntimeError::Run(error.to_string()))?;
    let mut upstream = upstream;
    copy_bidirectional_with_timeout(&mut client, &mut upstream, io_timeout)
        .await
        .map(|_| ())
        .map_err(|error| ProxyRuntimeError::Run(error.to_string()))
}

async fn copy_bidirectional_with_timeout<A, B>(
    left: &mut A,
    right: &mut B,
    io_timeout: Duration,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (left_reader, left_writer) = tokio::io::split(left);
    let (right_reader, right_writer) = tokio::io::split(right);
    tokio::try_join!(
        copy_with_timeout(left_reader, right_writer, io_timeout),
        copy_with_timeout(right_reader, left_writer, io_timeout)
    )
}

async fn copy_with_timeout<R, W>(
    mut reader: R,
    mut writer: W,
    io_timeout: Duration,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0; 8 * 1024];
    let mut copied = 0_u64;
    loop {
        let read = tokio::time::timeout(io_timeout, reader.read(&mut buffer))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy read timed out"))??;
        if read == 0 {
            tokio::time::timeout(io_timeout, writer.shutdown())
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "proxy write shutdown timed out")
                })??;
            return Ok(copied);
        }
        tokio::time::timeout(io_timeout, writer.write_all(&buffer[..read]))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy write timed out"))??;
        copied = copied.saturating_add(read as u64);
    }
}

struct ParsedConnect {
    authority: String,
    host: Option<String>,
    has_body: bool,
}

async fn read_connect_request<S>(stream: &mut S) -> io::Result<ParsedConnect>
where
    S: AsyncRead + Unpin,
{
    let mut bytes = Vec::with_capacity(1024);
    while bytes.len() < MAX_CONNECT_HEADER_BYTES {
        let byte = stream.read_u8().await?;
        bytes.push(byte);
        if bytes.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !bytes.ends_with(b"\r\n\r\n") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CONNECT headers too large",
        ));
    }
    let headers = std::str::from_utf8(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "CONNECT headers are not ASCII"))?;
    if !headers.is_ascii() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CONNECT headers are not ASCII",
        ));
    }
    let mut lines = headers[..headers.len() - 4].split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request line"))?;
    let mut parts = request_line.split_ascii_whitespace();
    if parts.next() != Some("CONNECT") || parts.next().is_none() || parts.next() != Some("HTTP/1.1")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "only HTTP/1.1 CONNECT is supported",
        ));
    }
    let authority = request_line
        .split_ascii_whitespace()
        .nth(1)
        .expect("CONNECT request line was checked")
        .to_owned();
    let mut host = None;
    let mut has_body = false;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid header"))?;
        if name.eq_ignore_ascii_case("host") {
            if host.replace(value.trim().to_owned()).is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate Host header",
                ));
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            has_body = true;
        } else if name.eq_ignore_ascii_case("content-length") {
            if value.trim() != "0" {
                has_body = true;
            }
        } else if name.eq_ignore_ascii_case("expect") {
            has_body = true;
        }
    }
    Ok(ParsedConnect {
        authority,
        host,
        has_body,
    })
}

struct UnixSocketGuard {
    path: PathBuf,
    parent: OwnedFd,
    name: CString,
    device: u64,
    inode: u64,
    _created_directories: CreatedDirectorySet,
}

impl UnixSocketGuard {
    fn bind(path: &Path) -> io::Result<(UnixListener, Self)> {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        if absolute.as_os_str().as_bytes().len() >= 108 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unix socket path is too long",
            ));
        }
        let name = CString::new(
            absolute
                .file_name()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing socket name"))?
                .as_bytes(),
        )
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid socket name"))?;
        let (parent, created_directories, normalized) = open_socket_parent(&absolute)?;
        if stat_at(parent.as_raw_fd(), &name)?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "socket path exists",
            ));
        }
        // Binding through the held directory FD makes the final component
        // directory-confined even if an ancestor is renamed during setup.
        let bind_path = PathBuf::from(format!(
            "/proc/self/fd/{}/{}",
            parent.as_raw_fd(),
            name.to_string_lossy()
        ));
        let listener = UnixListener::bind(&bind_path)?;
        let identity = stat_at(parent.as_raw_fd(), &name)?
            .ok_or_else(|| io::Error::other("bound Unix socket disappeared"))?;
        let guard = Self {
            path: normalized,
            parent,
            name,
            device: identity.st_dev as u64,
            inode: identity.st_ino as u64,
            _created_directories: created_directories,
        };
        fs::set_permissions(&bind_path, fs::Permissions::from_mode(0o600))?;
        let current = stat_at(guard.parent.as_raw_fd(), &guard.name)?;
        if !current
            .as_ref()
            .is_some_and(|metadata| guard.matches(metadata))
            || current
                .as_ref()
                .is_some_and(|metadata| metadata.st_mode & 0o777 != 0o600)
        {
            return Err(io::Error::other(
                "bound Unix socket identity or permissions changed",
            ));
        }
        Ok((listener, guard))
    }

    fn matches(&self, metadata: &libc::stat) -> bool {
        metadata.st_mode & libc::S_IFMT == libc::S_IFSOCK
            && metadata.st_dev == self.device
            && metadata.st_ino == self.inode
    }
}

impl Drop for UnixSocketGuard {
    fn drop(&mut self) {
        if let Ok(Some(metadata)) = stat_at(self.parent.as_raw_fd(), &self.name)
            && self.matches(&metadata)
            && unsafe { libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0) } == -1
        {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::NotFound {
                tracing::warn!(path = %self.path.display(), %error, "failed to remove Rama proxy Unix socket");
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct DirectoryKey {
    device: u64,
    inode: u64,
}

struct DirectoryRecord {
    parent: OwnedFd,
    name: CString,
    device: u64,
    inode: u64,
    path: PathBuf,
    created_by_baffle: bool,
    leases: usize,
}

static DIRECTORY_REGISTRY: OnceLock<Mutex<HashMap<DirectoryKey, DirectoryRecord>>> =
    OnceLock::new();
static SOCKET_PARENT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

struct CreatedDirectorySet(Vec<DirectoryKey>);

impl Drop for CreatedDirectorySet {
    fn drop(&mut self) {
        // Provisioning holds this lock while it walks and registers directory
        // descriptors. Serialize removal with that walk so a newly opened
        // directory cannot be unlinked before its lease is registered.
        let path_lock = SOCKET_PARENT_LOCK.get_or_init(|| Mutex::new(()));
        let _path_lock = path_lock.lock().unwrap_or_else(|error| error.into_inner());
        let registry = DIRECTORY_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
        let mut registry = registry.lock().unwrap_or_else(|error| error.into_inner());
        while let Some(key) = self.0.pop() {
            let Some(record) = registry.get_mut(&key) else {
                continue;
            };
            record.leases = record.leases.saturating_sub(1);
            if record.leases != 0 {
                continue;
            }
            if !record.created_by_baffle {
                registry.remove(&key);
                continue;
            }
            let matches = stat_at(record.parent.as_raw_fd(), &record.name)
                .ok()
                .flatten()
                .is_some_and(|metadata| {
                    metadata.st_mode & libc::S_IFMT == libc::S_IFDIR
                        && metadata.st_dev == record.device
                        && metadata.st_ino == record.inode
                });
            if !matches {
                registry.remove(&key);
                continue;
            }
            if unsafe {
                libc::unlinkat(
                    record.parent.as_raw_fd(),
                    record.name.as_ptr(),
                    libc::AT_REMOVEDIR,
                )
            } == 0
            {
                registry.remove(&key);
            } else {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::NotFound {
                    registry.remove(&key);
                } else {
                    tracing::debug!(path = %record.path.display(), %error, "left non-empty session socket directory");
                }
            }
        }
    }
}

fn register_directory(
    parent: &OwnedFd,
    name: &CString,
    metadata: &libc::stat,
    path: PathBuf,
    created_by_baffle: bool,
) -> io::Result<DirectoryKey> {
    let key = DirectoryKey {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    };
    let registry = DIRECTORY_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let mut registry = registry.lock().unwrap_or_else(|error| error.into_inner());
    let record = registry.entry(key).or_insert(DirectoryRecord {
        parent: parent.try_clone()?,
        name: name.clone(),
        device: key.device,
        inode: key.inode,
        path,
        created_by_baffle,
        leases: 0,
    });
    record.created_by_baffle |= created_by_baffle;
    record.leases += 1;
    Ok(key)
}

fn open_socket_parent(path: &Path) -> io::Result<(OwnedFd, CreatedDirectorySet, PathBuf)> {
    let path_lock = SOCKET_PARENT_LOCK.get_or_init(|| Mutex::new(()));
    let mut created = CreatedDirectorySet(Vec::new());
    let result = {
        let _path_lock = path_lock.lock().unwrap_or_else(|error| error.into_inner());
        open_socket_parent_locked(path, &mut created)
    };
    match result {
        Ok((parent, normalized)) => Ok((parent, created, normalized)),
        Err(error) => {
            drop(created);
            Err(error)
        }
    }
}

fn open_socket_parent_locked(
    path: &Path,
    created: &mut CreatedDirectorySet,
) -> io::Result<(OwnedFd, PathBuf)> {
    let parent_path = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let absolute_parent = if parent_path.is_absolute() {
        parent_path.to_path_buf()
    } else {
        std::env::current_dir()?.join(parent_path)
    };
    let root = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut current = unsafe { OwnedFd::from_raw_fd(root) };
    let mut normalized = PathBuf::from("/");
    for component in absolute_parent.components() {
        let component = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::ParentDir => {
                CString::new("..").expect("parent component contains no nul byte")
            }
            Component::Normal(name) => CString::new(name.as_bytes()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid directory name")
            })?,
            Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid socket path",
                ));
            }
        };
        let mut made = false;
        let mut fd = unsafe {
            libc::openat(
                current.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd == -1 && io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
            let mkdir = unsafe { libc::mkdirat(current.as_raw_fd(), component.as_ptr(), 0o700) };
            if mkdir == 0 {
                made = true;
            } else if io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
                return Err(io::Error::last_os_error());
            }
            fd = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    component.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
        }
        if fd == -1 {
            return Err(io::Error::last_os_error());
        }
        let next = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(next.as_raw_fd(), metadata.as_mut_ptr()) } == -1 {
            return Err(io::Error::last_os_error());
        }
        let metadata = unsafe { metadata.assume_init() };
        if made {
            unsafe {
                libc::fchmod(next.as_raw_fd(), 0o700);
            }
        }
        normalized.push(component.to_string_lossy().as_ref());
        let registered =
            register_directory(&current, &component, &metadata, normalized.clone(), made);
        match registered {
            Ok(key) => created.0.push(key),
            Err(error) => {
                if made {
                    unsafe {
                        libc::unlinkat(current.as_raw_fd(), component.as_ptr(), libc::AT_REMOVEDIR);
                    }
                }
                return Err(error);
            }
        }
        current = next;
    }
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing socket name"))?;
    let normalized = normalized.join(name);
    Ok((current, normalized))
}

fn stat_at(parent: libc::c_int, name: &CString) -> io::Result<Option<libc::stat>> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent,
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        return Ok(Some(unsafe { metadata.assume_init() }));
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(None)
    } else {
        Err(error)
    }
}

fn bind_unix_listener(path: &Path) -> io::Result<(UnixListener, UnixSocketGuard)> {
    UnixSocketGuard::bind(path)
}

struct ConnectionGuard(Arc<Metrics>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.connection_stopped();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        fs, io,
        os::unix::fs::PermissionsExt,
        path::Path,
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
        time::Duration,
    };

    use rama::crypto::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };
    use tokio::{
        io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
        net::{TcpListener, UnixStream},
        sync::{mpsc, oneshot},
        time::timeout,
    };
    use tokio_rustls::{TlsAcceptor, TlsConnector, rustls};

    use super::{ProxyRuntime, RuntimeId, set_test_upstream_trust_anchor};
    use crate::{
        ca::ManagedCa,
        config::{ControlRequest, SessionConfig},
        proxy_runtime::ProxyRuntimeEvent,
        secrets::ResolvedSecrets,
    };

    type TestError = Box<dyn Error + Send + Sync>;

    fn write_managed_ca(directory: &Path) -> Arc<ManagedCa> {
        let key = KeyPair::generate().expect("Baffle CA key should generate");
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let certificate = params
            .self_signed(&key)
            .expect("Baffle CA certificate should generate");
        let cert_path = directory.join("baffle-ca.pem");
        let key_path = directory.join("baffle-ca-key.pem");
        fs::write(&cert_path, certificate.pem()).expect("Baffle CA certificate should be saved");
        fs::write(&key_path, key.serialize_pem()).expect("Baffle CA key should be saved");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .expect("Baffle CA key should be private");
        Arc::new(
            ManagedCa::load(&crate::config::CaConfig {
                certificate: cert_path,
                private_key: key_path,
            })
            .expect("Baffle CA should load"),
        )
    }

    fn upstream_tls_config(server_name: &str) -> rustls::ServerConfig {
        upstream_tls_config_with_expiration(server_name, false)
    }

    fn upstream_tls_config_with_expiration(
        server_name: &str,
        expired: bool,
    ) -> rustls::ServerConfig {
        let (root_certificate, root_key, root_der) = upstream_root();
        set_test_upstream_trust_anchor(root_der);
        let root_key = KeyPair::from_pem(&root_key).expect("upstream root key should parse");
        let issuer = Issuer::from_ca_cert_pem(&root_certificate, root_key)
            .expect("upstream root should create an issuer");
        let server_key = KeyPair::generate().expect("upstream key should generate");
        let mut params = CertificateParams::new(vec![server_name.to_owned()])
            .expect("upstream leaf parameters should be valid");
        if expired {
            params.not_before = rcgen::date_time_ymd(2020, 1, 1);
            params.not_after = rcgen::date_time_ymd(2021, 1, 1);
        }
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let certificate = params
            .signed_by(&server_key, &issuer)
            .expect("upstream leaf should be signed");
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(certificate.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
            )
            .expect("upstream TLS server should accept its key pair");
        // The relay mirrors the client's negotiated ALPN. Advertising h2 lets
        // the same fixture exercise HTTP/2 on both sides of the live proxy.
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        config
    }

    fn upstream_root() -> (String, String, Vec<u8>) {
        use std::sync::OnceLock;
        static ROOT: OnceLock<(String, String, Vec<u8>)> = OnceLock::new();
        ROOT.get_or_init(|| {
            let key = KeyPair::generate().expect("test upstream CA key should generate");
            let mut params = CertificateParams::default();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let certificate = params
                .self_signed(&key)
                .expect("test upstream CA certificate should generate");
            let der = certificate.der().to_vec();
            (certificate.pem(), key.serialize_pem(), der)
        })
        .clone()
    }

    fn intercept_session(port: u16) -> SessionConfig {
        let input = format!(
            "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"localhost\"\nmode = \"intercept\"\nports = [{port}]\npaths = [\"/allowed\"]\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"proxy-token\"\nformat = \"bearer\"\n"
        );
        let ControlRequest::Create { session, .. } =
            ControlRequest::from_toml(&input).expect("interception session should parse")
        else {
            panic!("expected create request");
        };
        session
    }

    fn tunnel_session(port: u16) -> SessionConfig {
        let input = format!(
            "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"localhost\"\nmode = \"tunnel\"\nports = [{port}]\n"
        );
        let ControlRequest::Create { session, .. } =
            ControlRequest::from_toml(&input).expect("tunnel session should parse")
        else {
            panic!("expected create request");
        };
        session
    }

    async fn start_runtime(
        directory: &Path,
        session: SessionConfig,
        ca: Arc<ManagedCa>,
        timeout: Duration,
    ) -> Result<(ProxyRuntime, mpsc::UnboundedReceiver<ProxyRuntimeEvent>), TestError> {
        start_runtime_named(directory, session, ca, "rama-test", timeout).await
    }

    async fn start_runtime_named(
        directory: &Path,
        session: SessionConfig,
        ca: Arc<ManagedCa>,
        name: &str,
        timeout: Duration,
    ) -> Result<(ProxyRuntime, mpsc::UnboundedReceiver<ProxyRuntimeEvent>), TestError> {
        start_runtime_limited(directory, session, ca, name, 8, timeout).await
    }

    async fn start_runtime_limited(
        directory: &Path,
        session: SessionConfig,
        ca: Arc<ManagedCa>,
        name: &str,
        max_connections: usize,
        timeout: Duration,
    ) -> Result<(ProxyRuntime, mpsc::UnboundedReceiver<ProxyRuntimeEvent>), TestError> {
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let runtime = ProxyRuntime::start_with_metrics(
            RuntimeId::new(name),
            session,
            Arc::new(ResolvedSecrets::from_values([(
                "proxy-token".to_owned(),
                "test-credential".to_owned(),
            )])),
            ca,
            directory.join(format!("{name}.sock")),
            max_connections,
            timeout,
            Arc::new(crate::telemetry::Metrics::default()),
            events_tx,
        )
        .await?;
        Ok((runtime, events_rx))
    }

    async fn start_origin(
        config: rustls::ServerConfig,
        seen: oneshot::Sender<String>,
    ) -> Result<
        (
            std::net::SocketAddr,
            tokio::task::JoinHandle<()>,
            oneshot::Receiver<()>,
        ),
        TestError,
    > {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("origin should accept");
            let _ = accepted_tx.send(());
            let tls = TlsAcceptor::from(Arc::new(config))
                .accept(stream)
                .await
                .expect("BoringSSL should establish TLS with the origin");
            let mut reader = BufReader::new(tls);
            let mut request_line = String::new();
            reader
                .read_line(&mut request_line)
                .await
                .expect("origin request line should be readable");
            let mut authorization = String::new();
            loop {
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .await
                    .expect("origin header should be readable");
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                if let Some((name, value)) = line.split_once(':')
                    && name.eq_ignore_ascii_case("authorization")
                {
                    authorization = value.trim().to_owned();
                }
            }
            let _ = seen.send(format!("{request_line}{authorization}"));
            reader
                .get_mut()
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
                )
                .await
                .expect("origin response should be written");
            // Keep the connection open so the client can exercise a second
            // request on the same intercepted TLS connection.
            let mut second = String::new();
            let _ = reader.read_line(&mut second).await;
        });
        Ok((address, task, accepted_rx))
    }

    async fn open_tls_client(
        proxy: &Path,
        authority: &str,
        ca: &ManagedCa,
    ) -> Result<tokio_rustls::client::TlsStream<UnixStream>, TestError> {
        open_tls_client_for_name(proxy, authority, "localhost", ca).await
    }

    async fn open_tls_client_for_name(
        proxy: &Path,
        authority: &str,
        server_name: &str,
        ca: &ManagedCa,
    ) -> Result<tokio_rustls::client::TlsStream<UnixStream>, TestError> {
        open_tls_client_with_alpn(proxy, authority, server_name, ca, &[], &[]).await
    }

    async fn open_tls_client_with_alpn(
        proxy: &Path,
        authority: &str,
        server_name: &str,
        ca: &ManagedCa,
        alpn: &[&[u8]],
        extra_roots: &[Vec<u8>],
    ) -> Result<tokio_rustls::client::TlsStream<UnixStream>, TestError> {
        let mut stream = UnixStream::connect(proxy).await?;
        stream
            .write_all(
                format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
            )
            .await?;
        let mut reader = BufReader::new(stream);
        let mut status = String::new();
        timeout(Duration::from_secs(2), reader.read_line(&mut status)).await??;
        if !status.starts_with("HTTP/1.1 200") {
            return Err(format!("CONNECT failed: {status}").into());
        }
        loop {
            let mut line = String::new();
            timeout(Duration::from_secs(2), reader.read_line(&mut line)).await??;
            if line == "\r\n" || line.is_empty() {
                break;
            }
        }

        let (_, parsed_ca) = x509_parser::pem::parse_x509_pem(ca.public_certificate_pem())?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(parsed_ca.contents))?;
        for root in extra_roots {
            roots.add(CertificateDer::from(root.clone()))?;
        }
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
        let connector = TlsConnector::from(Arc::new(config));
        Ok(connector
            .connect(
                rustls::pki_types::ServerName::try_from(server_name.to_owned())?,
                reader.into_inner(),
            )
            .await?)
    }

    async fn start_http2_origin(
        config: rustls::ServerConfig,
        seen: tokio::sync::mpsc::UnboundedSender<(String, String, String)>,
    ) -> Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>), TestError> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("origin should accept");
            let tls = TlsAcceptor::from(Arc::new(config))
                .accept(stream)
                .await
                .expect("origin should establish TLS");
            assert_eq!(
                tls.get_ref().1.alpn_protocol(),
                Some(b"h2".as_slice()),
                "the proxy must negotiate HTTP/2 with the origin"
            );
            let service = rama::service::service_fn(
                move |request: rama::http::Request<rama::http::core::body::Incoming>| {
                    let sender = seen.clone();
                    async move {
                        let path = request
                            .uri()
                            .path()
                            .map(|path| path.to_string())
                            .unwrap_or_default();
                        let authority = request
                            .uri()
                            .authority()
                            .map(|authority| authority.to_string())
                            .unwrap_or_default();
                        let authorization = request
                            .headers()
                            .get(rama::http::header::AUTHORIZATION)
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default()
                            .to_owned();
                        let _ = sender.send((path, authority, authorization));
                        Ok::<_, std::convert::Infallible>(
                            rama::http::Response::builder()
                                .status(rama::http::StatusCode::OK)
                                .body(rama::http::Body::empty())
                                .expect("origin response should build"),
                        )
                    }
                },
            );
            rama::http::core::server::conn::http2::Builder::new(rama::rt::Executor::default())
                .serve_connection(rama::ServiceInput::new(tls), service)
                .await
                .expect("origin HTTP/2 connection should complete");
        });
        Ok((address, task))
    }

    fn h2_request(uri: String, host: String, authorization: Option<&str>) -> rama::http::Request {
        let mut request = rama::http::Request::builder()
            .method(rama::http::Method::GET)
            .version(rama::http::Version::HTTP_2)
            .uri(uri)
            .header(rama::http::header::HOST, host);
        if let Some(authorization) = authorization {
            request = request.header(rama::http::header::AUTHORIZATION, authorization);
        }
        request
            .body(rama::http::Body::empty())
            .expect("HTTP/2 request should build")
    }

    struct FragmentFirstWrite<T> {
        inner: T,
        first_byte_written: bool,
        remainder_delay: Option<Pin<Box<tokio::time::Sleep>>>,
    }

    impl<T> FragmentFirstWrite<T> {
        fn new(inner: T) -> Self {
            Self {
                inner,
                first_byte_written: false,
                remainder_delay: None,
            }
        }
    }

    impl<T: AsyncRead + Unpin> AsyncRead for FragmentFirstWrite<T> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(context, buffer)
        }
    }

    impl<T: AsyncWrite + Unpin> AsyncWrite for FragmentFirstWrite<T> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            if buffer.is_empty() {
                return Poll::Ready(Ok(0));
            }
            if !self.first_byte_written {
                match Pin::new(&mut self.inner).poll_write(context, &buffer[..1]) {
                    Poll::Ready(Ok(written)) => {
                        self.first_byte_written = true;
                        self.remainder_delay =
                            Some(Box::pin(tokio::time::sleep(Duration::from_millis(75))));
                        return Poll::Ready(Ok(written));
                    }
                    result => return result,
                }
            }
            if let Some(delay) = self.remainder_delay.as_mut() {
                if delay.as_mut().poll(context).is_pending() {
                    return Poll::Pending;
                }
                self.remainder_delay = None;
            }
            Pin::new(&mut self.inner).poll_write(context, buffer)
        }

        fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(context)
        }
    }

    async fn read_http_response<S>(reader: &mut BufReader<S>) -> io::Result<String>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        let mut status = String::new();
        reader.read_line(&mut status).await?;
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            if line == "\r\n" || line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).await?;
        Ok(format!(
            "{}{}",
            status.trim(),
            String::from_utf8_lossy(&body)
        ))
    }

    #[tokio::test]
    async fn intercepted_session_forwards_allowed_https_and_injects_daemon_secret()
    -> Result<(), TestError> {
        let directory = tempfile::tempdir()?;
        let ca = write_managed_ca(directory.path());
        let (seen_tx, seen_rx) = oneshot::channel();
        let (origin_address, origin_task, _accepted) =
            start_origin(upstream_tls_config("localhost"), seen_tx).await?;
        let port = origin_address.port();
        let (runtime, _events) = start_runtime(
            directory.path(),
            intercept_session(port),
            Arc::clone(&ca),
            Duration::from_secs(2),
        )
        .await?;
        let mut tls =
            open_tls_client(runtime.socket_path(), &format!("localhost:{port}"), &ca).await?;
        tls.write_all(
            format!(
                "GET /allowed HTTP/1.1\r\nHost: localhost:{port}\r\nAuthorization: Bearer attacker-value\r\nConnection: keep-alive\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;
        let mut reader = BufReader::new(tls);
        let response = timeout(Duration::from_secs(3), read_http_response(&mut reader)).await??;
        assert!(
            response.starts_with("HTTP/1.1 200 OKok"),
            "unexpected origin response: {response}"
        );
        let observed = seen_rx.await?;
        assert!(observed.starts_with("GET /allowed HTTP/1.1"));
        assert!(observed.contains("Bearer test-credential"));

        reader
            .get_mut()
            .write_all(
                format!("GET /blocked HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes(),
            )
            .await?;
        let denied = timeout(Duration::from_secs(3), read_http_response(&mut reader)).await??;
        assert!(
            denied.starts_with("HTTP/1.1 403"),
            "unexpected denied response: {denied}"
        );

        reader
            .get_mut()
            .write_all(
                format!("GET /allowed HTTP/1.1\r\nHost: other.example:{port}\r\n\r\n").as_bytes(),
            )
            .await?;
        let mismatched = timeout(Duration::from_secs(3), read_http_response(&mut reader)).await??;
        assert!(
            mismatched.starts_with("HTTP/1.1 400"),
            "decrypted HTTP authority must remain bound to CONNECT: {mismatched}"
        );

        reader
            .get_mut()
            .write_all(b"GET /allowed HTTP/1.1\r\nConnection: close\r\n\r\n")
            .await?;
        let missing_host =
            timeout(Duration::from_secs(3), read_http_response(&mut reader)).await??;
        assert!(
            missing_host.starts_with("HTTP/1.1 400"),
            "an intercepted HTTP/1.1 request without Host must be rejected: {missing_host}"
        );

        drop(reader);
        origin_task.abort();
        runtime.shutdown(Duration::from_secs(2)).await;
        Ok(())
    }

    #[tokio::test]
    async fn rejects_plaintext_forward_http_before_dialing_the_origin() -> Result<(), TestError> {
        let directory = tempfile::tempdir()?;
        let ca = write_managed_ca(directory.path());
        let upstream = TcpListener::bind("127.0.0.1:0").await?;
        let port = upstream.local_addr()?.port();
        let (runtime, _) = start_runtime(
            directory.path(),
            intercept_session(port),
            ca,
            Duration::from_secs(1),
        )
        .await?;

        let mut client = UnixStream::connect(runtime.socket_path()).await?;
        client
            .write_all(
                format!(
                    "GET http://localhost:{port}/allowed HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await?;
        let mut reader = BufReader::new(client);
        let mut status = String::new();
        timeout(Duration::from_secs(1), reader.read_line(&mut status)).await??;
        assert!(status.starts_with("HTTP/1.1 400"));
        assert!(
            timeout(Duration::from_millis(150), upstream.accept())
                .await
                .is_err(),
            "plaintext forward HTTP must not cause an upstream connection"
        );

        runtime.shutdown(Duration::from_secs(1)).await;
        Ok(())
    }

    #[tokio::test]
    async fn intercepted_http2_streams_apply_path_authority_and_injection_policy()
    -> Result<(), TestError> {
        let directory = tempfile::tempdir()?;
        let ca = write_managed_ca(directory.path());
        let (seen_sender, mut seen) = mpsc::unbounded_channel();
        let (origin_address, origin_task) =
            start_http2_origin(upstream_tls_config("localhost"), seen_sender).await?;
        let port = origin_address.port();
        let authority = format!("localhost:{port}");
        let (runtime, _) = start_runtime(
            directory.path(),
            intercept_session(port),
            Arc::clone(&ca),
            Duration::from_secs(2),
        )
        .await?;
        let tls = open_tls_client_with_alpn(
            runtime.socket_path(),
            &authority,
            "localhost",
            &ca,
            &[b"h2"],
            &[],
        )
        .await?;
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        let (mut sender, connection) =
            rama::http::core::client::conn::http2::handshake::<_, rama::http::Body>(
                rama::rt::Executor::default(),
                rama::ServiceInput::new(tls),
            )
            .await?;
        let driver = tokio::spawn(connection);

        let request_one = h2_request(
            format!("https://{authority}/allowed"),
            authority.clone(),
            Some("Bearer attacker-one"),
        );
        let request_two = h2_request(
            format!("https://{authority}/allowed"),
            authority.clone(),
            Some("Bearer attacker-two"),
        );
        let request_denied = h2_request(
            format!("https://{authority}/blocked"),
            authority.clone(),
            Some("Bearer attacker-denied"),
        );
        let request_mismatched = h2_request(
            format!("https://example.org:{port}/allowed"),
            authority.clone(),
            Some("Bearer attacker-mismatched"),
        );

        sender.ready().await?;
        let mut sender_one = sender.clone();
        let mut sender_two = sender.clone();
        let mut sender_denied = sender.clone();
        let mut sender_mismatched = sender.clone();
        sender_one.ready().await?;
        sender_two.ready().await?;
        sender_denied.ready().await?;
        sender_mismatched.ready().await?;
        let (one, two, denied, mismatched) = tokio::join!(
            timeout(Duration::from_secs(3), sender_one.send_request(request_one)),
            timeout(Duration::from_secs(3), sender_two.send_request(request_two)),
            timeout(
                Duration::from_secs(3),
                sender_denied.send_request(request_denied)
            ),
            timeout(
                Duration::from_secs(3),
                sender_mismatched.send_request(request_mismatched)
            ),
        );
        let one = one??;
        let two = two??;
        let denied = denied??;
        let mismatched = mismatched??;
        assert_eq!(one.status(), rama::http::StatusCode::OK);
        assert_eq!(two.status(), rama::http::StatusCode::OK);
        assert_eq!(denied.status(), rama::http::StatusCode::FORBIDDEN);
        assert_eq!(mismatched.status(), rama::http::StatusCode::BAD_REQUEST);

        for path in ["/allowedness", "/allowed%2fprivate", "/%2e%2e/allowed"] {
            sender_denied.ready().await?;
            let request = h2_request(
                format!("https://{authority}{path}"),
                authority.clone(),
                Some("Bearer attacker-path"),
            );
            let response =
                timeout(Duration::from_secs(3), sender_denied.send_request(request)).await??;
            assert!(
                response.status() == rama::http::StatusCode::BAD_REQUEST
                    || response.status() == rama::http::StatusCode::FORBIDDEN,
                "unsafe path {path:?} must be rejected: {}",
                response.status()
            );
        }

        sender_denied.ready().await?;
        let wrong_scheme = h2_request(
            format!("http://{authority}/allowed"),
            authority.clone(),
            Some("Bearer attacker-scheme"),
        );
        let wrong_scheme = timeout(
            Duration::from_secs(3),
            sender_denied.send_request(wrong_scheme),
        )
        .await??;
        assert_eq!(
            wrong_scheme.status(),
            rama::http::StatusCode::BAD_REQUEST,
            "HTTP/2 :scheme http must not enter intercepted HTTPS policy"
        );

        for _ in 0..2 {
            let (path, seen_authority, authorization) =
                timeout(Duration::from_secs(2), seen.recv())
                    .await?
                    .ok_or_else(|| io::Error::other("origin event channel should remain open"))?;
            assert_eq!(path, "/allowed");
            assert_eq!(seen_authority, authority);
            assert_eq!(authorization, "Bearer test-credential");
            assert!(!authorization.contains("attacker"));
        }
        assert!(
            timeout(Duration::from_millis(150), seen.recv())
                .await
                .is_err(),
            "denied paths and mismatched authorities must not reach the origin"
        );

        drop(sender);
        driver.abort();
        origin_task.abort();
        runtime.shutdown(Duration::from_secs(2)).await;
        Ok(())
    }

    #[tokio::test]
    async fn tunnel_and_intercept_sessions_run_and_stop_independently() -> Result<(), TestError> {
        let directory = tempfile::tempdir()?;
        let ca = write_managed_ca(directory.path());

        let echo_origin = TcpListener::bind("127.0.0.1:0").await?;
        let echo_port = echo_origin.local_addr()?.port();
        let echo_task = tokio::spawn(async move {
            let (mut stream, _) = echo_origin.accept().await.expect("tunnel should connect");
            for length in [21, 5] {
                let mut payload = vec![0; length];
                stream
                    .read_exact(&mut payload)
                    .await
                    .expect("opaque tunnel payload should arrive");
                stream
                    .write_all(&payload)
                    .await
                    .expect("opaque payload should be echoed");
            }
        });
        let (tunnel_runtime, _tunnel_events) = start_runtime_named(
            directory.path(),
            tunnel_session(echo_port),
            Arc::clone(&ca),
            "rama-tunnel",
            Duration::from_secs(2),
        )
        .await?;

        let (seen_tx, seen_rx) = oneshot::channel();
        let (origin_address, origin_task, _accepted) =
            start_origin(upstream_tls_config("localhost"), seen_tx).await?;
        let (intercept_runtime, _intercept_events) = start_runtime_named(
            directory.path(),
            intercept_session(origin_address.port()),
            Arc::clone(&ca),
            "rama-intercept",
            Duration::from_secs(2),
        )
        .await?;

        let socket_path = tunnel_runtime.socket_path().to_path_buf();
        let mut tunnel = UnixStream::connect(&socket_path).await?;
        tunnel
            .write_all(
                format!(
                    "CONNECT localhost:{echo_port} HTTP/1.1\r\nHost: localhost:{echo_port}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await?;
        let mut tunnel = BufReader::new(tunnel);
        let mut status = String::new();
        timeout(Duration::from_secs(2), tunnel.read_line(&mut status)).await??;
        assert!(status.starts_with("HTTP/1.1 200"));
        loop {
            let mut line = String::new();
            tunnel.read_line(&mut line).await?;
            if line == "\r\n" || line.is_empty() {
                break;
            }
        }
        tunnel.get_mut().write_all(b"opaque tunnel payload").await?;
        let mut echoed = [0; 21];
        timeout(Duration::from_secs(2), tunnel.read_exact(&mut echoed)).await??;
        assert_eq!(&echoed, b"opaque tunnel payload");

        let tunnel_shutdown = tokio::spawn(tunnel_runtime.shutdown(Duration::from_secs(2)));
        timeout(Duration::from_secs(1), async {
            while socket_path.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("shutdown should remove the session socket before draining");
        tunnel.get_mut().write_all(b"still").await?;
        let mut drained = [0; 5];
        timeout(Duration::from_secs(1), tunnel.read_exact(&mut drained)).await??;
        assert_eq!(&drained, b"still");
        drop(tunnel);
        timeout(Duration::from_secs(2), tunnel_shutdown).await??;
        echo_task.abort();

        let port = origin_address.port();
        let mut tls = open_tls_client(
            intercept_runtime.socket_path(),
            &format!("localhost:{port}"),
            &ca,
        )
        .await?;
        tls.write_all(
            format!("GET /allowed HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes(),
        )
        .await?;
        let mut reader = BufReader::new(tls);
        let response = timeout(Duration::from_secs(3), read_http_response(&mut reader)).await??;
        assert!(response.starts_with("HTTP/1.1 200 OKok"));
        assert!(seen_rx.await?.starts_with("GET /allowed HTTP/1.1"));

        origin_task.abort();
        intercept_runtime.shutdown(Duration::from_secs(2)).await;
        Ok(())
    }

    #[tokio::test]
    async fn unix_listener_enforces_the_configured_connection_limit() -> Result<(), TestError> {
        let directory = tempfile::tempdir()?;
        let ca = write_managed_ca(directory.path());
        let (runtime, _) = start_runtime_limited(
            directory.path(),
            tunnel_session(443),
            ca,
            "rama-unix-limited",
            1,
            Duration::from_secs(2),
        )
        .await?;

        let mut admitted = UnixStream::connect(runtime.socket_path()).await?;
        admitted.write_all(b"C").await?;
        tokio::time::sleep(Duration::from_millis(25)).await;
        let mut over_limit = UnixStream::connect(runtime.socket_path()).await?;
        let mut byte = [0; 1];
        let read = timeout(Duration::from_secs(1), over_limit.read(&mut byte)).await??;
        assert_eq!(read, 0, "over-limit Unix clients must be closed");

        drop(admitted);
        runtime.shutdown(Duration::from_secs(1)).await;
        Ok(())
    }

    #[tokio::test]
    async fn nested_socket_directories_are_private_and_removed_on_shutdown() -> Result<(), TestError>
    {
        let directory = tempfile::tempdir()?;
        let ca = write_managed_ca(directory.path());
        let path = directory.path().join("cladding/github.sock");
        let (events, _) = mpsc::unbounded_channel();
        let runtime = ProxyRuntime::start(
            RuntimeId::new("rama-nested-socket"),
            tunnel_session(443),
            ca,
            path.clone(),
            4,
            events,
        )
        .await?;
        assert!(path.exists());
        assert_eq!(
            fs::metadata(path.parent().expect("named socket has a parent"))?
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(UnixStream::connect(&path).await.is_ok());
        runtime.shutdown(Duration::from_secs(1)).await;
        assert!(!path.exists());
        assert!(!path.parent().expect("named socket has a parent").exists());
        Ok(())
    }

    #[tokio::test]
    async fn nested_socket_parent_symlink_is_rejected() -> Result<(), TestError> {
        let directory = tempfile::tempdir()?;
        let target = tempfile::tempdir()?;
        let ca = write_managed_ca(directory.path());
        let link = directory.path().join("cladding");
        std::os::unix::fs::symlink(target.path(), &link)?;
        let path = link.join("github.sock");
        let (events, _) = mpsc::unbounded_channel();
        let result = ProxyRuntime::start(
            RuntimeId::new("rama-symlink-socket"),
            tunnel_session(443),
            ca,
            path.clone(),
            4,
            events,
        )
        .await;
        assert!(result.is_err());
        assert!(!target.path().join("github.sock").exists());
        assert!(fs::symlink_metadata(link)?.file_type().is_symlink());
        Ok(())
    }

    #[tokio::test]
    async fn renamed_socket_parent_cleanup_leaves_replacement_path_untouched()
    -> Result<(), TestError> {
        let directory = tempfile::tempdir()?;
        let ca = write_managed_ca(directory.path());
        let original_parent = directory.path().join("cladding");
        let path = original_parent.join("github.sock");
        let (events, _) = mpsc::unbounded_channel();
        let runtime = ProxyRuntime::start(
            RuntimeId::new("rama-renamed-socket-parent"),
            tunnel_session(443),
            ca,
            path,
            4,
            events,
        )
        .await?;
        let renamed_parent = directory.path().join("cladding-old");
        fs::rename(&original_parent, &renamed_parent)?;
        fs::create_dir(&original_parent)?;
        let replacement = original_parent.join("github.sock");
        fs::write(&replacement, b"replacement")?;

        runtime.shutdown(Duration::from_secs(1)).await;
        assert!(!renamed_parent.join("github.sock").exists());
        assert_eq!(fs::read(replacement)?, b"replacement");
        Ok(())
    }

    #[tokio::test]
    async fn startup_rejects_an_existing_socket_path_without_replacing_it() -> Result<(), TestError>
    {
        let directory = tempfile::tempdir()?;
        let ca = write_managed_ca(directory.path());
        let socket_path = directory.path().join("occupied.sock");
        fs::write(&socket_path, b"owned by another process")?;
        let (events, _receiver) = mpsc::unbounded_channel();
        let result = ProxyRuntime::start_with_metrics(
            RuntimeId::new("rama-startup-conflict"),
            tunnel_session(443),
            Arc::new(ResolvedSecrets::default()),
            ca,
            socket_path.clone(),
            4,
            Duration::from_secs(1),
            Arc::new(crate::telemetry::Metrics::default()),
            events,
        )
        .await;
        assert!(
            result.is_err(),
            "startup must fail when the configured socket path already exists"
        );
        assert_eq!(fs::read(socket_path)?, b"owned by another process");
        Ok(())
    }

    #[tokio::test]
    async fn direct_listener_task_failure_is_reported_to_the_session_event_channel()
    -> Result<(), TestError> {
        let directory = tempfile::tempdir()?;
        let ca = write_managed_ca(directory.path());
        let (runtime, mut events) = start_runtime(
            directory.path(),
            tunnel_session(443),
            ca,
            Duration::from_secs(1),
        )
        .await?;
        let id = runtime.runtime_id().clone();

        runtime.task_abort.abort();
        let event = timeout(Duration::from_secs(2), events.recv())
            .await?
            .ok_or_else(|| io::Error::other("session event channel should remain open"))?;
        assert_eq!(event.runtime_id, id);
        assert!(
            event.result.is_err(),
            "listener task failure must reach the supervisor"
        );
        runtime.shutdown(Duration::from_secs(1)).await;
        Ok(())
    }

    #[tokio::test]
    async fn cancelling_shutdown_with_an_active_tunnel_aborts_tasks_and_cleans_up()
    -> Result<(), TestError> {
        let directory = tempfile::tempdir()?;
        let ca = write_managed_ca(directory.path());
        let origin = TcpListener::bind("127.0.0.1:0").await?;
        let port = origin.local_addr()?.port();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.expect("origin should accept");
            let mut byte = [0; 1];
            let _ = stream.read(&mut byte).await;
        });
        let (runtime, mut events) = start_runtime_named(
            directory.path(),
            tunnel_session(port),
            ca,
            "rama-cancel-shutdown",
            Duration::from_secs(30),
        )
        .await?;
        let local_address = runtime.socket_path().to_path_buf();
        let socket_path = runtime.socket_path().to_path_buf();
        let runtime_id = runtime.runtime_id().clone();
        let mut tunnel = UnixStream::connect(&socket_path).await?;
        tunnel
            .write_all(
                format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n")
                    .as_bytes(),
            )
            .await?;
        let mut tunnel = BufReader::new(tunnel);
        let mut status = String::new();
        timeout(Duration::from_secs(2), tunnel.read_line(&mut status)).await??;
        assert!(status.starts_with("HTTP/1.1 200"));
        loop {
            let mut line = String::new();
            tunnel.read_line(&mut line).await?;
            if line == "\r\n" || line.is_empty() {
                break;
            }
        }

        let shutdown = tokio::spawn(runtime.shutdown(Duration::from_secs(10)));
        tokio::task::yield_now().await;
        shutdown.abort();
        let _ = shutdown.await;

        timeout(Duration::from_secs(2), async {
            while socket_path.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert!(UnixStream::connect(local_address).await.is_err());
        let mut byte = [0; 1];
        let read = timeout(Duration::from_secs(1), tunnel.read(&mut byte)).await?;
        assert!(
            matches!(read, Ok(0) | Err(_)),
            "active tunnel should close when its session owner is cancelled"
        );
        let event = timeout(Duration::from_secs(2), events.recv())
            .await?
            .ok_or_else(|| io::Error::other("session event channel should remain open"))?;
        assert_eq!(event.runtime_id, runtime_id);
        assert!(
            event.result.is_err(),
            "cancelled proxy task failure must propagate to the session registry"
        );
        origin_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn cancelling_shutdown_with_an_inflight_intercepted_request_closes_it()
    -> Result<(), TestError> {
        let directory = tempfile::tempdir()?;
        let ca = write_managed_ca(directory.path());
        let origin = TcpListener::bind("127.0.0.1:0").await?;
        let port = origin.local_addr()?.port();
        let (request_seen_sender, request_seen) = oneshot::channel();
        let (release_origin, release_origin_rx) = oneshot::channel::<()>();
        let origin_task = tokio::spawn(async move {
            let (stream, _) = origin.accept().await.expect("origin should accept");
            let tls = TlsAcceptor::from(Arc::new(upstream_tls_config("localhost")))
                .accept(stream)
                .await
                .expect("origin should establish TLS");
            let mut reader = BufReader::new(tls);
            let mut request_line = String::new();
            reader
                .read_line(&mut request_line)
                .await
                .expect("origin request line should be readable");
            loop {
                let mut header = String::new();
                reader
                    .read_line(&mut header)
                    .await
                    .expect("origin request headers should be readable");
                if header == "\r\n" || header.is_empty() {
                    break;
                }
            }
            let _ = request_seen_sender.send(request_line);
            let _ = release_origin_rx.await;
            let _ = reader
                .get_mut()
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
        });
        let (runtime, mut events) = start_runtime_named(
            directory.path(),
            intercept_session(port),
            Arc::clone(&ca),
            "rama-cancel-intercept",
            Duration::from_secs(30),
        )
        .await?;
        let local_address = runtime.socket_path().to_path_buf();
        let socket_path = runtime.socket_path().to_path_buf();
        let runtime_id = runtime.runtime_id().clone();
        let mut client = open_tls_client(&local_address, &format!("localhost:{port}"), &ca).await?;
        client
            .write_all(
                format!("GET /allowed HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes(),
            )
            .await?;
        let request_line = timeout(Duration::from_secs(2), request_seen)
            .await?
            .map_err(|_| io::Error::other("origin did not receive the intercepted request"))?;
        assert!(request_line.starts_with("GET /allowed HTTP/1.1"));

        let shutdown = tokio::spawn(runtime.shutdown(Duration::from_secs(10)));
        tokio::task::yield_now().await;
        shutdown.abort();
        let _ = shutdown.await;

        timeout(Duration::from_secs(2), async {
            while socket_path.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert!(UnixStream::connect(local_address).await.is_err());
        let mut byte = [0; 1];
        match timeout(Duration::from_secs(1), client.read(&mut byte)).await? {
            Ok(0) | Err(_) => (),
            other => panic!("cancelled intercepted connection remained open: {other:?}"),
        }
        let event = timeout(Duration::from_secs(2), events.recv())
            .await?
            .ok_or_else(|| io::Error::other("session event channel should remain open"))?;
        assert_eq!(event.runtime_id, runtime_id);
        assert!(
            event.result.is_err(),
            "cancelled proxy task failure must propagate to the session registry"
        );
        drop(release_origin);
        origin_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn proxy_task_failure_is_reported_to_the_session_event_channel() -> Result<(), TestError>
    {
        let directory = tempfile::tempdir()?;
        let ca = write_managed_ca(directory.path());
        let (runtime, mut events) = start_runtime(
            directory.path(),
            tunnel_session(443),
            ca,
            Duration::from_secs(1),
        )
        .await?;

        runtime.task_abort.abort();
        let event = timeout(Duration::from_secs(2), events.recv())
            .await?
            .ok_or_else(|| io::Error::other("session event channel should remain open"))?;
        assert!(
            event.result.is_err(),
            "proxy task failure must reach its supervisor"
        );
        runtime.shutdown(Duration::from_secs(1)).await;
        Ok(())
    }

    #[tokio::test]
    async fn interception_closes_non_tls_and_fragmented_client_hellos() -> Result<(), TestError> {
        let directory = tempfile::tempdir()?;
        let ca = write_managed_ca(directory.path());
        let upstream = TcpListener::bind("127.0.0.1:0").await?;
        let port = upstream.local_addr()?.port();
        let (runtime, _events) = start_runtime(
            directory.path(),
            intercept_session(port),
            ca,
            Duration::from_millis(100),
        )
        .await?;

        let mut unsupported = UnixStream::connect(runtime.socket_path()).await?;
        unsupported
            .write_all(
                format!(
                    "CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\nContent-Length: 1\r\n\r\nx"
                )
                .as_bytes(),
            )
            .await?;
        let mut response = BufReader::new(unsupported);
        let mut status = String::new();
        timeout(Duration::from_secs(1), response.read_line(&mut status)).await??;
        assert!(
            status.starts_with("HTTP/1.1 400"),
            "CONNECT bodies must be rejected"
        );

        for payload in [
            b"not TLS".as_slice(),
            &[0x16, 0x03, 0x03, 0x00, 0x20, 0x01, 0x00],
        ] {
            let mut stream = UnixStream::connect(runtime.socket_path()).await?;
            stream
                .write_all(
                    format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n")
                        .as_bytes(),
                )
                .await?;
            let mut reader = BufReader::new(stream);
            let mut status = String::new();
            timeout(Duration::from_secs(1), reader.read_line(&mut status)).await??;
            assert!(status.starts_with("HTTP/1.1 200"));
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).await?;
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            reader.get_mut().write_all(payload).await?;
            let mut byte = [0u8; 1];
            match timeout(Duration::from_secs(1), reader.read(&mut byte)).await {
                Ok(Ok(0)) => (),
                Ok(Err(error))
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset
                            | io::ErrorKind::BrokenPipe
                            | io::ErrorKind::UnexpectedEof
                    ) =>
                {
                    // Closing without a TLS close-notify can reset the TCP stream.
                }
                other => {
                    panic!("failed TLS inspection returned tunnel bytes or stayed open: {other:?}")
                }
            }
        }

        runtime.shutdown(Duration::from_secs(2)).await;
        Ok(())
    }

    #[tokio::test]
    async fn valid_client_hello_split_after_one_byte_is_inspected_before_forwarding()
    -> Result<(), TestError> {
        let directory = tempfile::tempdir()?;
        let ca = write_managed_ca(directory.path());
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
        let upstream_address = upstream_listener.local_addr()?;
        let upstream_task = tokio::spawn(async move {
            let (stream, _) = upstream_listener
                .accept()
                .await
                .expect("upstream should accept the proxy connection");
            let tls = TlsAcceptor::from(Arc::new(upstream_tls_config("localhost")))
                .accept(stream)
                .await
                .expect("upstream TLS should complete");
            let mut tls = tls;
            let mut request = [0; 512];
            match timeout(Duration::from_millis(500), tls.read(&mut request)).await {
                Ok(Ok(read)) if read > 0 => Some(request[..read].to_vec()),
                _ => None,
            }
        });
        let (runtime, _) = start_runtime(
            directory.path(),
            intercept_session(upstream_address.port()),
            Arc::clone(&ca),
            Duration::from_secs(2),
        )
        .await?;

        let authority = format!("localhost:{}", upstream_address.port());
        let mut connect = UnixStream::connect(runtime.socket_path()).await?;
        connect
            .write_all(
                format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
            )
            .await?;
        let mut connect = BufReader::new(connect);
        let mut status = String::new();
        timeout(Duration::from_secs(2), connect.read_line(&mut status)).await??;
        assert!(status.starts_with("HTTP/1.1 200"));
        loop {
            let mut line = String::new();
            connect.read_line(&mut line).await?;
            if line == "\r\n" || line.is_empty() {
                break;
            }
        }

        let (_, parsed_ca) = x509_parser::pem::parse_x509_pem(ca.public_certificate_pem())?;
        let (_, _, upstream_root) = upstream_root();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(parsed_ca.contents))?;
        roots.add(CertificateDer::from(upstream_root))?;
        let mut client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tls = TlsConnector::from(Arc::new(client_config))
            .connect(
                rustls::pki_types::ServerName::try_from("localhost".to_owned())?,
                FragmentFirstWrite::new(connect.into_inner()),
            )
            .await;

        if let Ok(mut tls) = tls {
            tls.write_all(
                format!("GET /blocked HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await?;
            let mut reader = BufReader::new(tls);
            let mut response = String::new();
            timeout(Duration::from_secs(2), reader.read_line(&mut response)).await??;
            assert!(
                response.starts_with("HTTP/1.1 403"),
                "a valid fragmented ClientHello must reach path policy: {response:?}"
            );
        }

        let origin_request = timeout(Duration::from_secs(2), upstream_task).await??;
        assert!(
            origin_request.is_none(),
            "an interception-required fragmented ClientHello must not turn into an opaque tunnel"
        );
        runtime.shutdown(Duration::from_secs(2)).await;
        Ok(())
    }

    #[tokio::test]
    async fn rejects_tls_sni_that_does_not_match_connect_authority() -> Result<(), TestError> {
        let directory = tempfile::tempdir()?;
        let ca = write_managed_ca(directory.path());
        let upstream = TcpListener::bind("127.0.0.1:0").await?;
        let port = upstream.local_addr()?.port();
        let (runtime, _events) = start_runtime(
            directory.path(),
            intercept_session(port),
            ca.clone(),
            Duration::from_secs(1),
        )
        .await?;

        let result = open_tls_client_for_name(
            runtime.socket_path(),
            &format!("localhost:{port}"),
            "other.example",
            &ca,
        )
        .await;
        assert!(
            result.is_err(),
            "mismatched SNI must not establish interception"
        );
        runtime.shutdown(Duration::from_secs(2)).await;
        Ok(())
    }

    #[tokio::test]
    async fn rejects_upstream_certificate_hostname_mismatch_through_running_proxy()
    -> Result<(), TestError> {
        let directory = tempfile::tempdir()?;
        let ca = write_managed_ca(directory.path());
        let (seen_tx, _seen_rx) = oneshot::channel();
        let (origin_address, origin_task, accepted) =
            start_origin(upstream_tls_config("other.example"), seen_tx).await?;
        let port = origin_address.port();
        let (runtime, _events) = start_runtime(
            directory.path(),
            intercept_session(port),
            Arc::clone(&ca),
            Duration::from_secs(2),
        )
        .await?;
        if let Ok(mut tls) =
            open_tls_client(runtime.socket_path(), &format!("localhost:{port}"), &ca).await
        {
            tls.write_all(
                format!("GET /allowed HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes(),
            )
            .await?;
            let mut byte = [0u8; 1];
            let result = timeout(Duration::from_secs(3), tls.read(&mut byte)).await?;
            assert!(
                result.is_err() || result? == 0,
                "mismatched upstream identity must not return data"
            );
        }
        timeout(Duration::from_secs(2), accepted).await??;
        origin_task.abort();
        runtime.shutdown(Duration::from_secs(2)).await;
        Ok(())
    }

    #[tokio::test]
    async fn rejects_expired_upstream_certificate_through_running_proxy() -> Result<(), TestError> {
        let directory = tempfile::tempdir()?;
        let ca = write_managed_ca(directory.path());
        let (seen_tx, _seen_rx) = oneshot::channel();
        let (origin_address, origin_task, accepted) = start_origin(
            upstream_tls_config_with_expiration("localhost", true),
            seen_tx,
        )
        .await?;
        let port = origin_address.port();
        let (runtime, _events) = start_runtime(
            directory.path(),
            intercept_session(port),
            Arc::clone(&ca),
            Duration::from_secs(2),
        )
        .await?;
        if let Ok(mut tls) =
            open_tls_client(runtime.socket_path(), &format!("localhost:{port}"), &ca).await
        {
            tls.write_all(
                format!("GET /allowed HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes(),
            )
            .await?;
            let mut byte = [0u8; 1];
            let result = timeout(Duration::from_secs(3), tls.read(&mut byte)).await?;
            assert!(
                result.is_err() || result? == 0,
                "expired upstream identity must not return data"
            );
        }
        timeout(Duration::from_secs(2), accepted).await??;
        origin_task.abort();
        runtime.shutdown(Duration::from_secs(2)).await;
        Ok(())
    }
}
