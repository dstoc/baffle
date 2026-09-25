//! One Hudsucker proxy instance hosted by the daemon's shared Tokio runtime.

use std::{
    fmt, fs,
    future::Future,
    io,
    net::SocketAddr,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hudsucker::{
    Body, HttpContext, HttpHandler, Proxy, RequestOrResponse, TlsInterception, WebSocketContext,
    WebSocketHandler,
    hyper::{
        Request, Response, StatusCode,
        header::{CONNECTION, HeaderName, HeaderValue, UPGRADE},
    },
    rustls::crypto::aws_lc_rs,
    tokio_tungstenite::tungstenite::Message,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixListener},
    sync::Semaphore,
    task::{AbortHandle, JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

use crate::{
    ca::ManagedCa,
    config::{HeaderInjection, InjectionFormat, RuleMode, SessionConfig},
    policy::{AuthorizationError, SessionPolicy},
    secrets::{ResolvedSecrets, SecretValue},
    telemetry::Metrics,
};

/// A stable identifier for one running Hudsucker instance.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RuntimeId(String);

impl RuntimeId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A startup or fatal error from one proxy instance.
#[derive(Debug)]
pub enum ProxyRuntimeError {
    Bind(io::Error),
    BindSocket(io::Error),
    Bridge(io::Error),
    Build(hudsucker::Error),
    Run(hudsucker::Error),
    Task(String),
}

impl ProxyRuntimeError {
    pub fn class(&self) -> &'static str {
        match self {
            Self::Bind(_) => "bind",
            Self::BindSocket(_) => "socket_bind",
            Self::Bridge(_) => "bridge",
            Self::Build(_) => "proxy_build",
            Self::Run(_) => "proxy_run",
            Self::Task(_) => "task",
        }
    }
}

impl fmt::Display for ProxyRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind(_) => formatter.write_str("could not bind proxy listener"),
            Self::BindSocket(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                formatter.write_str("proxy Unix socket path already exists")
            }
            Self::BindSocket(_) => formatter.write_str("could not bind proxy Unix socket"),
            Self::Bridge(_) => formatter.write_str("proxy Unix socket bridge failed"),
            Self::Build(_) => formatter.write_str("could not build proxy"),
            Self::Run(_) => formatter.write_str("proxy runtime failed"),
            Self::Task(_) => formatter.write_str("proxy runtime task failed"),
        }
    }
}

/// A typed notification that a proxy runtime exited.
#[derive(Debug)]
pub struct ProxyRuntimeEvent {
    pub runtime_id: RuntimeId,
    pub result: Result<(), ProxyRuntimeError>,
}

/// A running proxy with its dedicated TCP and Unix listeners and tasks.
pub struct ProxyRuntime {
    runtime_id: RuntimeId,
    local_addr: SocketAddr,
    socket_path: PathBuf,
    cancellation: CancellationToken,
    bridge_ingress_shutdown: CancellationToken,
    bridge_force_cancellation: CancellationToken,
    runtime_abort: AbortHandle,
    bridge_abort: AbortHandle,
    task: JoinHandle<()>,
    metrics: Arc<Metrics>,
}

impl ProxyRuntime {
    /// Bind and start one proxy from a validated session configuration.
    ///
    /// Hudsucker builds its outbound client inside each `start` call. This
    /// method creates a separate builder and handler for every runtime while
    /// sharing only the daemon-owned CA material.
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
            Duration::from_secs(5),
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
        connection_timeout: Duration,
        io_timeout: Duration,
        metrics: Arc<Metrics>,
        events: tokio::sync::mpsc::UnboundedSender<ProxyRuntimeEvent>,
    ) -> Result<Self, ProxyRuntimeError> {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .map_err(ProxyRuntimeError::Bind)?;
        let local_addr = listener.local_addr().map_err(ProxyRuntimeError::Bind)?;
        let (unix_listener, socket_guard) =
            bind_unix_listener(&socket_path).map_err(ProxyRuntimeError::BindSocket)?;
        let cancellation = CancellationToken::new();
        let shutdown = cancellation.clone();
        let bridge_ingress_shutdown = CancellationToken::new();
        let bridge_force_cancellation = CancellationToken::new();
        let policy = Arc::new(SessionPolicy::compile(&session));

        let policy_handler = PolicyHandler::with_metrics(
            runtime_id.clone(),
            Arc::clone(&policy),
            secrets,
            Arc::clone(&metrics),
            cancellation.clone(),
        );
        let proxy = Proxy::builder()
            .with_listener(listener)
            .with_ca(ca.for_proxy())
            .with_rustls_connector(aws_lc_rs::default_provider())
            .with_http_handler(policy_handler.clone())
            .with_websocket_handler(policy_handler)
            .with_graceful_shutdown(async move {
                shutdown.cancelled().await;
            })
            .build()
            .map_err(ProxyRuntimeError::Build)?;

        let mut bridge_task = tokio::spawn(run_bridge(
            unix_listener,
            socket_guard,
            BridgeSettings {
                upstream: local_addr,
                permits: Arc::new(Semaphore::new(max_connections)),
                connection_timeout,
                io_timeout,
                ingress_shutdown: bridge_ingress_shutdown.clone(),
                force_cancellation: bridge_force_cancellation.clone(),
                metrics: Arc::clone(&metrics),
                runtime_id: runtime_id.clone(),
            },
        ));
        let bridge_abort = bridge_task.abort_handle();

        // Keep the Hudsucker task's result observable even if the task panics.
        let mut runtime_task = tokio::spawn(proxy.start());
        let runtime_abort = runtime_task.abort_handle();
        let event_id = runtime_id.clone();
        let supervisor_cancellation = cancellation.clone();
        let supervisor_ingress_shutdown = bridge_ingress_shutdown.clone();
        let supervisor_force_cancellation = bridge_force_cancellation.clone();
        let task = tokio::spawn(async move {
            let (runtime_result, bridge_result) = tokio::select! {
                runtime_result = &mut runtime_task => {
                    let runtime_result = map_runtime_result(runtime_result);
                    supervisor_ingress_shutdown.cancel();
                    if runtime_result.is_err() {
                        supervisor_force_cancellation.cancel();
                    }
                    supervisor_cancellation.cancel();
                    (runtime_result, map_bridge_result(bridge_task.await))
                }
                bridge_result = &mut bridge_task => {
                    let bridge_result = map_bridge_result(bridge_result);
                    if bridge_result.is_err() {
                        supervisor_force_cancellation.cancel();
                    }
                    supervisor_cancellation.cancel();
                    (map_runtime_result(runtime_task.await), bridge_result)
                }
            };
            let result = runtime_result.and(bridge_result);
            if result.is_err() {
                tracing::error!(
                    event = "session_lifecycle",
                    session_id = %event_id.as_str(),
                    state = "failed",
                    "proxy session task failed"
                );
            }
            let _ = events.send(ProxyRuntimeEvent {
                runtime_id: event_id,
                result,
            });
        });

        Ok(Self {
            runtime_id,
            local_addr,
            socket_path,
            cancellation,
            bridge_ingress_shutdown,
            bridge_force_cancellation,
            runtime_abort,
            bridge_abort,
            task,
            metrics,
        })
    }

    pub fn runtime_id(&self) -> &RuntimeId {
        &self.runtime_id
    }

    /// Return the pre-bound loopback listener address used by Hudsucker.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Return the private Unix-domain socket used to reach this proxy.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Ask Hudsucker to drain active connections, then bound the wait.
    pub async fn shutdown(mut self, grace: Duration) {
        tracing::info!(
            event = "session_lifecycle",
            session_id = %self.runtime_id.as_str(),
            state = "stopping",
            "proxy session shutdown started"
        );
        self.bridge_ingress_shutdown.cancel();
        self.cancellation.cancel();
        if tokio::time::timeout(grace, &mut self.task).await.is_err() {
            let forced_shutdowns = self.metrics.forced_shutdown();
            tracing::warn!(
                event = "forced_shutdown",
                session_id = %self.runtime_id.as_str(),
                forced_shutdowns,
                "proxy session exceeded its shutdown grace period"
            );
            self.runtime_abort.abort();
            self.bridge_abort.abort();
            let _ = (&mut self.task).await;
        } else {
            tracing::info!(
                event = "session_lifecycle",
                session_id = %self.runtime_id.as_str(),
                state = "stopped",
                "proxy session stopped"
            );
        }
    }
}

fn map_runtime_result(
    result: Result<Result<(), hudsucker::Error>, tokio::task::JoinError>,
) -> Result<(), ProxyRuntimeError> {
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(ProxyRuntimeError::Run(error)),
        Err(error) => Err(ProxyRuntimeError::Task(error.to_string())),
    }
}

fn map_bridge_result(
    result: Result<io::Result<()>, tokio::task::JoinError>,
) -> Result<(), ProxyRuntimeError> {
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(ProxyRuntimeError::Bridge(error)),
        Err(error) => Err(ProxyRuntimeError::Task(error.to_string())),
    }
}

struct UnixSocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl UnixSocketGuard {
    fn bind(path: &Path) -> io::Result<(UnixListener, Self)> {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "Unix socket path already exists",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let listener = UnixListener::bind(path)?;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket() {
            return Err(io::Error::other("bound Unix path is not a socket"));
        }
        let guard = Self {
            path: path.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };

        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        let metadata = fs::symlink_metadata(path)?;
        if !guard.matches(&metadata) || metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(io::Error::other(
                "bound Unix socket has unexpected identity or permissions",
            ));
        }

        Ok((listener, guard))
    }

    fn matches(&self, metadata: &fs::Metadata) -> bool {
        metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
    }
}

impl Drop for UnixSocketGuard {
    fn drop(&mut self) {
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) if self.matches(&metadata) => {
                if let Err(error) = fs::remove_file(&self.path)
                    && error.kind() != io::ErrorKind::NotFound
                {
                    tracing::warn!(path = %self.path.display(), %error, "failed to remove proxy Unix socket");
                }
            }
            Ok(_) => tracing::warn!(
                path = %self.path.display(),
                "proxy Unix socket path changed; leaving replacement untouched"
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(
                path = %self.path.display(),
                %error,
                "could not inspect proxy Unix socket during cleanup"
            ),
        }
    }
}

fn bind_unix_listener(path: &Path) -> io::Result<(UnixListener, UnixSocketGuard)> {
    UnixSocketGuard::bind(path)
}

struct BridgeSettings {
    upstream: SocketAddr,
    permits: Arc<Semaphore>,
    connection_timeout: Duration,
    io_timeout: Duration,
    ingress_shutdown: CancellationToken,
    force_cancellation: CancellationToken,
    metrics: Arc<Metrics>,
    runtime_id: RuntimeId,
}

async fn run_bridge(
    listener: UnixListener,
    socket_guard: UnixSocketGuard,
    settings: BridgeSettings,
) -> io::Result<()> {
    let BridgeSettings {
        upstream,
        permits,
        connection_timeout,
        io_timeout,
        ingress_shutdown,
        force_cancellation,
        metrics,
        runtime_id,
    } = settings;
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = ingress_shutdown.cancelled() => break,
            _ = force_cancellation.cancelled() => break,
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    metrics.bridge_failure();
                    return Err(io::Error::other(format!("bridge connection task failed: {error}")));
                }
            }
            accepted = listener.accept() => {
                let (mut unix_stream, _) = match accepted {
                    Ok(connection) => connection,
                    Err(error) => {
                        metrics.bridge_failure();
                        return Err(error);
                    }
                };
                let permit = match Arc::clone(&permits).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        drop(unix_stream);
                        continue;
                    }
                };
                metrics.connection_started();
                let connection_metrics = Arc::clone(&metrics);
                let session_id = runtime_id.clone();
                let connection_guard = ActiveConnectionGuard(Arc::clone(&metrics));
                let connection_cancellation = force_cancellation.clone();
                connections.spawn(async move {
                    let _connection_guard = connection_guard;
                    tokio::select! {
                        biased;
                        _ = connection_cancellation.cancelled() => {}
                        result = async {
                            let mut tcp_stream = match tokio::time::timeout(
                                connection_timeout,
                                TcpStream::connect(upstream),
                            ).await {
                                Ok(Ok(stream)) => stream,
                                Ok(Err(error)) => {
                                    let failures = connection_metrics.upstream_failure();
                                    tracing::warn!(
                                        event = "upstream_failure",
                                        session_id = %session_id.as_str(),
                                        upstream_failures = failures,
                                        error_kind = ?error.kind(),
                                        "proxy bridge could not connect to its upstream listener"
                                    );
                                    return Err(error);
                                }
                                Err(_) => {
                                    let failures = connection_metrics.upstream_failure();
                                    tracing::warn!(
                                        event = "upstream_failure",
                                        session_id = %session_id.as_str(),
                                        upstream_failures = failures,
                                        error_kind = "timed_out",
                                        "proxy bridge connection timed out"
                                    );
                                    return Err(io::Error::new(io::ErrorKind::TimedOut, "upstream connection timed out"));
                                }
                            };
                            copy_bidirectional_with_timeout(&mut unix_stream, &mut tcp_stream, io_timeout).await?;
                            Ok::<(), io::Error>(())
                        } => {
                            if let Err(error) = result {
                                tracing::debug!(
                                    event = "bridge_connection_closed",
                                    session_id = %session_id.as_str(),
                                    error_kind = ?error.kind(),
                                    "proxy bridge connection closed"
                                );
                            }
                        }
                    }
                    drop(permit);
                });
            }
        }
    }

    // Stop new clients and make the socket path unavailable before draining
    // streams that were already accepted.
    drop(listener);
    drop(socket_guard);

    while let Some(result) = connections.join_next().await {
        if let Err(error) = result {
            metrics.bridge_failure();
            return Err(io::Error::other(format!(
                "bridge connection task failed during shutdown: {error}"
            )));
        }
    }
    Ok(())
}

struct ActiveConnectionGuard(Arc<Metrics>);

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.0.connection_stopped();
    }
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
    let left_to_right = copy_with_timeout(left_reader, right_writer, io_timeout);
    let right_to_left = copy_with_timeout(right_reader, left_writer, io_timeout);
    tokio::try_join!(left_to_right, right_to_left)
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

#[cfg(test)]
mod tests {
    use std::{fs, sync::Arc, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream, UnixStream},
        sync::Semaphore,
        time::timeout,
    };
    use tokio_util::sync::CancellationToken;

    use super::{BridgeSettings, ProxyRuntime, RuntimeId, UnixSocketGuard, run_bridge};
    use crate::{
        ca::ManagedCa,
        config::{CaConfig, ControlRequest},
        telemetry::Metrics,
    };
    use hudsucker::rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};

    fn write_test_ca(directory: &std::path::Path) -> Arc<ManagedCa> {
        use std::os::unix::fs::PermissionsExt;

        let key_pair = KeyPair::generate().expect("CA key should be generated");
        let mut parameters = CertificateParams::default();
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let certificate = parameters
            .self_signed(&key_pair)
            .expect("CA certificate should be generated");
        let certificate_path = directory.join("runtime-test-ca.pem");
        let private_key_path = directory.join("runtime-test-ca-key.pem");
        fs::write(&certificate_path, certificate.pem()).expect("CA certificate should be saved");
        fs::write(&private_key_path, key_pair.serialize_pem()).expect("CA key should be saved");
        fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600))
            .expect("CA key permissions should be restricted");
        Arc::new(
            ManagedCa::load(&CaConfig {
                certificate: certificate_path,
                private_key: private_key_path,
            })
            .expect("test CA should load"),
        )
    }

    fn session_config() -> crate::config::SessionConfig {
        let ControlRequest::Create { session, .. } = ControlRequest::from_toml(
            "version = 1\noperation = \"create\"\n\n[session]\npersistent = true\n\n[[rules]]\nhost = \"runtime.example.test\"\nmode = \"tunnel\"\n",
        )
        .expect("session config should parse")
        else {
            panic!("test request should create a session");
        };
        session
    }

    #[tokio::test]
    async fn admission_limit_rejects_before_opening_another_upstream_connection() {
        let directory = tempfile::tempdir().expect("test directory should be created");
        let socket_path = directory.path().join("bridge.sock");
        let (unix_listener, socket_guard) =
            UnixSocketGuard::bind(&socket_path).expect("Unix bridge should bind");
        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test upstream should bind");
        let upstream_address = upstream
            .local_addr()
            .expect("test upstream address should be available");
        let cancellation = CancellationToken::new();
        let force_cancellation = CancellationToken::new();
        let bridge = tokio::spawn(run_bridge(
            unix_listener,
            socket_guard,
            BridgeSettings {
                upstream: upstream_address,
                permits: Arc::new(Semaphore::new(1)),
                connection_timeout: Duration::from_secs(1),
                io_timeout: Duration::from_secs(1),
                ingress_shutdown: cancellation.clone(),
                force_cancellation: force_cancellation.clone(),
                metrics: Arc::new(Metrics::default()),
                runtime_id: RuntimeId::new("bridge-test"),
            },
        ));

        let _first_client = UnixStream::connect(&socket_path)
            .await
            .expect("first Unix client should connect");
        let (_first_upstream, _) = timeout(Duration::from_secs(2), upstream.accept())
            .await
            .expect("first bridge should open an upstream connection")
            .expect("first upstream connection should succeed");

        let mut rejected_client = UnixStream::connect(&socket_path)
            .await
            .expect("Unix listener should accept a client while at capacity");
        let mut byte = [0; 1];
        let read = timeout(Duration::from_secs(2), rejected_client.read(&mut byte))
            .await
            .expect("over-limit client should be closed")
            .expect("over-limit client close should be readable");
        assert_eq!(read, 0, "over-limit client must not be bridged");
        assert!(
            timeout(Duration::from_millis(50), upstream.accept())
                .await
                .is_err(),
            "admission must happen before opening an upstream TCP connection"
        );

        cancellation.cancel();
        force_cancellation.cancel();
        timeout(Duration::from_secs(2), bridge)
            .await
            .expect("bridge should stop when its session is cancelled")
            .expect("bridge task should join")
            .expect("bridge should shut down cleanly");
        assert!(
            !socket_path.exists(),
            "session cancellation removes its socket"
        );
    }

    #[tokio::test]
    async fn ingress_shutdown_removes_socket_and_drains_accepted_streams() {
        let directory = tempfile::tempdir().expect("test directory should be created");
        let socket_path = directory.path().join("draining.sock");
        let (unix_listener, socket_guard) =
            UnixSocketGuard::bind(&socket_path).expect("Unix bridge should bind");
        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test upstream should bind");
        let upstream_address = upstream
            .local_addr()
            .expect("test upstream address should be available");
        let ingress_shutdown = CancellationToken::new();
        let force_cancellation = CancellationToken::new();
        let bridge = tokio::spawn(run_bridge(
            unix_listener,
            socket_guard,
            BridgeSettings {
                upstream: upstream_address,
                permits: Arc::new(Semaphore::new(1)),
                connection_timeout: Duration::from_secs(1),
                io_timeout: Duration::from_secs(1),
                ingress_shutdown: ingress_shutdown.clone(),
                force_cancellation,
                metrics: Arc::new(Metrics::default()),
                runtime_id: RuntimeId::new("bridge-test"),
            },
        ));

        let mut client = UnixStream::connect(&socket_path)
            .await
            .expect("Unix client should connect before shutdown");
        let (mut upstream_stream, _) = timeout(Duration::from_secs(2), upstream.accept())
            .await
            .expect("bridge should open an upstream connection")
            .expect("upstream connection should succeed");

        ingress_shutdown.cancel();
        timeout(Duration::from_secs(2), async {
            while socket_path.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("ingress shutdown should unlink the socket promptly");
        assert!(!bridge.is_finished(), "accepted streams should drain");
        assert!(
            UnixStream::connect(&socket_path).await.is_err(),
            "new clients should not connect after ingress shutdown"
        );

        client
            .write_all(b"drain request")
            .await
            .expect("accepted client stream should remain writable");
        let mut request = [0; 13];
        timeout(
            Duration::from_secs(2),
            upstream_stream.read_exact(&mut request),
        )
        .await
        .expect("upstream should receive the in-flight request")
        .expect("in-flight request should be readable");
        assert_eq!(&request, b"drain request");
        upstream_stream
            .write_all(b"drain response")
            .await
            .expect("upstream response should be writable");
        let mut response = [0; 14];
        timeout(Duration::from_secs(2), client.read_exact(&mut response))
            .await
            .expect("client should receive the in-flight response")
            .expect("in-flight response should be readable");
        assert_eq!(&response, b"drain response");

        drop(client);
        drop(upstream_stream);
        timeout(Duration::from_secs(2), bridge)
            .await
            .expect("bridge should finish after accepted streams close")
            .expect("bridge task should join")
            .expect("bridge should shut down cleanly");
    }

    #[tokio::test]
    async fn idle_bridge_io_times_out_and_releases_its_connection_slot() {
        let directory = tempfile::tempdir().expect("test directory should be created");
        let socket_path = directory.path().join("idle.sock");
        let (unix_listener, socket_guard) =
            UnixSocketGuard::bind(&socket_path).expect("Unix bridge should bind");
        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test upstream should bind");
        let upstream_address = upstream
            .local_addr()
            .expect("test upstream address should be available");
        let ingress_shutdown = CancellationToken::new();
        let force_cancellation = CancellationToken::new();
        let metrics = Arc::new(Metrics::default());
        let bridge = tokio::spawn(run_bridge(
            unix_listener,
            socket_guard,
            BridgeSettings {
                upstream: upstream_address,
                permits: Arc::new(Semaphore::new(1)),
                connection_timeout: Duration::from_secs(1),
                io_timeout: Duration::from_millis(50),
                ingress_shutdown: ingress_shutdown.clone(),
                force_cancellation,
                metrics: Arc::clone(&metrics),
                runtime_id: RuntimeId::new("idle-bridge"),
            },
        ));

        let mut client = UnixStream::connect(&socket_path)
            .await
            .expect("Unix client should connect");
        let (_upstream_stream, _) = timeout(Duration::from_secs(2), upstream.accept())
            .await
            .expect("bridge should connect to its upstream")
            .expect("upstream accept should succeed");
        let mut byte = [0; 1];
        let read = timeout(Duration::from_secs(1), client.read(&mut byte))
            .await
            .expect("idle bridge should close after the I/O timeout")
            .expect("timed out bridge should close cleanly");
        assert_eq!(read, 0);
        assert_eq!(metrics.snapshot().active_connections, 0);
        assert_eq!(metrics.snapshot().upstream_failures, 0);

        ingress_shutdown.cancel();
        timeout(Duration::from_secs(1), bridge)
            .await
            .expect("bridge should stop after ingress cancellation")
            .expect("bridge task should join")
            .expect("bridge should shut down cleanly");
        assert!(!socket_path.exists());
    }

    #[tokio::test]
    async fn one_proxy_task_failure_is_reported_without_stopping_another_session() {
        let directory = tempfile::tempdir().expect("test directory should be created");
        let ca = write_test_ca(directory.path());
        let (event_sender, mut events) = tokio::sync::mpsc::unbounded_channel();
        let first_id = RuntimeId::new("runtime-fails");
        let first = ProxyRuntime::start(
            first_id.clone(),
            session_config(),
            Arc::clone(&ca),
            directory.path().join("fails.sock"),
            4,
            event_sender.clone(),
        )
        .await
        .expect("first runtime should start");
        let second = ProxyRuntime::start(
            RuntimeId::new("runtime-survives"),
            session_config(),
            ca,
            directory.path().join("survives.sock"),
            4,
            event_sender,
        )
        .await
        .expect("second runtime should start");

        first.runtime_abort.abort();
        let failure = timeout(Duration::from_secs(2), events.recv())
            .await
            .expect("failed runtime should report its exit")
            .expect("runtime event channel should remain open");
        assert_eq!(failure.runtime_id, first_id);
        assert!(
            failure.result.is_err(),
            "runtime task failure should propagate"
        );
        let surviving_connection = timeout(
            Duration::from_secs(2),
            TcpStream::connect(second.local_addr()),
        )
        .await
        .expect("peer runtime should keep accepting connections")
        .expect("peer runtime should remain available");
        drop(surviving_connection);

        first.shutdown(Duration::from_secs(1)).await;
        second.shutdown(Duration::from_secs(1)).await;
        assert!(!directory.path().join("fails.sock").exists());
        assert!(!directory.path().join("survives.sock").exists());
    }
}

impl Drop for ProxyRuntime {
    fn drop(&mut self) {
        self.bridge_ingress_shutdown.cancel();
        self.bridge_force_cancellation.cancel();
        self.cancellation.cancel();
        // A caller can be cancelled while awaiting graceful shutdown. Abort
        // owned tasks on drop so that cancellation cannot detach a live proxy
        // or bridge from its session manager.
        self.runtime_abort.abort();
        self.bridge_abort.abort();
    }
}

#[derive(Clone)]
pub(crate) struct PolicyHandler {
    runtime_id: RuntimeId,
    policy: Arc<SessionPolicy>,
    secrets: Arc<ResolvedSecrets>,
    metrics: Arc<Metrics>,
    cancellation: CancellationToken,
}

impl PolicyHandler {
    #[cfg(test)]
    pub(crate) fn new(runtime_id: RuntimeId, policy: Arc<SessionPolicy>) -> Self {
        Self::with_metrics(
            runtime_id,
            policy,
            Arc::new(ResolvedSecrets::default()),
            Arc::new(Metrics::default()),
            CancellationToken::new(),
        )
    }

    fn with_metrics(
        runtime_id: RuntimeId,
        policy: Arc<SessionPolicy>,
        secrets: Arc<ResolvedSecrets>,
        metrics: Arc<Metrics>,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            runtime_id,
            policy,
            secrets,
            metrics,
            cancellation,
        }
    }

    #[cfg(test)]
    pub(crate) fn handle_policy_request(&self, request: Request<Body>) -> RequestOrResponse {
        self.handle_policy_request_with_context(request, None)
    }

    fn handle_policy_request_with_context(
        &self,
        mut request: Request<Body>,
        connect_authority: Option<&hudsucker::hyper::http::uri::Authority>,
    ) -> RequestOrResponse {
        let authorization = if self.cancellation.is_cancelled() {
            Err(AuthorizationError::Denied)
        } else {
            self.policy
                .authorize_proxy_request(&mut request, connect_authority)
        };
        match authorization {
            Ok((_, injections))
                if !injections.is_empty()
                    && has_unsupported_upgrade_or_hop_header(&request, injections) =>
            {
                self.deny_request(&request, AuthorizationError::Denied)
            }
            Ok((_, injections)) => match inject_headers(&mut request, injections, &self.secrets) {
                Ok(()) => RequestOrResponse::Request(request),
                Err(()) => self.deny_request(&request, AuthorizationError::Denied),
            },
            Err(error) => self.deny_request(&request, error),
        }
    }

    fn deny_request(
        &self,
        request: &Request<Body>,
        error: AuthorizationError,
    ) -> RequestOrResponse {
        let request_count = self.metrics.denied_request();
        let destination = request_destination(request);
        let (status, reason) = match error {
            AuthorizationError::InvalidAuthority => (StatusCode::BAD_REQUEST, "invalid_authority"),
            AuthorizationError::Denied => (StatusCode::FORBIDDEN, "no_matching_rule"),
        };
        tracing::info!(
            event = "request_decision",
            session_id = %self.runtime_id.as_str(),
            method = %request.method(),
            %destination,
            outcome = "denied",
            reason,
            denied_requests = request_count,
            "proxy request denied"
        );
        Response::builder()
            .status(status)
            .body(Body::empty())
            .expect("static policy response is valid")
            .into()
    }

    pub(crate) fn connect_should_intercept(&self, request: &Request<Body>) -> bool {
        if self.cancellation.is_cancelled() {
            return true;
        }
        self.policy
            .authorize(request)
            .map(|mode| mode == RuleMode::Intercept)
            // An invalid request is rejected by handle_request. Keep the
            // fallback in interception mode so errors never select a tunnel.
            .unwrap_or(true)
    }

    fn tls_should_intercept(
        &self,
        connect_authority: &hudsucker::hyper::http::uri::Authority,
        server_name: Option<&str>,
    ) -> TlsInterception {
        if !self.cancellation.is_cancelled()
            && self
                .policy
                .permits_tls_interception(connect_authority, server_name)
        {
            TlsInterception::Intercept
        } else {
            TlsInterception::Reject
        }
    }
}

fn has_unsupported_upgrade_or_hop_header(
    request: &Request<Body>,
    injections: &[HeaderInjection],
) -> bool {
    if request.headers().contains_key(UPGRADE) || connection_header_has(request, "upgrade") {
        return true;
    }
    injections
        .iter()
        .any(|injection| connection_header_has(request, &injection.header))
}

fn connection_header_has(request: &Request<Body>, expected: &str) -> bool {
    request
        .headers()
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case(expected))
}

fn inject_headers(
    request: &mut Request<Body>,
    injections: &[HeaderInjection],
    secrets: &ResolvedSecrets,
) -> Result<(), ()> {
    let values = injections
        .iter()
        .map(|injection| {
            let name = HeaderName::from_bytes(injection.header.as_bytes()).map_err(|_| ())?;
            let secret = secrets.get(injection.secret.as_str()).ok_or(())?;
            let value = format_secret(injection, secret)?;
            let value = HeaderValue::from_bytes(value.as_bytes()).map_err(|_| ())?;
            Ok((name, value))
        })
        .collect::<Result<Vec<_>, ()>>()?;

    for (name, value) in values {
        request.headers_mut().remove(&name);
        request.headers_mut().insert(name, value);
    }
    Ok(())
}

fn format_secret(injection: &HeaderInjection, secret: &SecretValue) -> Result<String, ()> {
    Ok(match injection.format {
        InjectionFormat::Raw => secret.as_str().to_owned(),
        InjectionFormat::Bearer => format!("Bearer {}", secret.as_str()),
        InjectionFormat::BasicPassword => {
            let username = injection.username.as_deref().ok_or(())?;
            let encoded = STANDARD.encode(format!("{username}:{}", secret.as_str()));
            format!("Basic {encoded}")
        }
    })
}

impl HttpHandler for PolicyHandler {
    fn handle_request(
        &mut self,
        ctx: &HttpContext,
        request: Request<Body>,
    ) -> impl Future<Output = RequestOrResponse> + Send {
        let response =
            self.handle_policy_request_with_context(request, ctx.connect_authority.as_ref());
        async move { response }
    }

    fn should_intercept_connect(
        &mut self,
        _ctx: &HttpContext,
        request: &Request<Body>,
    ) -> impl Future<Output = bool> + Send {
        let intercept = self.connect_should_intercept(request);
        async move { intercept }
    }

    fn should_intercept_tls(
        &mut self,
        _ctx: &HttpContext,
        connect_authority: &hudsucker::hyper::http::uri::Authority,
        client_hello: hudsucker::rustls::server::ClientHello<'_>,
    ) -> impl Future<Output = TlsInterception> + Send {
        let decision = self.tls_should_intercept(connect_authority, client_hello.server_name());
        async move { decision }
    }
}

fn request_authority(request: &Request<Body>) -> Option<hudsucker::hyper::http::uri::Authority> {
    request.uri().authority().cloned().or_else(|| {
        request
            .headers()
            .get(hudsucker::hyper::http::header::HOST)?
            .to_str()
            .ok()?
            .parse()
            .ok()
    })
}

fn safe_authority_host(authority: &hudsucker::hyper::http::uri::Authority) -> Option<String> {
    let host = authority.host();
    if host.is_empty()
        || host.len() > 253
        || !host.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
        })
    {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

fn request_destination(request: &Request<Body>) -> String {
    let Some(authority) = request_authority(request) else {
        return "unknown".into();
    };
    let Some(host) = safe_authority_host(&authority) else {
        return "unknown".into();
    };
    match authority
        .port_u16()
        .or_else(|| match request.uri().scheme_str() {
            Some("http") => Some(80),
            Some("https") => Some(443),
            _ => None,
        }) {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}

#[cfg(test)]
mod request_log_tests {
    use super::{PolicyHandler, RuntimeId, StatusCode, request_destination};
    use crate::{config::ControlRequest, policy::SessionPolicy};
    use hudsucker::{Body, RequestOrResponse, hyper::Request};
    use std::sync::Arc;

    fn session_policy() -> SessionPolicy {
        let ControlRequest::Create { session, .. } = ControlRequest::from_toml(
            "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"api.example.test\"\nmode = \"intercept\"\n",
        )
        .expect("test policy should parse")
        else {
            panic!("test request should create a session");
        };
        SessionPolicy::compile(&session)
    }

    #[test]
    fn request_metadata_excludes_path_query_and_credentials() {
        let request = Request::builder()
            .uri("https://user:password@api.example.test/private?token=secret")
            .body(Body::empty())
            .expect("request should build");
        assert_eq!(request_destination(&request), "api.example.test:443");

        let handler =
            PolicyHandler::new(RuntimeId::new("test-session"), Arc::new(session_policy()));
        let denied = Request::builder()
            .uri("https://example.net/private?token=secret")
            .body(Body::empty())
            .expect("request should build");
        assert!(matches!(
            handler.handle_policy_request(denied),
            RequestOrResponse::Response(response) if response.status() == StatusCode::FORBIDDEN
        ));
        assert_eq!(handler.metrics.snapshot().denied_requests, 1);
        assert_eq!(handler.runtime_id.as_str(), "test-session");
    }
}

#[cfg(test)]
mod header_injection_tests {
    use std::sync::Arc;

    use hudsucker::{
        Body, RequestOrResponse,
        hyper::{
            Request, StatusCode,
            header::{AUTHORIZATION, HeaderValue},
        },
    };

    use super::{PolicyHandler, RuntimeId};
    use crate::{
        config::ControlRequest, policy::SessionPolicy, secrets::ResolvedSecrets, telemetry::Metrics,
    };
    use tokio_util::sync::CancellationToken;

    const REST_CONFIG: &str = "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"api.github.com\"\nmode = \"intercept\"\nports = [443]\npaths = [\"/repos/dstoc/cladding\", \"/repos/dstoc/cladding/**\"]\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"github-api\"\nformat = \"bearer\"\n";

    const GIT_CONFIG: &str = "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"github.com\"\nmode = \"intercept\"\nports = [443]\npaths = [\"/dstoc/cladding.git/**\"]\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"github-git\"\nformat = \"basic_password\"\nusername = \"x-access-token\"\n";

    const COMBINED_CONFIG: &str = "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"api.github.com\"\nmode = \"intercept\"\nports = [443]\npaths = [\"/repos/dstoc/cladding\", \"/repos/dstoc/cladding/**\"]\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"github-api\"\nformat = \"bearer\"\n\n[[rules]]\nhost = \"github.com\"\nmode = \"intercept\"\nports = [443]\npaths = [\"/dstoc/cladding.git/**\"]\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"github-git\"\nformat = \"basic_password\"\nusername = \"x-access-token\"\n";

    fn handler(config: &str, secrets: &[(&str, &str)]) -> PolicyHandler {
        let ControlRequest::Create { session, .. } =
            ControlRequest::from_toml(config).expect("injection policy should parse")
        else {
            panic!("test config should create a session");
        };
        let policy = Arc::new(SessionPolicy::compile(&session));
        let secrets = Arc::new(ResolvedSecrets::from_values(
            secrets
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
        ));
        PolicyHandler::with_metrics(
            RuntimeId::new("header-injection-test"),
            policy,
            secrets,
            Arc::new(Metrics::default()),
            CancellationToken::new(),
        )
    }

    fn intercepted_request(uri: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(uri)
            .header("host", uri_host(uri))
            .body(Body::empty())
            .expect("intercepted request should build")
    }

    fn uri_host(uri: &str) -> &str {
        uri.strip_prefix("https://")
            .expect("test URI should use HTTPS")
            .split('/')
            .next()
            .expect("test URI should include a host")
    }

    fn forwarded_request(
        handler: &PolicyHandler,
        request: Request<Body>,
        authority: &str,
    ) -> Request<Body> {
        let authority = authority.parse().expect("CONNECT authority should parse");
        match handler.handle_policy_request_with_context(request, Some(&authority)) {
            RequestOrResponse::Request(request) => request,
            RequestOrResponse::Response(response) => {
                panic!(
                    "authorized fixture request was denied: {}",
                    response.status()
                )
            }
        }
    }

    fn assert_denied(handler: &PolicyHandler, request: Request<Body>, authority: Option<&str>) {
        let authority = authority.map(|value| value.parse().expect("authority should parse"));
        let response = match handler.handle_policy_request_with_context(request, authority.as_ref())
        {
            RequestOrResponse::Response(response) => response,
            RequestOrResponse::Request(_) => panic!("request must be denied"),
        };
        assert!(matches!(
            response.status(),
            StatusCode::BAD_REQUEST | StatusCode::FORBIDDEN
        ));
    }

    #[test]
    fn github_rest_injects_bearer_after_authorization_and_replaces_client_values() {
        let handler = handler(REST_CONFIG, &[("github-api", "rest-fixture-token")]);
        let mut request =
            intercepted_request("https://api.github.com/repos/dstoc/cladding/issues?state=open");
        request.headers_mut().insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer client-value"),
        );
        request.headers_mut().append(
            AUTHORIZATION,
            HeaderValue::from_static("Basic second-client-value"),
        );

        let request = forwarded_request(&handler, request, "api.github.com:443");
        let values = request
            .headers()
            .get_all(AUTHORIZATION)
            .iter()
            .collect::<Vec<_>>();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], "Bearer rest-fixture-token");
        assert_eq!(request.uri().query(), Some("state=open"));
    }

    #[test]
    fn github_git_smart_http_discovery_fetch_and_push_use_basic_credentials() {
        let handler = handler(GIT_CONFIG, &[("github-git", "git-fixture-token")]);
        let flows = [
            ("GET", "info/refs?service=git-upload-pack"),
            ("POST", "git-upload-pack"),
            ("GET", "info/refs?service=git-receive-pack"),
            ("POST", "git-receive-pack"),
        ];

        for (method, operation) in flows {
            let uri = format!("https://github.com/dstoc/cladding.git/{operation}");
            let mut request = intercepted_request(&uri);
            *request.method_mut() = method.parse().expect("Git method should parse");
            request.headers_mut().insert(
                AUTHORIZATION,
                HeaderValue::from_static("Bearer client-value"),
            );
            let request = forwarded_request(&handler, request, "github.com:443");
            assert_eq!(
                request.headers()[AUTHORIZATION],
                "Basic eC1hY2Nlc3MtdG9rZW46Z2l0LWZpeHR1cmUtdG9rZW4="
            );
        }
    }

    #[test]
    fn github_api_and_git_rules_use_their_own_secret_and_format() {
        let handler = handler(
            COMBINED_CONFIG,
            &[
                ("github-api", "rest-fixture-token"),
                ("github-git", "git-fixture-token"),
            ],
        );
        let rest = intercepted_request("https://api.github.com/repos/dstoc/cladding/issues");
        let rest = forwarded_request(&handler, rest, "api.github.com:443");
        assert_eq!(rest.headers()[AUTHORIZATION], "Bearer rest-fixture-token");

        let git = intercepted_request(
            "https://github.com/dstoc/cladding.git/info/refs?service=git-upload-pack",
        );
        let git = forwarded_request(&handler, git, "github.com:443");
        assert_eq!(
            git.headers()[AUTHORIZATION],
            "Basic eC1hY2Nlc3MtdG9rZW46Z2l0LWZpeHR1cmUtdG9rZW4="
        );
    }

    #[test]
    fn raw_format_injects_the_secret_without_a_scheme_prefix() {
        let config = "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"api.github.com\"\nmode = \"intercept\"\nports = [443]\npaths = [\"/repos/dstoc/cladding/**\"]\n\n[[rules.inject]]\nheader = \"X-Api-Key\"\nsecret = \"raw-token\"\nformat = \"raw\"\n";
        let handler = handler(config, &[("raw-token", "fixture-value")]);
        let request = intercepted_request("https://api.github.com/repos/dstoc/cladding/issues");
        let request = forwarded_request(&handler, request, "api.github.com:443");
        assert_eq!(request.headers()["x-api-key"], "fixture-value");
    }

    #[test]
    fn credentials_are_denied_for_wrong_host_path_port_scheme_authority_and_upgrade() {
        let handler = handler(REST_CONFIG, &[("github-api", "rest-fixture-token")]);

        assert_denied(
            &handler,
            intercepted_request("https://evil.example/repos/dstoc/cladding"),
            Some("evil.example:443"),
        );
        assert_denied(
            &handler,
            intercepted_request("https://api.github.com/repos/other/repository"),
            Some("api.github.com:443"),
        );
        assert_denied(
            &handler,
            intercepted_request("https://api.github.com:444/repos/dstoc/cladding"),
            Some("api.github.com:444"),
        );

        let plaintext = Request::builder()
            .method("GET")
            .uri("http://api.github.com/repos/dstoc/cladding")
            .body(Body::empty())
            .expect("plaintext request should build");
        assert_denied(&handler, plaintext, Some("api.github.com:443"));

        assert_denied(
            &handler,
            intercepted_request("https://api.github.com/repos/dstoc/cladding"),
            Some("redirected.example:443"),
        );

        // A redirect is followed by the client as a new CONNECT and request.
        // Even another GitHub hostname must match a separate rule before it
        // can receive this session's credential.
        assert_denied(
            &handler,
            intercepted_request("https://github.com/repos/dstoc/cladding"),
            Some("github.com:443"),
        );

        let mut conflicting_host =
            intercepted_request("https://api.github.com/repos/dstoc/cladding");
        conflicting_host
            .headers_mut()
            .insert("host", HeaderValue::from_static("evil.example"));
        assert_denied(&handler, conflicting_host, Some("api.github.com:443"));

        let mut upgraded = intercepted_request("https://api.github.com/repos/dstoc/cladding");
        upgraded.headers_mut().insert(
            "connection",
            HeaderValue::from_static("keep-alive, Upgrade"),
        );
        upgraded
            .headers_mut()
            .insert("upgrade", HeaderValue::from_static("websocket"));
        assert_denied(&handler, upgraded, Some("api.github.com:443"));

        let mut nominated_as_hop_by_hop =
            intercepted_request("https://api.github.com/repos/dstoc/cladding");
        nominated_as_hop_by_hop
            .headers_mut()
            .insert("connection", HeaderValue::from_static("Authorization"));
        assert_denied(
            &handler,
            nominated_as_hop_by_hop,
            Some("api.github.com:443"),
        );

        let mut direct = intercepted_request("https://api.github.com/repos/dstoc/cladding");
        direct.headers_mut().insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer client-value"),
        );
        assert_denied(&handler, direct, None);
    }

    #[test]
    fn missing_resolved_secret_fails_closed_before_forwarding() {
        let handler = handler(REST_CONFIG, &[]);
        let request = intercepted_request("https://api.github.com/repos/dstoc/cladding/issues");
        assert_denied(&handler, request, Some("api.github.com:443"));
    }

    #[test]
    fn outer_connect_is_authorized_without_receiving_credentials() {
        let handler = handler(REST_CONFIG, &[("github-api", "rest-fixture-token")]);
        let connect = Request::builder()
            .method("CONNECT")
            .uri("api.github.com:443")
            .header("proxy-authorization", "client-proxy-value")
            .body(Body::empty())
            .expect("CONNECT request should build");
        let original = connect.headers()["proxy-authorization"].clone();
        let forwarded = match handler.handle_policy_request(connect) {
            RequestOrResponse::Request(request) => request,
            RequestOrResponse::Response(response) => {
                panic!("authorized CONNECT was denied: {}", response.status())
            }
        };
        assert_eq!(forwarded.headers()["proxy-authorization"], original);
        assert!(!forwarded.headers().contains_key(AUTHORIZATION));
    }
}

impl WebSocketHandler for PolicyHandler {
    async fn handle_message(
        &mut self,
        _ctx: &WebSocketContext,
        message: Message,
    ) -> Option<Message> {
        Some(message)
    }
}
