//! Fail-closed ClientHello inspection and verified upstream TLS interception.

use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use rama::io::peek::PeekTimeoutPolicy;
use rama::{
    Service,
    extensions::{Extensions, ExtensionsRef},
    http::proxy::mitm::HttpMitmRelay,
    io::BridgeIo,
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
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};

use crate::{
    ca::ManagedCa,
    policy::{Destination, SessionPolicy},
    secrets::ResolvedSecrets,
    telemetry::Metrics,
};

#[cfg(feature = "benchmark-tcp-nodelay")]
use super::super::benchmark_tcp_nodelay_enabled;
use super::{ProxyRuntimeError, http};

#[allow(clippy::too_many_arguments)]
pub(super) async fn intercept_client<S>(
    mut client: S,
    policy: Arc<SessionPolicy>,
    secrets: Arc<ResolvedSecrets>,
    ca: Arc<ManagedCa>,
    authority: String,
    destination: Destination,
    metrics: Arc<Metrics>,
    io_timeout: Duration,
) -> Result<(), ProxyRuntimeError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
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
    if !policy.permits_tls_interception_authority(&authority, sni.as_deref()) {
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
    let egress_config = match super::super::integration_test_upstream_root() {
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
    let request_policy = http::RamaPolicyLayer {
        policy: Arc::clone(&policy),
        connect_authority: authority.clone(),
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
