//! Fail-closed Rama adapter scaffold.
//!
//! Rama's proxy and BoringSSL APIs are feature-selected independently, but
//! Baffle has not yet connected them to its authority-bound CONNECT/TLS policy.
//! Until that integration can verify upstream certificates and bind decrypted
//! authorities, session startup is rejected rather than falling back to a
//! tunnel.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use super::{ProxyRuntimeError, ProxyRuntimeEvent, RuntimeId};
use crate::{ca::ManagedCa, config::SessionConfig, secrets::ResolvedSecrets, telemetry::Metrics};

/// A Rama runtime placeholder which rejects startup until security checks are
/// implemented. It deliberately does not create a listener or opaque tunnel.
pub struct ProxyRuntime {
    runtime_id: RuntimeId,
    socket_path: PathBuf,
}

impl ProxyRuntime {
    pub async fn start(
        _runtime_id: RuntimeId,
        _session: SessionConfig,
        _ca: Arc<ManagedCa>,
        _socket_path: PathBuf,
        _max_connections: usize,
        _events: tokio::sync::mpsc::UnboundedSender<ProxyRuntimeEvent>,
    ) -> Result<Self, ProxyRuntimeError> {
        Err(ProxyRuntimeError::BackendUnavailable)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn start_with_metrics(
        _runtime_id: RuntimeId,
        _session: SessionConfig,
        _secrets: Arc<ResolvedSecrets>,
        _ca: Arc<ManagedCa>,
        _socket_path: PathBuf,
        _max_connections: usize,
        _connection_timeout: Duration,
        _io_timeout: Duration,
        _metrics: Arc<Metrics>,
        _events: tokio::sync::mpsc::UnboundedSender<ProxyRuntimeEvent>,
    ) -> Result<Self, ProxyRuntimeError> {
        Err(ProxyRuntimeError::BackendUnavailable)
    }

    pub fn runtime_id(&self) -> &RuntimeId {
        &self.runtime_id
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub async fn shutdown(self, _grace: Duration) {}
}

#[cfg(test)]
mod tests {
    use super::ProxyRuntimeError;
    use rama::{
        io::peek::PeekTimeoutPolicy,
        tls::{
            KeyLogIntent,
            boring::proxy::{TlsMitmEgressServerAuth, TlsMitmRelay},
            client::ServerVerifyMode,
            server::peek_client_hello_from_input_with_timeout_policy,
        },
    };
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn unavailable_backend_reports_a_stable_failure_class() {
        let error = ProxyRuntimeError::BackendUnavailable;
        assert_eq!(error.class(), "backend_unavailable");
        assert!(
            error
                .to_string()
                .contains("upstream TLS and authority checks")
        );
    }

    #[test]
    fn rama_boring_server_api_is_selected() {
        let _ = std::any::type_name::<rama::tls::boring::server::TlsAcceptorLayer>();
    }

    #[test]
    fn rama_exposes_verified_egress_and_disabled_key_logging_controls() {
        let auth = TlsMitmEgressServerAuth::new().with_server_verify(ServerVerifyMode::Auto);
        let relay = TlsMitmRelay::new(())
            .with_keylog_intent(KeyLogIntent::Disabled)
            .with_egress_server_auth(auth);

        assert!(matches!(relay.keylog_intent_ref(), KeyLogIntent::Disabled));
        assert!(relay.egress_server_auth_ref().is_some());
    }

    #[tokio::test]
    async fn rama_client_hello_peek_fails_closed_on_fragmented_input() {
        let (mut client, proxy) = tokio::io::duplex(64);
        let (fragment_written, fragment_ready) = tokio::sync::oneshot::channel();
        let write_fragment = tokio::spawn(async move {
            // A plausible TLS handshake record header and a partial ClientHello.
            client
                .write_all(&[0x16, 0x03, 0x03, 0x00, 0x20, 0x01, 0x00])
                .await
                .expect("partial ClientHello should be written");
            fragment_written
                .send(())
                .expect("the peek test should still be active");
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
        fragment_ready
            .await
            .expect("partial ClientHello should arrive before the peek starts");

        let result = peek_client_hello_from_input_with_timeout_policy(
            proxy,
            Some(Duration::from_millis(5)),
            PeekTimeoutPolicy::FailClosed,
        )
        .await;

        assert!(
            result.is_err(),
            "an incomplete ClientHello must be rejected"
        );
        write_fragment.await.expect("fragment writer should finish");
    }

    #[tokio::test]
    async fn rama_client_hello_peek_reports_non_tls_without_a_fallback_decision() {
        let (mut client, proxy) = tokio::io::duplex(64);
        client
            .write_all(b"not a TLS ClientHello")
            .await
            .expect("non-TLS prefix should be written");

        let (_, client_hello) = peek_client_hello_from_input_with_timeout_policy(
            proxy,
            Some(Duration::from_millis(50)),
            PeekTimeoutPolicy::FailClosed,
        )
        .await
        .expect("a definitive non-TLS prefix is not a peek timeout");

        assert!(
            client_hello.is_none(),
            "the caller must reject this result for interception-required traffic"
        );
    }
}
