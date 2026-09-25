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
}
