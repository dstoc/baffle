use std::{fs, os::unix::fs::MetadataExt, sync::Arc};

use tokio::sync::mpsc;

use crate::{
    ca::ManagedCa,
    config::{CaConfig, DaemonSettings, SessionCreateMode},
    proxy_runtime::TestUpstreamTrust,
    telemetry::Metrics,
    test_ca::write_test_ca,
};

use crate::control::session::SessionManager;

pub(super) fn session_manager(directory: &std::path::Path, max_sessions: usize) -> SessionManager {
    let (certificate_path, private_key_path) = write_test_ca(directory);
    let ca = Arc::new(
        ManagedCa::load(&CaConfig {
            certificate: certificate_path,
            private_key: private_key_path,
        })
        .expect("test CA should load"),
    );
    let (runtime_events, _receiver) = mpsc::unbounded_channel();
    let trusted_operator_uid = fs::metadata(directory)
        .expect("test directory should have metadata")
        .uid();
    let settings = DaemonSettings {
        control_socket: directory.join("control.sock"),
        socket_dir: directory.to_path_buf(),
        trusted_operator_uid,
        max_sessions,
        max_connections_per_session: 128,
        shutdown_grace_seconds: 1,
        control_read_timeout_ms: 1_000,
        max_provisioning_requests: 1,
        io_timeout_ms: 1_000,
        session_config_dir: None,
        create_mode: SessionCreateMode::Inline,
    };
    SessionManager::new(
        &settings,
        ca,
        TestUpstreamTrust::default(),
        runtime_events,
        Arc::new(Metrics::default()),
    )
}
