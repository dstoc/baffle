use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    sync::Arc,
};

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use tokio::sync::mpsc;

use crate::{
    ca::ManagedCa,
    config::{CaConfig, DaemonSettings, SessionCreateMode},
    telemetry::Metrics,
};

use super::session::SessionManager;

pub(super) fn session_manager(directory: &std::path::Path, max_sessions: usize) -> SessionManager {
    let key_pair = KeyPair::generate().expect("CA key should be generated");
    let mut parameters = CertificateParams::default();
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let certificate = parameters
        .self_signed(&key_pair)
        .expect("CA certificate should be generated");
    let certificate_path = directory.join("control-test-ca.pem");
    let private_key_path = directory.join("control-test-ca-key.pem");
    fs::write(&certificate_path, certificate.pem()).expect("CA certificate should be saved");
    fs::write(&private_key_path, key_pair.serialize_pem()).expect("CA key should be saved");
    fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600))
        .expect("CA key permissions should be restricted");
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
        connection_timeout_ms: 1_000,
        io_timeout_ms: 1_000,
        session_config_dir: None,
        create_mode: SessionCreateMode::Inline,
    };
    SessionManager::new(&settings, ca, runtime_events, Arc::new(Metrics::default()))
}
