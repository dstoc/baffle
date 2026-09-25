#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use baffle_client::{Client, HostRule, SessionConfig, SessionState};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::{sleep, timeout},
};

struct DaemonProcess {
    child: Child,
    _directory: TempDir,
    control_socket: PathBuf,
}

impl Drop for DaemonProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test]
async fn client_manages_ephemeral_leases_and_persistent_sessions() {
    let daemon = start_daemon(4);
    let client = Client::new(&daemon.control_socket);
    let policy = || SessionConfig::new().with_rule(HostRule::tunnel("example.com"));

    let explicit = client
        .create(policy())
        .await
        .expect("ephemeral session should be created");
    assert!(!explicit.is_persistent());
    let explicit_path = explicit.socket_path().to_path_buf();
    assert!(explicit_path.exists());
    let sessions = client.list().await.expect("sessions should be listed");
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].state, SessionState::Running);
    assert_eq!(sessions[0].socket_path, explicit_path);

    request_through_proxy(&explicit_path).await;
    explicit.close();
    wait_for_count(&client, 0).await;
    assert!(!explicit_path.exists(), "close should release the lease");

    let dropped = client
        .create(policy())
        .await
        .expect("second ephemeral session should be created");
    let dropped_path = dropped.socket_path().to_path_buf();
    drop(dropped);
    wait_for_count(&client, 0).await;
    assert!(!dropped_path.exists(), "drop should release the lease");

    let persistent = client
        .create(
            SessionConfig::new()
                .persistent(true)
                .with_rule(HostRule::tunnel("example.com")),
        )
        .await
        .expect("persistent session should be created");
    assert!(persistent.is_persistent());
    let persistent_id = persistent.id().to_owned();
    let persistent_path = persistent.socket_path().to_path_buf();
    drop(persistent);
    assert!(
        persistent_path.exists(),
        "drop must not stop a persistent session"
    );
    assert_eq!(client.list().await.expect("session should remain").len(), 1);

    client
        .stop(&persistent_id)
        .await
        .expect("persistent session should stop");
    wait_for_count(&client, 0).await;
    assert!(
        !persistent_path.exists(),
        "stop should remove the proxy socket"
    );
}

#[tokio::test]
async fn client_returns_typed_policy_and_capacity_errors() {
    let daemon = start_daemon(1);
    let client = Client::new(&daemon.control_socket);
    let persistent = client
        .create(
            SessionConfig::new()
                .persistent(true)
                .with_rule(HostRule::tunnel("one.example")),
        )
        .await
        .expect("first session should be created");

    let error = client
        .create(SessionConfig::new().with_rule(HostRule::tunnel("two.example")))
        .await
        .expect_err("session capacity should be enforced");
    assert!(matches!(
        error,
        baffle_client::ClientError::CapacityLimit(_)
    ));

    let error = client
        .create(SessionConfig::new())
        .await
        .expect_err("empty policy should be rejected");
    assert!(matches!(
        error,
        baffle_client::ClientError::InvalidPolicy(_)
    ));

    client
        .stop(persistent.id())
        .await
        .expect("test session should stop");
}

async fn request_through_proxy(socket_path: &std::path::Path) {
    let mut socket = UnixStream::connect(socket_path)
        .await
        .expect("proxy data socket should accept a request");
    socket
        .write_all(
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("proxy request should be written");
    let mut response = Vec::new();
    timeout(Duration::from_secs(3), socket.read_to_end(&mut response))
        .await
        .expect("proxy response should arrive")
        .expect("proxy response should be readable");
    assert!(
        response.starts_with(b"HTTP/1.1 400") || response.starts_with(b"HTTP/1.1 403"),
        "the daemon should deny plaintext forward HTTP: {}",
        String::from_utf8_lossy(&response)
    );
}

async fn wait_for_count(client: &Client, expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if client.list().await.expect("list should succeed").len() == expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "session count should reach {expected}"
        );
        sleep(Duration::from_millis(10)).await;
    }
}

fn start_daemon(max_sessions: usize) -> DaemonProcess {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let control_socket = directory.path().join("run/control.sock");
    let socket_dir = directory.path().join("proxies");
    let config_path = directory.path().join("daemon.toml");
    let (certificate_path, private_key_path) = write_test_ca(directory.path());
    let trusted_uid = fs::metadata(directory.path())
        .expect("temporary directory should have metadata")
        .uid();
    let config = format!(
        "[daemon]\ncontrol_socket = \"{}\"\nsocket_dir = \"{}\"\ntrusted_operator_uid = {trusted_uid}\nmax_sessions = {max_sessions}\n\n[ca]\ncertificate = \"{}\"\nprivate_key = \"{}\"\n\n[secrets]\ndirectory = \"unused-secrets\"\n",
        control_socket.display(),
        socket_dir.display(),
        certificate_path.display(),
        private_key_path.display(),
    );
    fs::write(&config_path, config).expect("daemon config should be written");
    let child = Command::new(env!("CARGO_BIN_EXE_baffle"))
        .arg("daemon")
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("daemon should start");
    let mut daemon = DaemonProcess {
        child,
        _directory: directory,
        control_socket,
    };

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if daemon.control_socket.exists() {
            return daemon;
        }
        if let Some(status) = daemon
            .child
            .try_wait()
            .expect("daemon status should be readable")
        {
            panic!("daemon exited before binding control socket: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "daemon should bind control socket"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn write_test_ca(directory: &std::path::Path) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let key_pair = KeyPair::generate().expect("CA key should be generated");
    let mut parameters = CertificateParams::default();
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let certificate = parameters
        .self_signed(&key_pair)
        .expect("CA certificate should be generated");
    let certificate_path = directory.join("ca.pem");
    let private_key_path = directory.join("ca-key.pem");
    fs::write(&certificate_path, certificate.pem()).expect("CA certificate should be saved");
    fs::write(&private_key_path, key_pair.serialize_pem()).expect("CA key should be saved");
    fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600))
        .expect("CA key permissions should be restricted");
    (certificate_path, private_key_path)
}
