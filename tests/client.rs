#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
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
    session_config_dir: Option<PathBuf>,
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

#[tokio::test]
async fn typed_client_creates_from_a_daemon_managed_file_and_holds_the_lease() {
    let daemon = start_file_only_daemon(4);
    let config_dir = daemon
        .session_config_dir
        .as_ref()
        .expect("file-only daemon should have a config directory");
    let nested_dir = config_dir.join("cladding");
    fs::create_dir(&nested_dir).expect("nested config directory should be created");
    fs::set_permissions(&nested_dir, fs::Permissions::from_mode(0o700))
        .expect("nested config directory should be private");
    let config_path = nested_dir.join("github.toml");
    fs::write(
        &config_path,
        "version = 1\noperation = \"create\"\n\n[session]\npersistent = false\n\n[[rules]]\nhost = \"github.com\"\nmode = \"tunnel\"\n",
    )
    .expect("session config should be written");
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))
        .expect("session config should be private");

    let client = Client::new(&daemon.control_socket);
    let session = client
        .create_from_file("cladding/github.toml")
        .await
        .expect("typed file create should succeed");
    assert!(!session.is_persistent());
    let socket_path = session.socket_path().to_path_buf();
    assert!(socket_path.exists());
    assert_eq!(client.list().await.expect("list should succeed").len(), 1);
    request_through_proxy(&socket_path).await;

    let missing = client
        .create_from_file("missing.toml")
        .await
        .expect_err("missing config should fail");
    assert!(matches!(
        missing,
        baffle_client::ClientError::SessionConfigNotFound(_)
    ));
    let disabled_inline = client
        .create(SessionConfig::new().with_rule(HostRule::tunnel("example.com")))
        .await
        .expect_err("inline create must be rejected in file-only mode");
    assert!(matches!(
        disabled_inline,
        baffle_client::ClientError::OperationNotAllowed(_)
    ));
    let malformed_name = client
        .create_from_file("../outside.toml")
        .await
        .expect_err("unsafe names should fail in the client");
    assert!(matches!(
        malformed_name,
        baffle_client::ClientError::InvalidPolicy(_)
    ));

    session.close();
    wait_for_count(&client, 0).await;
    assert!(!socket_path.exists());
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
    start_daemon_with_mode(max_sessions, false)
}

fn start_file_only_daemon(max_sessions: usize) -> DaemonProcess {
    start_daemon_with_mode(max_sessions, true)
}

fn start_daemon_with_mode(max_sessions: usize, file_only: bool) -> DaemonProcess {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let control_socket = directory.path().join("run/control.sock");
    let socket_dir = directory.path().join("proxies");
    let config_path = directory.path().join("daemon.toml");
    let session_config_dir = file_only.then(|| directory.path().join("session-configs"));
    if let Some(session_config_dir) = &session_config_dir {
        fs::create_dir(session_config_dir).expect("session config directory should be created");
        fs::set_permissions(session_config_dir, fs::Permissions::from_mode(0o700))
            .expect("session config directory should be private");
    }
    let (certificate_path, private_key_path) = write_test_ca(directory.path());
    let trusted_uid = fs::metadata(directory.path())
        .expect("temporary directory should have metadata")
        .uid();
    let file_settings = session_config_dir
        .as_ref()
        .map(|path| {
            format!(
                "create_mode = \"file_only\"\nsession_config_dir = \"{}\"\n",
                path.display()
            )
        })
        .unwrap_or_default();
    let config = format!(
        "[daemon]\ncontrol_socket = \"{}\"\nsocket_dir = \"{}\"\ntrusted_operator_uid = {trusted_uid}\nmax_sessions = {max_sessions}\n{file_settings}\n[ca]\ncertificate = \"{}\"\nprivate_key = \"{}\"\n\n[secrets]\ndirectory = \"unused-secrets\"\n",
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
        session_config_dir,
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
