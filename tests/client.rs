#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    time::{Duration, Instant},
};

use baffle_client::{
    Client, ClientError, CredentialMode, HeaderInjection, HostRule, ReloadStatus, SessionConfig,
    SessionState,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::{sleep, timeout},
};

#[allow(dead_code)]
mod common;
use common::DaemonProcess;

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
    assert_ca_certificate(explicit.ca_certificate_pem(), &daemon.ca_certificate);
    let explicit_seed = explicit
        .credential_seed_base64url()
        .expect("new daemon should return the session credential seed")
        .to_owned();
    assert_eq!(explicit_seed.len(), 43);
    assert!(
        explicit_seed
            .bytes()
            .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') })
    );
    assert!(
        !format!("{explicit:?}").contains(&explicit_seed),
        "Session debug output must not expose the credential seed"
    );
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
    let dropped_seed = dropped
        .credential_seed_base64url()
        .expect("new daemon should return the session credential seed")
        .to_owned();
    assert!(
        explicit_seed != dropped_seed,
        "each session must receive a fresh credential seed"
    );
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
    let persistent_seed = persistent
        .credential_seed_base64url()
        .expect("new daemon should return the session credential seed");
    assert!(
        persistent_seed != explicit_seed && persistent_seed != dropped_seed,
        "each session must receive a fresh credential seed"
    );
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
async fn disabled_client_credentials_need_no_secret_file() {
    let daemon = start_daemon(2);
    let client = Client::new(&daemon.control_socket);
    let mut rule = HostRule::intercept("example.com");
    rule.inject
        .push(HeaderInjection::bearer("Authorization", "not-provisioned"));
    let session = client
        .create(
            SessionConfig::new()
                .default_credential_mode(CredentialMode::Substitute)
                .credential_mode("not-provisioned", CredentialMode::Disabled)
                .with_rule(rule),
        )
        .await
        .expect("disabled credentials should not be loaded or entitled");

    assert!(session.credential_seed_base64url().is_some());
    session.close();
    wait_for_count(&client, 0).await;
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
        .expect_err("the configured session limit should apply to an empty policy too");
    assert!(matches!(
        error,
        baffle_client::ClientError::CapacityLimit(_)
    ));

    client
        .stop(persistent.id())
        .await
        .expect("test session should stop");
}

#[tokio::test]
async fn typed_reload_uses_a_short_control_connection_and_preserves_the_creator_lease() {
    let daemon = start_file_only_daemon(2);
    let config_dir = daemon
        .session_config_dir
        .as_ref()
        .expect("file-only daemon should have a session config directory");
    let config_path = config_dir.join("managed.toml");
    fs::write(
        &config_path,
        "version = 2\npersistent = false\n\n[rules.\"example.com\"]\n",
    )
    .expect("administrator policy should be written");
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))
        .expect("administrator policy should be private");

    let client = Client::new(&daemon.control_socket);
    let session = client
        .create_from_file("managed.toml")
        .await
        .expect("file-backed session should be created");
    let session_id = session.id().to_owned();
    let socket_path = session.socket_path().to_path_buf();

    let unchanged = client
        .reload(&session_id)
        .await
        .expect("reload should return a per-session result");
    assert_eq!(unchanged.status, ReloadStatus::Unchanged);
    assert_eq!(unchanged.socket_path, socket_path);
    assert_eq!(
        client.list().await.expect("session should list")[0].generation,
        1
    );

    fs::write(
        &config_path,
        "# policy update\nversion = 2\npersistent = true\n\n[rules.\"api.example.com\"]\n",
    )
    .expect("updated policy should be written");
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))
        .expect("updated policy should remain private");
    let reloaded = client
        .reload(&session_id)
        .await
        .expect("changed policy should reload");
    assert_eq!(reloaded.status, ReloadStatus::Reloaded);
    assert_eq!(reloaded.socket_path, socket_path);
    let listed = client.list().await.expect("session should remain listed");
    assert_eq!(listed.len(), 1, "reload must not replace the creator lease");
    assert_eq!(listed[0].id, session_id);
    assert_eq!(listed[0].generation, 2);
    assert!(
        !listed[0].persistent,
        "reload must keep creation-time lifetime"
    );

    let all = client
        .reload_all()
        .await
        .expect("reload_all should return independent results");
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].status, ReloadStatus::Unchanged);
    assert_eq!(
        client
            .list()
            .await
            .expect("creator lease should remain")
            .len(),
        1
    );
    drop(session);
    wait_for_count(&client, 0).await;
    assert!(!socket_path.exists());
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
    fs::write(&config_path, "version = 2\n\n[rules.\"github.com\"]\n")
        .expect("session config should be written");
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))
        .expect("session config should be private");

    let client = Client::new(&daemon.control_socket);
    let session = client
        .create_from_file("cladding/github.toml")
        .await
        .expect("typed file create should succeed");
    assert!(!session.is_persistent());
    assert_ca_certificate(session.ca_certificate_pem(), &daemon.ca_certificate);
    assert!(session.credential_seed_base64url().is_some());
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

#[tokio::test]
async fn typed_file_create_can_require_ephemeral_and_omission_keeps_existing_behavior() {
    let daemon = start_file_only_daemon(4);
    let config_dir = daemon
        .session_config_dir
        .as_ref()
        .expect("file-only daemon should have a config directory");
    let policy_path = config_dir.join("managed.toml");
    fs::write(
        &policy_path,
        "version = 2\npersistent = true\n\n[rules.\"example.com\"]\n",
    )
    .expect("persistent session config should be written");
    fs::set_permissions(&policy_path, fs::Permissions::from_mode(0o600))
        .expect("session config should be private");

    let client = Client::new(&daemon.control_socket);
    let rejected = client
        .create_ephemeral_from_file("managed.toml")
        .await
        .expect_err("persistent policy must be rejected");
    assert!(matches!(
        rejected,
        ClientError::InvalidPolicy(ref message)
            if message == "session configuration must be ephemeral"
    ));
    assert!(
        client
            .list()
            .await
            .expect("sessions should list")
            .is_empty()
    );
    assert_eq!(
        fs::read_dir(&daemon.socket_dir)
            .expect("proxy socket directory should remain available")
            .count(),
        0,
        "persistent policy rejection must leave no session socket"
    );

    fs::write(
        &policy_path,
        "version = 2\npersistent = false\n\n[rules.\"example.com\"]\n",
    )
    .expect("ephemeral session config should be written");
    fs::set_permissions(&policy_path, fs::Permissions::from_mode(0o600))
        .expect("session config should remain private");
    let session = client
        .create_ephemeral_from_file("managed.toml")
        .await
        .expect("ephemeral policy should be created");
    assert!(!session.is_persistent());
    assert_ca_certificate(session.ca_certificate_pem(), &daemon.ca_certificate);
    let socket_path = session.socket_path().to_path_buf();
    assert!(socket_path.exists());
    session.close();
    wait_for_count(&client, 0).await;
    assert!(
        !socket_path.exists(),
        "closing the lease should remove its socket"
    );

    fs::write(
        &policy_path,
        "version = 2\npersistent = true\n\n[rules.\"example.com\"]\n",
    )
    .expect("persistent session config should be restored");
    fs::set_permissions(&policy_path, fs::Permissions::from_mode(0o600))
        .expect("session config should remain private");
    let persistent = client
        .create_from_file("managed.toml")
        .await
        .expect("omitting the constraint should preserve persistent creation");
    assert!(persistent.is_persistent());
    let persistent_id = persistent.id().to_owned();
    let persistent_path = persistent.socket_path().to_path_buf();
    drop(persistent);
    assert!(persistent_path.exists());
    client
        .stop(&persistent_id)
        .await
        .expect("persistent session should be explicitly stopped");
    assert!(!persistent_path.exists());
}

#[tokio::test]
async fn ephemeral_file_create_rejects_persistent_responses_from_older_daemons() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let control_socket = directory.path().join("control.sock");
    let listener = UnixListener::bind(&control_socket).expect("fake daemon should bind");
    let fake_daemon = tokio::spawn(async move {
        let (mut create, _) = listener
            .accept()
            .await
            .expect("client should request file creation");
        let request = read_request_frame(&mut create).await;
        assert!(request.contains("operation = \"create_from_file\""));
        assert!(request.contains("require_ephemeral = true"));
        write_response_frame(
            &mut create,
            serde_json::json!({
                "version": 2,
                "ok": true,
                "result": {
                    "id": "legacy-persistent",
                    "socket": "/tmp/legacy-persistent.sock",
                    "persistent": true
                }
            }),
        )
        .await;
        drop(create);

        let (mut stop, _) = listener
            .accept()
            .await
            .expect("client should clean up the unexpected persistent session");
        let request = read_request_frame(&mut stop).await;
        assert!(request.contains("operation = \"stop\""));
        assert!(request.contains("session_id = \"legacy-persistent\""));
        write_response_frame(
            &mut stop,
            serde_json::json!({
                "version": 2,
                "ok": true,
                "result": { "stopped": true }
            }),
        )
        .await;
    });

    let client = Client::new(&control_socket);
    let error = client
        .create_ephemeral_from_file("managed.toml")
        .await
        .expect_err("a persistent response must not become a Session");
    assert!(matches!(
        error,
        ClientError::Protocol(ref message)
            if message.contains("persistent session despite require_ephemeral")
                && message.contains("session was stopped")
    ));
    fake_daemon
        .await
        .expect("fake daemon should verify the request and cleanup");
}

async fn read_request_frame(stream: &mut UnixStream) -> String {
    let mut header = [0; 4];
    stream
        .read_exact(&mut header)
        .await
        .expect("request header should be read");
    let mut body = vec![0; u32::from_be_bytes(header) as usize];
    stream
        .read_exact(&mut body)
        .await
        .expect("request body should be read");
    String::from_utf8(body).expect("request should be UTF-8")
}

async fn write_response_frame(stream: &mut UnixStream, response: serde_json::Value) {
    let body = serde_json::to_vec(&response).expect("response should serialize");
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .await
        .expect("response length should be written");
    stream
        .write_all(&body)
        .await
        .expect("response body should be written");
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

fn assert_ca_certificate(actual: Option<&str>, configured_path: &Path) {
    let configured = fs::read_to_string(configured_path)
        .expect("configured CA certificate should be valid UTF-8 PEM");
    assert_eq!(actual, Some(configured.as_str()));
    let (_, pem) = x509_parser::pem::parse_x509_pem(
        actual
            .expect("new daemon should return its public CA certificate")
            .as_bytes(),
    )
    .expect("returned CA should be valid PEM");
    x509_parser::parse_x509_certificate(&pem.contents)
        .expect("returned CA should contain a valid X.509 certificate");
}

fn start_daemon(max_sessions: usize) -> DaemonProcess {
    DaemonProcess::start(max_sessions, &[])
}

fn start_file_only_daemon(max_sessions: usize) -> DaemonProcess {
    DaemonProcess::start_file_only_with_upstream_ca(max_sessions, &[], None)
}
