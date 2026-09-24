use std::{fs, net::SocketAddr, sync::Arc, time::Duration};

use baffle_proxy::{
    ca::ManagedCa,
    config::{ControlRequest, SessionConfig},
    proxy_runtime::{ProxyRuntime, ProxyRuntimeEvent, RuntimeId},
};
use hudsucker::rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream, UnixStream},
    sync::mpsc,
    time::timeout,
};

fn session_config() -> SessionConfig {
    let request = ControlRequest::from_toml(
        "version = 1\noperation = \"create\"\n\n[session]\npersistent = true\n\n[[rules]]\nhost = \"allowed.example\"\nmode = \"tunnel\"\nports = [443]\n",
    )
    .expect("test session should be valid");
    let ControlRequest::Create { session, .. } = request else {
        panic!("test request should create a session");
    };
    session
}

fn write_test_ca(directory: &std::path::Path) -> Arc<ManagedCa> {
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
    Arc::new(
        ManagedCa::load(&baffle_proxy::config::CaConfig {
            certificate: certificate_path,
            private_key: private_key_path,
        })
        .expect("test CA should load"),
    )
}

async fn assert_denied(address: SocketAddr, method: &str, target: &str) {
    let mut stream = TcpStream::connect(address)
        .await
        .expect("proxy listener should accept connections");
    let request =
        format!("{method} {target} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("proxy request should be sent");
    let mut reader = BufReader::new(stream);
    let mut status = String::new();
    timeout(Duration::from_secs(2), reader.read_line(&mut status))
        .await
        .expect("proxy should return a response")
        .expect("proxy response should be readable");
    assert!(
        status.starts_with("HTTP/1.1 403") || status.starts_with("HTTP/1.0 403"),
        "policy handler should reject {method}: {status:?}"
    );
}

async fn assert_exit(
    events: &mut mpsc::UnboundedReceiver<ProxyRuntimeEvent>,
    expected_id: &RuntimeId,
) {
    let event = timeout(Duration::from_secs(2), events.recv())
        .await
        .expect("runtime should report its exit")
        .expect("runtime event channel should remain open");
    assert_eq!(&event.runtime_id, expected_id);
    assert!(event.result.is_ok(), "graceful stop should succeed");
}

#[tokio::test]
async fn multiple_proxy_instances_deny_outbound_requests_and_stop_independently() {
    let directory = tempfile::tempdir().expect("test directory should be created");
    let ca = write_test_ca(directory.path());
    let (event_sender, mut events) = mpsc::unbounded_channel();
    let first_id = RuntimeId::new("runtime-first");
    let second_id = RuntimeId::new("runtime-second");

    let first = ProxyRuntime::start(
        first_id.clone(),
        session_config(),
        Arc::clone(&ca),
        directory.path().join("first.sock"),
        8,
        event_sender.clone(),
    )
    .await
    .expect("first runtime should start");
    let first_address = first.local_addr();
    let second = ProxyRuntime::start(
        second_id.clone(),
        session_config(),
        ca,
        directory.path().join("second.sock"),
        8,
        event_sender,
    )
    .await
    .expect("second runtime should start");
    let second_address = second.local_addr();

    assert!(first_address.ip().is_loopback());
    assert!(second_address.ip().is_loopback());
    assert_ne!(first_address, second_address);
    assert_ne!(first.socket_path(), second.socket_path());
    assert_eq!(first.runtime_id(), &first_id);
    assert_eq!(second.runtime_id(), &second_id);

    assert_denied(first_address, "GET", "http://example.com/").await;
    assert_denied(first_address, "CONNECT", "example.com:443").await;
    assert_denied(second_address, "GET", "http://example.com/").await;
    assert_unix_proxy_denied(first.socket_path()).await;

    first.shutdown(Duration::from_secs(2)).await;
    assert_exit(&mut events, &first_id).await;
    assert!(
        TcpStream::connect(first_address).await.is_err(),
        "stopped runtime should close only its own listener"
    );
    assert!(!directory.path().join("first.sock").exists());
    assert!(directory.path().join("second.sock").exists());
    assert_denied(second_address, "GET", "http://example.com/").await;
    assert_unix_proxy_denied(second.socket_path()).await;

    second.shutdown(Duration::from_secs(2)).await;
    assert_exit(&mut events, &second_id).await;
    assert!(!directory.path().join("second.sock").exists());
}

async fn assert_unix_proxy_denied(path: &std::path::Path) {
    let mut stream = UnixStream::connect(path)
        .await
        .expect("proxy Unix socket should accept an ordinary HTTP proxy request");
    stream
        .write_all(
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("HTTP proxy request should be sent through the Unix socket");
    let mut reader = BufReader::new(stream);
    let mut status = String::new();
    timeout(Duration::from_secs(2), reader.read_line(&mut status))
        .await
        .expect("Hudsucker should respond through the Unix bridge")
        .expect("proxy response should be readable");
    assert!(
        status.starts_with("HTTP/1.1 403") || status.starts_with("HTTP/1.0 403"),
        "the assigned Hudsucker instance should respond: {status:?}"
    );
}

#[tokio::test]
async fn replacing_a_session_socket_does_not_delete_the_replacement_on_shutdown() {
    let directory = tempfile::tempdir().expect("test directory should be created");
    let ca = write_test_ca(directory.path());
    let (event_sender, mut events) = mpsc::unbounded_channel();
    let id = RuntimeId::new("runtime-replaced-socket");
    let path = directory.path().join("replaced.sock");
    let runtime = ProxyRuntime::start(
        id.clone(),
        session_config(),
        ca,
        path.clone(),
        1,
        event_sender,
    )
    .await
    .expect("runtime should start");

    fs::remove_file(&path).expect("test should remove the original socket path");
    fs::write(&path, b"unrelated replacement")
        .expect("test should create an unrelated replacement file");

    runtime.shutdown(Duration::from_secs(2)).await;
    assert_exit(&mut events, &id).await;
    assert_eq!(
        fs::read(&path).expect("replacement should remain"),
        b"unrelated replacement"
    );
}

#[tokio::test]
async fn unix_socket_path_that_is_a_symlink_is_left_untouched() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("test directory should be created");
    let ca = write_test_ca(directory.path());
    let target = directory.path().join("target");
    let path = directory.path().join("proxy.sock");
    fs::write(&target, b"target contents").expect("test target should be created");
    symlink(&target, &path).expect("test symlink should be created");
    let (event_sender, _events) = mpsc::unbounded_channel();

    let error = match ProxyRuntime::start(
        RuntimeId::new("runtime-symlink"),
        session_config(),
        ca,
        path.clone(),
        1,
        event_sender,
    )
    .await
    {
        Err(error) => error,
        Ok(runtime) => {
            runtime.shutdown(Duration::from_secs(2)).await;
            panic!("runtime must not bind through an existing symlink");
        }
    };

    assert!(error.to_string().contains("already exists"));
    assert!(
        fs::symlink_metadata(&path)
            .expect("symlink should remain")
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read(&target).expect("target should remain"),
        b"target contents"
    );
}

#[tokio::test]
async fn unauthorized_ip_literal_is_rejected_before_an_upstream_connection() {
    let directory = tempfile::tempdir().expect("test directory should be created");
    let ca = write_test_ca(directory.path());
    let (event_sender, mut events) = mpsc::unbounded_channel();
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream probe should bind");
    let upstream_address = upstream
        .local_addr()
        .expect("probe address should be available");
    let runtime_id = RuntimeId::new("runtime-ip-deny");
    let runtime = ProxyRuntime::start(runtime_id.clone(), session_config(), ca, event_sender)
        .await
        .expect("proxy runtime should start");

    let mut stream = TcpStream::connect(runtime.local_addr())
        .await
        .expect("proxy listener should accept connections");
    let request = format!(
        "GET http://{upstream_address}/ HTTP/1.1\r\nHost: {upstream_address}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("proxy request should be sent");
    let mut reader = BufReader::new(stream);
    let mut status = String::new();
    timeout(Duration::from_secs(2), reader.read_line(&mut status))
        .await
        .expect("proxy should return a response")
        .expect("proxy response should be readable");
    assert!(
        status.starts_with("HTTP/1.1 400") || status.starts_with("HTTP/1.0 400"),
        "IP literal request should be rejected: {status:?}"
    );
    assert!(
        timeout(Duration::from_millis(100), upstream.accept())
            .await
            .is_err(),
        "rejected destination must not receive an upstream connection"
    );

    runtime.shutdown(Duration::from_secs(2)).await;
    assert_exit(&mut events, &runtime_id).await;
}
