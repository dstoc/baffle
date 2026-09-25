use std::{fs, net::SocketAddr, sync::Arc, time::Duration};

use baffle_proxy::{
    ca::ManagedCa,
    config::{ControlRequest, SessionConfig},
    proxy_runtime::{ProxyRuntime, ProxyRuntimeEvent, RuntimeId},
};
use hudsucker::rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
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

fn intercept_session_config(port: u16) -> SessionConfig {
    let toml = format!(
        "version = 1\noperation = \"create\"\n\n[session]\npersistent = true\n\n[[rules]]\nhost = \"localhost\"\nmode = \"intercept\"\nports = [{port}]\npaths = [\"/allowed\"]\n"
    );
    let ControlRequest::Create { session, .. } =
        ControlRequest::from_toml(&toml).expect("intercept session should be valid")
    else {
        panic!("test request should create a session");
    };
    session
}

fn private_destination_session_config(port: u16) -> SessionConfig {
    let toml = format!(
        "version = 1\noperation = \"create\"\n\n[session]\npersistent = true\n\n[[rules]]\nhost = \"localhost\"\nmode = \"tunnel\"\nports = [{port}]\nprivate_addresses = [\"127.0.0.1\"]\n"
    );
    let ControlRequest::Create { session, .. } =
        ControlRequest::from_toml(&toml).expect("private destination session should be valid")
    else {
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

#[tokio::test]
async fn intercept_connect_with_unknown_payload_does_not_open_an_opaque_tunnel() {
    let directory = tempfile::tempdir().expect("test directory should be created");
    let ca = write_test_ca(directory.path());
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test upstream should bind");
    let upstream_port = upstream
        .local_addr()
        .expect("test upstream address should be available")
        .port();
    let (event_sender, mut events) = mpsc::unbounded_channel();
    let id = RuntimeId::new("runtime-intercept-unknown-connect");
    let runtime = ProxyRuntime::start(
        id.clone(),
        intercept_session_config(upstream_port),
        ca,
        directory.path().join("intercept.sock"),
        4,
        event_sender,
    )
    .await
    .expect("intercept runtime should start");

    let mut client = TcpStream::connect(runtime.local_addr())
        .await
        .expect("proxy should accept CONNECT");
    let request = format!(
        "CONNECT localhost:{upstream_port} HTTP/1.1\r\nHost: localhost:{upstream_port}\r\n\r\n"
    );
    client
        .write_all(request.as_bytes())
        .await
        .expect("CONNECT request should be sent");
    let mut client = BufReader::new(client);
    let mut status = String::new();
    timeout(Duration::from_secs(2), client.read_line(&mut status))
        .await
        .expect("proxy should respond to CONNECT")
        .expect("CONNECT response should be readable");
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "unexpected response: {status:?}"
    );
    loop {
        let mut header = String::new();
        timeout(Duration::from_secs(2), client.read_line(&mut header))
            .await
            .expect("CONNECT response headers should arrive")
            .expect("CONNECT response header should be readable");
        if header == "\r\n" || header.is_empty() {
            break;
        }
    }

    client
        .get_mut()
        .write_all(b"NOPE")
        .await
        .expect("unknown CONNECT payload should be sent");
    assert!(
        timeout(Duration::from_millis(250), upstream.accept())
            .await
            .is_err(),
        "intercept mode must not connect to the destination for an unknown payload"
    );
    let mut byte = [0; 1];
    let read = timeout(Duration::from_secs(2), client.read(&mut byte))
        .await
        .expect("proxy should close an unsupported intercepted payload")
        .expect("proxy connection should close cleanly");
    assert_eq!(read, 0, "unsupported payload must not receive tunnel data");

    runtime.shutdown(Duration::from_secs(2)).await;
    assert_exit(&mut events, &id).await;
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
    let runtime = ProxyRuntime::start(
        runtime_id.clone(),
        session_config(),
        ca,
        directory.path().join("ip-deny.sock"),
        8,
        event_sender,
    )
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

#[tokio::test]
async fn http_and_connect_can_use_an_explicit_private_destination() {
    let directory = tempfile::tempdir().expect("test directory should be created");
    let ca = write_test_ca(directory.path());
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test upstream should bind");
    let upstream_port = upstream
        .local_addr()
        .expect("test upstream address should be available")
        .port();
    let (event_sender, mut events) = mpsc::unbounded_channel();
    let id = RuntimeId::new("runtime-private-destination");
    let runtime = ProxyRuntime::start(
        id.clone(),
        private_destination_session_config(upstream_port),
        ca,
        directory.path().join("private-destination.sock"),
        4,
        event_sender,
    )
    .await
    .expect("runtime should start");

    let upstream_task = tokio::spawn(async move {
        let (mut http, _) = upstream
            .accept()
            .await
            .expect("authorized HTTP request should reach upstream");
        let mut request = Vec::new();
        let mut chunk = [0; 1024];
        loop {
            let count = http
                .read(&mut chunk)
                .await
                .expect("upstream request should be readable");
            assert_ne!(count, 0, "upstream should receive an HTTP request");
            request.extend_from_slice(&chunk[..count]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        assert!(request.starts_with(b"GET / HTTP/1.1"));
        http.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .expect("HTTP response should reach the proxy");
        http.shutdown()
            .await
            .expect("HTTP upstream should close cleanly");

        let (mut tunnel, _) = upstream
            .accept()
            .await
            .expect("authorized CONNECT should reach upstream");
        let mut payload = [0; 4];
        tunnel
            .read_exact(&mut payload)
            .await
            .expect("CONNECT payload should reach upstream");
        tunnel
            .write_all(&payload)
            .await
            .expect("CONNECT response should reach the proxy");
    });

    let mut http_client = TcpStream::connect(runtime.local_addr())
        .await
        .expect("proxy should accept HTTP");
    http_client
        .write_all(
            format!(
                "GET http://localhost:{upstream_port}/ HTTP/1.1\r\nHost: localhost:{upstream_port}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("HTTP request should be sent");
    let mut http_response = Vec::new();
    timeout(
        Duration::from_secs(3),
        http_client.read_to_end(&mut http_response),
    )
    .await
    .expect("HTTP response should arrive")
    .expect("HTTP response should be readable");
    assert!(http_response.windows(6).any(|window| window == b"200 OK"));
    assert!(http_response.ends_with(b"ok"));

    let mut connect_client = TcpStream::connect(runtime.local_addr())
        .await
        .expect("proxy should accept CONNECT");
    connect_client
        .write_all(
            format!(
                "CONNECT localhost:{upstream_port} HTTP/1.1\r\nHost: localhost:{upstream_port}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("CONNECT request should be sent");
    let mut connect_client = BufReader::new(connect_client);
    let mut status = String::new();
    timeout(
        Duration::from_secs(3),
        connect_client.read_line(&mut status),
    )
    .await
    .expect("CONNECT response should arrive")
    .expect("CONNECT status should be readable");
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "unexpected response: {status:?}"
    );
    loop {
        let mut header = String::new();
        timeout(
            Duration::from_secs(3),
            connect_client.read_line(&mut header),
        )
        .await
        .expect("CONNECT headers should arrive")
        .expect("CONNECT header should be readable");
        if header == "\r\n" || header.is_empty() {
            break;
        }
    }
    connect_client
        .get_mut()
        .write_all(b"ping")
        .await
        .expect("CONNECT payload should be sent");
    let mut echoed = [0; 4];
    timeout(
        Duration::from_secs(3),
        connect_client.read_exact(&mut echoed),
    )
    .await
    .expect("CONNECT response should arrive")
    .expect("CONNECT response should be readable");
    assert_eq!(&echoed, b"ping");

    runtime.shutdown(Duration::from_secs(2)).await;
    assert_exit(&mut events, &id).await;
    upstream_task
        .await
        .expect("upstream task should complete successfully");
}
