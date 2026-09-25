use std::{error::Error, fs, net::SocketAddr, sync::Arc, time::Duration};

use baffle_proxy::{
    ca::ManagedCa,
    config::{ControlRequest, SessionConfig},
    proxy_runtime::{ProxyRuntime, ProxyRuntimeEvent, RuntimeId},
};
use hudsucker::{
    Body,
    hyper::{Request, Version},
    hyper_util::rt::{TokioExecutor, TokioIo},
    rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose},
    rustls::{
        ClientConfig, RootCertStore,
        crypto::aws_lc_rs,
        pki_types::{CertificateDer, ServerName},
    },
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream, UnixStream},
    sync::mpsc,
    time::timeout,
};
use tokio_rustls::{TlsConnector, client::TlsStream};

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
        "version = 1\noperation = \"create\"\n\n[session]\npersistent = true\n\n[[rules]]\nhost = \"localhost\"\nmode = \"intercept\"\nports = [{port}]\nprivate_addresses = [\"127.0.0.1\", \"::1\"]\npaths = [\"/allowed\"]\n"
    );
    let ControlRequest::Create { session, .. } =
        ControlRequest::from_toml(&toml).expect("intercept session should be valid")
    else {
        panic!("test request should create a session");
    };
    session
}

fn intercept_session_without_private_addresses_config(port: u16) -> SessionConfig {
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

fn tls_client_config(ca: &ManagedCa, alpn: &[u8]) -> Arc<ClientConfig> {
    let (_, certificate) = x509_parser::pem::parse_x509_pem(ca.public_certificate_pem())
        .expect("test CA certificate should be valid PEM");
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(certificate.contents))
        .expect("test CA certificate should be a valid trust anchor");
    let mut config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("supported TLS versions should be available")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    Arc::new(config)
}

async fn open_connect_tunnel(
    proxy_address: SocketAddr,
    authority: &str,
) -> Result<TcpStream, Box<dyn Error + Send + Sync>> {
    let mut stream = TcpStream::connect(proxy_address).await?;
    stream
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await?;
    let mut reader = BufReader::new(stream);
    let mut status = String::new();
    timeout(Duration::from_secs(2), reader.read_line(&mut status)).await??;
    if !status.starts_with("HTTP/1.1 200") {
        return Err(format!("CONNECT failed: {status:?}").into());
    }
    loop {
        let mut header = String::new();
        timeout(Duration::from_secs(2), reader.read_line(&mut header)).await??;
        if header == "\r\n" || header.is_empty() {
            break;
        }
    }
    Ok(reader.into_inner())
}

async fn connect_intercepted_tls(
    proxy_address: SocketAddr,
    authority: &str,
    server_name: &str,
    ca: &ManagedCa,
    alpn: &[u8],
) -> Result<TlsStream<TcpStream>, Box<dyn Error + Send + Sync>> {
    let stream = open_connect_tunnel(proxy_address, authority).await?;
    let server_name = ServerName::try_from(server_name.to_owned())?;
    let tls = TlsConnector::from(tls_client_config(ca, alpn))
        .connect(server_name, stream)
        .await?;
    Ok(tls)
}

async fn read_http1_status<S>(stream: &mut BufReader<S>) -> std::io::Result<String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut status = String::new();
    stream.read_line(&mut status).await?;
    loop {
        let mut header = String::new();
        stream.read_line(&mut header).await?;
        if header == "\r\n" || header.is_empty() {
            break;
        }
    }
    Ok(status)
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

#[tokio::test]
async fn intercepted_https_rejects_private_upstream_addresses() {
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
    let id = RuntimeId::new("runtime-intercept-private-upstream");
    let runtime = ProxyRuntime::start(
        id.clone(),
        intercept_session_without_private_addresses_config(upstream_port),
        Arc::clone(&ca),
        directory.path().join("intercept-private.sock"),
        4,
        event_sender,
    )
    .await
    .expect("intercept runtime should start");

    let mut proxy = TcpStream::connect(runtime.local_addr())
        .await
        .expect("proxy should accept CONNECT");
    proxy
        .write_all(
            format!(
                "CONNECT localhost:{upstream_port} HTTP/1.1\r\nHost: localhost:{upstream_port}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("CONNECT request should be sent");
    let mut proxy = BufReader::new(proxy);
    let mut status = String::new();
    timeout(Duration::from_secs(2), proxy.read_line(&mut status))
        .await
        .expect("proxy should respond to CONNECT")
        .expect("CONNECT response should be readable");
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "unexpected CONNECT response: {status:?}"
    );
    loop {
        let mut header = String::new();
        timeout(Duration::from_secs(2), proxy.read_line(&mut header))
            .await
            .expect("CONNECT response headers should arrive")
            .expect("CONNECT response header should be readable");
        if header == "\r\n" || header.is_empty() {
            break;
        }
    }

    let (_, ca_certificate) = x509_parser::pem::parse_x509_pem(ca.public_certificate_pem())
        .expect("test CA certificate should be valid PEM");
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_certificate.contents))
        .expect("test CA certificate should be a valid root");
    let client_config =
        ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("supported TLS versions should be available")
            .with_root_certificates(roots)
            .with_no_client_auth();
    let server_name =
        ServerName::try_from("localhost".to_owned()).expect("test TLS server name should be valid");
    let mut tls = timeout(
        Duration::from_secs(3),
        TlsConnector::from(Arc::new(client_config)).connect(server_name, proxy.into_inner()),
    )
    .await
    .expect("proxy TLS handshake should complete")
    .expect("test CA should authenticate the intercepted connection");
    tls.write_all(
        format!(
            "GET /allowed HTTP/1.1\r\nHost: localhost:{upstream_port}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .expect("intercepted HTTPS request should be sent");
    let mut response = Vec::new();
    timeout(Duration::from_secs(3), tls.read_to_end(&mut response))
        .await
        .expect("intercepted HTTPS response should arrive")
        .expect("intercepted HTTPS response should be readable");
    assert!(
        response.starts_with(b"HTTP/1.1 502") || response.starts_with(b"HTTP/1.0 502"),
        "private upstream resolution should fail as a gateway error: {response:?}"
    );
    assert!(
        timeout(Duration::from_millis(100), upstream.accept())
            .await
            .is_err(),
        "intercepted HTTPS must validate the upstream IP before dialing"
    );

    runtime.shutdown(Duration::from_secs(2)).await;
    assert_exit(&mut events, &id).await;
}

#[tokio::test]
async fn intercepted_tls_rejects_missing_or_conflicting_sni_before_egress() {
    let directory = tempfile::tempdir().expect("test directory should be created");
    let ca = write_test_ca(directory.path());
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test upstream should bind");
    let upstream_port = upstream.local_addr().unwrap().port();
    let (event_sender, mut events) = mpsc::unbounded_channel();
    let id = RuntimeId::new("runtime-intercept-sni");
    let runtime = ProxyRuntime::start(
        id.clone(),
        intercept_session_config(upstream_port),
        Arc::clone(&ca),
        directory.path().join("sni.sock"),
        4,
        event_sender,
    )
    .await
    .expect("intercept runtime should start");
    let authority = format!("localhost:{upstream_port}");

    let conflicting = timeout(
        Duration::from_secs(2),
        connect_intercepted_tls(
            runtime.local_addr(),
            &authority,
            "other.example",
            &ca,
            b"http/1.1",
        ),
    )
    .await
    .expect("conflicting SNI negotiation should finish")
    .is_err();
    assert!(conflicting, "SNI must match the CONNECT authority");

    let tunnel = open_connect_tunnel(runtime.local_addr(), &authority)
        .await
        .expect("second CONNECT should be accepted before TLS parsing");
    let missing_sni_name = ServerName::try_from("127.0.0.1".to_owned()).unwrap();
    let missing_sni = timeout(
        Duration::from_secs(2),
        TlsConnector::from(tls_client_config(&ca, b"http/1.1")).connect(missing_sni_name, tunnel),
    )
    .await
    .expect("missing SNI negotiation should finish")
    .is_err();
    assert!(missing_sni, "intercepted TLS must include SNI");

    let mut malformed = open_connect_tunnel(runtime.local_addr(), &authority)
        .await
        .expect("third CONNECT should be accepted before TLS parsing");
    malformed
        .write_all(b"\x16\x03\x03\x00\x01\xff")
        .await
        .expect("malformed TLS record should be sent");
    malformed
        .shutdown()
        .await
        .expect("malformed TLS sender should finish the record");
    let mut byte = [0; 1];
    let malformed_read = timeout(Duration::from_secs(2), malformed.read(&mut byte))
        .await
        .expect("malformed TLS connection should be rejected")
        .expect("malformed TLS connection should close cleanly");
    assert_eq!(malformed_read, 0, "malformed TLS must not receive a tunnel");

    assert!(
        timeout(Duration::from_millis(200), upstream.accept())
            .await
            .is_err(),
        "invalid intercepted identities must not reach the upstream"
    );

    runtime.shutdown(Duration::from_secs(2)).await;
    assert_exit(&mut events, &id).await;
}

#[tokio::test]
async fn plaintext_paths_are_canonicalized_and_rechecked_after_redirects_on_keepalive() {
    let directory = tempfile::tempdir().expect("test directory should be created");
    let ca = write_test_ca(directory.path());
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test upstream should bind");
    let upstream_port = upstream_listener.local_addr().unwrap().port();
    let (event_sender, mut events) = mpsc::unbounded_channel();
    let id = RuntimeId::new("runtime-http-path-keepalive");
    let runtime = ProxyRuntime::start(
        id.clone(),
        intercept_session_config(upstream_port),
        ca,
        directory.path().join("http-path-keepalive.sock"),
        4,
        event_sender,
    )
    .await
    .expect("intercept runtime should start");

    let authority = format!("localhost:{upstream_port}");
    let mut client = BufReader::new(
        TcpStream::connect(runtime.local_addr())
            .await
            .expect("proxy should accept plaintext HTTP"),
    );
    client
        .get_mut()
        .write_all(
            format!(
                "GET http://{authority}/%61llowed?ref=main HTTP/1.1\r\nHost: {authority}\r\nConnection: keep-alive\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("allowed request should be sent");

    let (upstream_stream, _) = timeout(Duration::from_secs(2), upstream_listener.accept())
        .await
        .expect("allowed request should reach the upstream")
        .expect("upstream connection should be accepted");
    let mut upstream = BufReader::new(upstream_stream);
    let mut request_line = String::new();
    timeout(
        Duration::from_secs(2),
        upstream.read_line(&mut request_line),
    )
    .await
    .expect("upstream request target should arrive")
    .expect("upstream request target should be readable");
    assert_eq!(
        request_line, "GET /allowed?ref=main HTTP/1.1\r\n",
        "upstream must receive the exact canonical path that policy checked"
    );
    loop {
        let mut header = String::new();
        timeout(Duration::from_secs(2), upstream.read_line(&mut header))
            .await
            .expect("upstream request headers should arrive")
            .expect("upstream request headers should be readable");
        if header == "\r\n" {
            break;
        }
    }
    upstream
        .get_mut()
        .write_all(
            b"HTTP/1.1 302 Found\r\nLocation: /outside\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
        )
        .await
        .expect("upstream redirect should be sent");
    let first_response = timeout(Duration::from_secs(2), read_http1_status(&mut client))
        .await
        .expect("redirect response should reach the client")
        .expect("redirect response should be readable");
    assert!(
        first_response.starts_with("HTTP/1.1 302"),
        "{first_response:?}"
    );

    client
        .get_mut()
        .write_all(
            format!(
                "GET http://{authority}/outside HTTP/1.1\r\nHost: {authority}\r\nConnection: keep-alive\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("redirect follow-up request should be sent on the reused connection");
    let denied_response = timeout(Duration::from_secs(2), read_http1_status(&mut client))
        .await
        .expect("redirect follow-up should receive a policy response")
        .expect("redirect follow-up response should be readable");
    assert!(
        denied_response.starts_with("HTTP/1.1 403"),
        "{denied_response:?}"
    );

    let unexpected_upstream_request = timeout(Duration::from_millis(200), async {
        let mut next_line = String::new();
        tokio::select! {
            result = upstream.read_line(&mut next_line) => result.map(|_| "reused upstream connection"),
            result = upstream_listener.accept() => result.map(|_| "new upstream connection"),
        }
    })
    .await;
    assert!(
        unexpected_upstream_request.is_err(),
        "a redirected request outside the path allowlist must not reach upstream"
    );

    drop(client);
    runtime.shutdown(Duration::from_secs(2)).await;
    assert_exit(&mut events, &id).await;
}

#[tokio::test]
async fn malformed_and_encoded_path_targets_are_rejected_before_upstream() {
    let directory = tempfile::tempdir().expect("test directory should be created");
    let ca = write_test_ca(directory.path());
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test upstream should bind");
    let upstream_port = upstream.local_addr().unwrap().port();
    let (event_sender, mut events) = mpsc::unbounded_channel();
    let id = RuntimeId::new("runtime-http-malformed-path");
    let runtime = ProxyRuntime::start(
        id.clone(),
        intercept_session_config(upstream_port),
        ca,
        directory.path().join("http-malformed-path.sock"),
        4,
        event_sender,
    )
    .await
    .expect("intercept runtime should start");

    let authority = format!("localhost:{upstream_port}");
    for path in [
        "/allowedness",
        "/allowed%2fprivate",
        "/allowed%252fprivate",
        "/%2e%2e/allowed",
        "/allowed%2",
    ] {
        let mut client = TcpStream::connect(runtime.local_addr())
            .await
            .expect("proxy should accept request connection");
        let request = format!(
            "GET http://{authority}{path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
        );
        client
            .write_all(request.as_bytes())
            .await
            .expect("malformed target should be sent");
        let mut reader = BufReader::new(client);
        let mut response = String::new();
        timeout(Duration::from_secs(2), reader.read_line(&mut response))
            .await
            .expect("proxy should reject the request target")
            .expect("rejection response should be readable");
        assert!(
            response.starts_with("HTTP/1.1 400") || response.starts_with("HTTP/1.1 403"),
            "unsafe target {path:?} received {response:?}"
        );
    }

    assert!(
        timeout(Duration::from_millis(200), upstream.accept())
            .await
            .is_err(),
        "malformed or non-matching paths must not reach the upstream"
    );
    runtime.shutdown(Duration::from_secs(2)).await;
    assert_exit(&mut events, &id).await;
}

#[tokio::test]
async fn intercepted_http2_path_rules_reject_disallowed_streams() {
    let directory = tempfile::tempdir().expect("test directory should be created");
    let ca = write_test_ca(directory.path());
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test upstream should bind");
    let upstream_port = upstream.local_addr().unwrap().port();
    let (event_sender, mut events) = mpsc::unbounded_channel();
    let id = RuntimeId::new("runtime-intercept-http2-path");
    let runtime = ProxyRuntime::start(
        id.clone(),
        intercept_session_config(upstream_port),
        Arc::clone(&ca),
        directory.path().join("http2-path.sock"),
        4,
        event_sender,
    )
    .await
    .expect("intercept runtime should start");

    let authority = format!("localhost:{upstream_port}");
    let tls = connect_intercepted_tls(runtime.local_addr(), &authority, "localhost", &ca, b"h2")
        .await
        .expect("matching SNI should establish intercepted TLS");
    let (mut sender, connection) =
        hudsucker::hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .expect("HTTP/2 client should connect to the intercepted stream");
    let driver = tokio::spawn(connection);
    let request = Request::builder()
        .method("GET")
        .version(Version::HTTP_2)
        .uri(format!("https://{authority}/outside"))
        .body(Body::empty())
        .expect("HTTP/2 request should build");
    let response = timeout(Duration::from_secs(2), sender.send_request(request))
        .await
        .expect("HTTP/2 path denial should return a response")
        .expect("HTTP/2 denial response should be readable");
    assert_eq!(response.status(), hudsucker::hyper::StatusCode::FORBIDDEN);
    assert!(
        timeout(Duration::from_millis(200), upstream.accept())
            .await
            .is_err(),
        "a disallowed HTTP/2 path must not reach the upstream"
    );
    drop(sender);
    driver.abort();

    runtime.shutdown(Duration::from_secs(2)).await;
    assert_exit(&mut events, &id).await;
}

#[tokio::test]
async fn intercepted_http2_authority_cannot_change_the_connect_destination() {
    let directory = tempfile::tempdir().expect("test directory should be created");
    let ca = write_test_ca(directory.path());
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test upstream should bind");
    let upstream_port = upstream.local_addr().unwrap().port();
    let (event_sender, mut events) = mpsc::unbounded_channel();
    let id = RuntimeId::new("runtime-intercept-http2-authority");
    let runtime = ProxyRuntime::start(
        id.clone(),
        intercept_session_config(upstream_port),
        Arc::clone(&ca),
        directory.path().join("http2.sock"),
        4,
        event_sender,
    )
    .await
    .expect("intercept runtime should start");
    let authority = format!("localhost:{upstream_port}");
    let tls = connect_intercepted_tls(runtime.local_addr(), &authority, "localhost", &ca, b"h2")
        .await
        .expect("matching SNI should establish intercepted TLS");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (mut sender, connection) =
        hudsucker::hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .expect("HTTP/2 client should connect to the intercepted stream");
    let driver = tokio::spawn(connection);
    let request = Request::builder()
        .method("GET")
        .version(Version::HTTP_2)
        .uri("https://example.org/allowed")
        .body(Body::empty())
        .expect("HTTP/2 request should build");
    let response = timeout(Duration::from_secs(2), sender.send_request(request))
        .await
        .expect("HTTP/2 request should receive a response")
        .expect("HTTP/2 response should be readable");
    assert_eq!(response.status(), hudsucker::hyper::StatusCode::BAD_REQUEST);
    assert!(
        timeout(Duration::from_millis(200), upstream.accept())
            .await
            .is_err(),
        "conflicting HTTP/2 :authority must not reach the upstream"
    );
    drop(sender);
    driver.abort();

    runtime.shutdown(Duration::from_secs(2)).await;
    assert_exit(&mut events, &id).await;
}

#[tokio::test]
async fn intercepted_http2_http_scheme_is_rejected_before_upstream_connection() {
    let directory = tempfile::tempdir().expect("test directory should be created");
    let ca = write_test_ca(directory.path());
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test upstream should bind");
    let upstream_port = upstream.local_addr().unwrap().port();
    let (event_sender, mut events) = mpsc::unbounded_channel();
    let id = RuntimeId::new("runtime-intercept-http2-http-scheme");
    let runtime = ProxyRuntime::start(
        id.clone(),
        intercept_session_config(upstream_port),
        Arc::clone(&ca),
        directory.path().join("http2-http-scheme.sock"),
        4,
        event_sender,
    )
    .await
    .expect("intercept runtime should start");
    let authority = format!("localhost:{upstream_port}");
    let tls = connect_intercepted_tls(runtime.local_addr(), &authority, "localhost", &ca, b"h2")
        .await
        .expect("matching SNI should establish intercepted TLS");
    let (mut sender, connection) =
        hudsucker::hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .expect("HTTP/2 client should connect to the intercepted stream");
    let driver = tokio::spawn(connection);
    let request = Request::builder()
        .method("GET")
        .version(Version::HTTP_2)
        .uri(format!("http://{authority}/allowed"))
        .body(Body::empty())
        .expect("HTTP/2 request should build");
    let response = timeout(Duration::from_secs(2), sender.send_request(request))
        .await
        .expect("HTTP/2 request should receive a response")
        .expect("HTTP/2 response should be readable");
    assert_eq!(response.status(), hudsucker::hyper::StatusCode::BAD_REQUEST);
    assert!(
        timeout(Duration::from_millis(200), upstream.accept())
            .await
            .is_err(),
        "an intercepted HTTP/2 request with :scheme http must not reach the upstream"
    );
    drop(sender);
    driver.abort();

    runtime.shutdown(Duration::from_secs(2)).await;
    assert_exit(&mut events, &id).await;
}

#[tokio::test]
async fn revocation_blocks_new_http1_requests_on_an_intercepted_connection() {
    let directory = tempfile::tempdir().expect("test directory should be created");
    let ca = write_test_ca(directory.path());
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test upstream should bind");
    let upstream_port = upstream.local_addr().unwrap().port();
    let (event_sender, mut events) = mpsc::unbounded_channel();
    let id = RuntimeId::new("runtime-intercept-revocation");
    let runtime = ProxyRuntime::start(
        id.clone(),
        intercept_session_config(upstream_port),
        Arc::clone(&ca),
        directory.path().join("revocation.sock"),
        4,
        event_sender,
    )
    .await
    .expect("intercept runtime should start");
    let authority = format!("localhost:{upstream_port}");
    let tls = connect_intercepted_tls(
        runtime.local_addr(),
        &authority,
        "localhost",
        &ca,
        b"http/1.1",
    )
    .await
    .expect("matching SNI should establish intercepted TLS");
    let mut client = BufReader::new(tls);

    client
        .get_mut()
        .write_all(
            format!("GET /allowed HTTP/1.1\r\nHost: {authority}\r\nConnection: keep-alive\r\n\r\n")
                .as_bytes(),
        )
        .await
        .expect("first intercepted request should be sent");
    let (upstream_stream, _) = timeout(Duration::from_secs(2), upstream.accept())
        .await
        .expect("first request should attempt one upstream connection")
        .expect("upstream connection should be accepted");
    drop(upstream_stream);
    let first_status = timeout(Duration::from_secs(2), read_http1_status(&mut client))
        .await
        .expect("first request should receive a response")
        .expect("first response should be readable");
    assert!(first_status.starts_with("HTTP/1.1 502"), "{first_status:?}");

    let socket_path = directory.path().join("revocation.sock");
    let shutdown = tokio::spawn(runtime.shutdown(Duration::from_secs(2)));
    timeout(Duration::from_secs(2), async {
        while socket_path.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("revocation should close the session ingress");

    let second_write = client
        .get_mut()
        .write_all(
            format!("GET /allowed HTTP/1.1\r\nHost: {authority}\r\nConnection: keep-alive\r\n\r\n")
                .as_bytes(),
        )
        .await;
    if second_write.is_ok() {
        let second_status = timeout(Duration::from_secs(2), read_http1_status(&mut client)).await;
        assert!(
            second_status.is_err()
                || second_status
                    .as_ref()
                    .ok()
                    .and_then(|result| result.as_ref().ok())
                    .is_none_or(|status| status.starts_with("HTTP/1.1 403")),
            "revoked connection must close or reject its next request"
        );
    }
    assert!(
        timeout(Duration::from_millis(200), upstream.accept())
            .await
            .is_err(),
        "a revoked intercepted connection must not create a new upstream request"
    );

    drop(client);
    timeout(Duration::from_secs(3), shutdown)
        .await
        .expect("proxy shutdown should finish")
        .expect("proxy shutdown task should join");
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
