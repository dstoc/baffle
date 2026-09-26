#![cfg(target_os = "linux")]

mod common;

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use common::{DaemonProcess, socket_from};
use h2::client;
use http::{Request, StatusCode, Version, header::AUTHORIZATION};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, UnixStream},
    sync::mpsc,
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, TlsConnector, rustls};

#[tokio::test]
async fn real_daemon_uses_isolated_unix_sockets_for_tunnel_sessions_and_leases() {
    let mut first_upstream = spawn_echo_origin().await;
    let mut second_upstream = spawn_echo_origin().await;
    let daemon = DaemonProcess::start(2, &[]);
    assert!(daemon.directory.path().is_dir());

    let mut ephemeral_lease = daemon.control();
    let (_, ephemeral_created) = daemon.create_session(
        &mut ephemeral_lease,
        &tunnel_session(false, first_upstream.address.port()),
    );
    assert_eq!(ephemeral_created["ok"], true);
    let ephemeral_socket = socket_from(&ephemeral_created);

    let named_session = tunnel_session(true, second_upstream.address.port()).replace(
        "persistent = true",
        "persistent = true\nsocket_name = \"cladding/github.sock\"",
    );
    let (_, persistent_created) = daemon.request(&named_session);
    assert_eq!(persistent_created["ok"], true);
    let persistent_socket = socket_from(&persistent_created);
    assert_ne!(ephemeral_socket, persistent_socket);
    assert_eq!(
        persistent_socket,
        daemon.directory.path().join("proxies/cladding/github.sock")
    );
    assert!(ephemeral_socket.exists());
    assert!(persistent_socket.exists());

    let mut first_tunnel = connect_tunnel(
        &ephemeral_socket,
        &format!("localhost:{}", first_upstream.address.port()),
    )
    .await;
    first_tunnel
        .write_all(b"first-session")
        .await
        .expect("tunnel payload should be sent");
    let mut first_echo = [0; 13];
    first_tunnel
        .read_exact(&mut first_echo)
        .await
        .expect("the first session should reach its assigned upstream");
    assert_eq!(&first_echo, b"first-session");
    assert!(
        timeout(Duration::from_secs(2), first_upstream.accepted.recv())
            .await
            .expect("the authorized destination should be dialed")
            .is_some()
    );
    drop(first_tunnel);

    assert_status(
        &ephemeral_socket,
        &format!(
            "CONNECT forbidden.localhost:{} HTTP/1.1\r\nHost: forbidden.localhost:{}\r\n\r\n",
            first_upstream.address.port(),
            first_upstream.address.port()
        ),
        &["403"],
    )
    .await;
    assert!(
        timeout(Duration::from_millis(150), first_upstream.accepted.recv())
            .await
            .is_err(),
        "a session must not dial a denied host"
    );

    assert_status(
        &ephemeral_socket,
        &format!(
            "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
            second_upstream.address.port(),
            second_upstream.address.port()
        ),
        &["403"],
    )
    .await;
    assert!(
        timeout(Duration::from_millis(150), second_upstream.accepted.recv())
            .await
            .is_err(),
        "a session with a different port rule must not dial the second upstream"
    );

    assert_status(
        &persistent_socket,
        &format!(
            "GET http://localhost:{}/ HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
            second_upstream.address.port(),
            second_upstream.address.port()
        ),
        &["400", "403"],
    )
    .await;
    assert!(
        timeout(Duration::from_millis(150), second_upstream.accepted.recv())
            .await
            .is_err(),
        "plaintext forward HTTP must not dial an allowed HTTPS destination"
    );

    let mut second_tunnel = connect_tunnel(
        &persistent_socket,
        &format!("localhost:{}", second_upstream.address.port()),
    )
    .await;
    second_tunnel
        .write_all(b"second-session")
        .await
        .expect("second tunnel payload should be sent");
    let mut second_echo = [0; 14];
    second_tunnel
        .read_exact(&mut second_echo)
        .await
        .expect("the second session should reach only its own upstream");
    assert_eq!(&second_echo, b"second-session");
    assert!(
        timeout(Duration::from_secs(2), second_upstream.accepted.recv())
            .await
            .expect("the second authorized destination should be dialed")
            .is_some()
    );
    drop(second_tunnel);

    let (_, full) = daemon.request(&tunnel_session(true, first_upstream.address.port()));
    assert_eq!(full["error"]["code"], "session_limit");
    drop(ephemeral_lease);
    wait_for_path(&ephemeral_socket, false).await;
    timeout(Duration::from_secs(3), async {
        loop {
            let (_, listed) = daemon.request("version = 1\noperation = \"list\"\n");
            if listed["result"]["sessions"].as_array().unwrap().len() == 1 {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("lease reaper should remove the session before the collision check");
    let (_, collision) = daemon.request(&named_session);
    assert_eq!(collision["error"]["code"], "internal_error");
    assert!(
        persistent_socket.exists(),
        "collision must preserve the owned socket"
    );
    assert!(
        persistent_socket.exists(),
        "the other session must keep running"
    );

    let session_id = persistent_created["result"]["id"]
        .as_str()
        .expect("persistent session should have an ID");
    fs::remove_file(&persistent_socket).expect("test should unlink the original socket");
    fs::write(&persistent_socket, b"replacement file")
        .expect("test should place an unrelated file at the old socket path");
    let (_, stopped) = daemon.request(&format!(
        "version = 1\noperation = \"stop\"\nsession_id = \"{session_id}\"\n"
    ));
    assert_eq!(stopped["result"]["stopped"], true);
    assert_eq!(
        fs::read(&persistent_socket).expect("replacement file should remain"),
        b"replacement file"
    );
    drop((first_upstream, second_upstream));
}

#[tokio::test]
async fn real_daemon_rejects_nested_socket_symlinks_and_path_traversal() {
    let daemon = DaemonProcess::start(4, &[]);
    let proxies = daemon.directory.path().join("proxies");
    let target = tempfile::tempdir().expect("symlink target should exist");
    let link = proxies.join("cladding");
    std::os::unix::fs::symlink(target.path(), &link)
        .expect("nested path symlink should be created");

    let named = tunnel_session(true, 443).replace(
        "persistent = true",
        "persistent = true\nsocket_name = \"cladding/github.sock\"",
    );
    let (_, response) = daemon.request(&named);
    assert_eq!(response["error"]["code"], "internal_error");
    assert!(
        !target.path().join("github.sock").exists(),
        "the daemon must not bind through a nested symlink"
    );

    let traversal = tunnel_session(true, 443).replace(
        "persistent = true",
        "persistent = true\nsocket_name = \"../outside.sock\"",
    );
    let (_, response) = daemon.request(&traversal);
    assert_eq!(response["error"]["code"], "invalid_request");
    assert!(!daemon.directory.path().join("outside.sock").exists());
}

#[tokio::test]
async fn real_daemon_checks_secret_entitlement_paths_and_credential_redaction() {
    let upstream_directory = tempfile::tempdir().expect("upstream fixture directory should exist");
    let (upstream_root, upstream_certificate, upstream_key) =
        write_upstream_certificates(upstream_directory.path());
    let mut upstream = spawn_tls_origin(upstream_certificate, upstream_key).await;
    let daemon = DaemonProcess::start_with_upstream_ca(2, &["api-token"], Some(&upstream_root));
    daemon.write_secret("api-token", "daemon-only-token-42");
    daemon.write_secret("unentitled-token", "unentitled-secret-value");

    let (_, denied) = daemon.request(&injected_session(
        "not-entitled.example",
        upstream.address.port(),
        "unentitled-token",
    ));
    assert_eq!(denied["error"]["code"], "secret_unavailable");
    assert!(
        !serde_json::to_string(&denied)
            .expect("error response should serialize")
            .contains("unentitled-secret-value"),
        "an unentitled secret value must not appear in the control response"
    );

    let mut lease = daemon.control();
    let (body, created) = daemon.create_session(
        &mut lease,
        &injected_session("localhost", upstream.address.port(), "api-token"),
    );
    assert_eq!(created["ok"], true);
    assert!(
        !String::from_utf8_lossy(&body).contains("daemon-only-token-42"),
        "session creation must not serialize a resolved credential"
    );
    let proxy_socket = socket_from(&created);
    let id = created["result"]["id"]
        .as_str()
        .expect("created session should have an ID")
        .to_owned();
    drop(lease);

    let (_, listed) = daemon.request("version = 1\noperation = \"list\"\n");
    let listed = serde_json::to_string(&listed).expect("session list should serialize");
    assert!(!listed.contains("api-token"));
    assert!(!listed.contains("daemon-only-token-42"));

    if !cfg!(baffle_integration_test) {
        // The local upstream trust hook is compiled only for CI's integration
        // build. The regular developer test command still checks entitlement
        // and control-protocol redaction above.
        return;
    }

    let mut allowed = connect_intercepted_tls(
        &proxy_socket,
        &format!("localhost:{}", upstream.address.port()),
        &daemon.ca_certificate,
    )
    .await;
    allowed
        .write_all(
            format!(
                "GET /allowed HTTP/1.1\r\nHost: localhost:{}\r\nAuthorization: Bearer client-supplied-value\r\nConnection: close\r\n\r\n",
                upstream.address.port()
            )
            .as_bytes(),
        )
        .await
        .expect("authorized HTTPS request should be sent");
    let mut allowed_response = Vec::new();
    timeout(
        Duration::from_secs(4),
        allowed.read_to_end(&mut allowed_response),
    )
    .await
    .expect("authorized response should arrive")
    .expect("authorized response should be readable");
    assert!(
        allowed_response.starts_with(b"HTTP/1.1 200")
            || allowed_response.starts_with(b"HTTP/1.0 200"),
        "authorized request should receive an upstream response: {}",
        String::from_utf8_lossy(&allowed_response)
    );
    let observed = timeout(Duration::from_secs(3), upstream.requests.recv())
        .await
        .expect("upstream should observe the authorized request")
        .expect("upstream fixture should remain active");
    assert!(observed.contains("GET /allowed HTTP/1.1"), "{observed}");
    assert!(
        observed
            .to_ascii_lowercase()
            .contains("authorization: bearer daemon-only-token-42"),
        "daemon should replace the client credential: {observed}"
    );
    assert!(
        !observed.contains("client-supplied-value"),
        "the client must not override a daemon-managed credential"
    );

    let mut denied_path = connect_intercepted_tls(
        &proxy_socket,
        &format!("localhost:{}", upstream.address.port()),
        &daemon.ca_certificate,
    )
    .await;
    denied_path
        .write_all(
            format!(
                "GET /forbidden HTTP/1.1\r\nHost: localhost:{}\r\nAuthorization: Bearer client-supplied-value\r\nConnection: close\r\n\r\n",
                upstream.address.port()
            )
            .as_bytes(),
        )
        .await
        .expect("denied HTTPS request should be sent");
    let mut denied_response = BufReader::new(denied_path);
    let mut status = String::new();
    timeout(
        Duration::from_secs(3),
        denied_response.read_line(&mut status),
    )
    .await
    .expect("denied-path response should arrive")
    .expect("denied-path response should be readable");
    assert!(status.starts_with("HTTP/1.1 403"), "{status:?}");
    assert!(
        timeout(Duration::from_millis(300), upstream.requests.recv())
            .await
            .is_err(),
        "the denied path must not reach the upstream or receive a credential"
    );

    let logs = fs::read_to_string(&daemon.log_path).expect("daemon log should be readable");
    assert!(!logs.contains("daemon-only-token-42"));
    assert!(!logs.contains("unentitled-secret-value"));

    let (_, stopped) = daemon.request(&format!(
        "version = 1\noperation = \"stop\"\nsession_id = \"{id}\"\n"
    ));
    assert_eq!(stopped["result"]["stopped"], true);
    wait_for_path(&proxy_socket, false).await;
    drop(upstream);
}

#[tokio::test]
async fn real_daemon_isolates_injected_credentials_across_http2_streams_and_sessions() {
    let upstream_directory = tempfile::tempdir().expect("upstream fixture directory should exist");
    let (upstream_root, upstream_certificate, upstream_key) =
        write_upstream_certificates(upstream_directory.path());
    let mut first_upstream =
        spawn_http2_tls_origin(upstream_certificate.clone(), upstream_key.clone()).await;
    let mut second_upstream = spawn_http2_tls_origin(upstream_certificate, upstream_key).await;
    let daemon = DaemonProcess::start_with_upstream_ca(
        4,
        &["session-one-token", "session-two-token"],
        Some(&upstream_root),
    );
    daemon.write_secret("session-one-token", "session-one-secret-91");
    daemon.write_secret("session-two-token", "session-two-secret-27");

    let first_session = injected_session(
        "localhost",
        first_upstream.address.port(),
        "session-one-token",
    )
    .replace(
        "persistent = true",
        "persistent = true\nsocket_name = \"cladding/http2-one.sock\"",
    );
    let (_, first_created) = daemon.request(&first_session);
    let (_, second_created) = daemon.request(&injected_session(
        "localhost",
        second_upstream.address.port(),
        "session-two-token",
    ));
    assert_eq!(first_created["ok"], true);
    assert_eq!(second_created["ok"], true);
    let first_socket = socket_from(&first_created);
    let second_socket = socket_from(&second_created);
    assert_ne!(first_socket, second_socket);
    assert_eq!(
        first_socket,
        daemon
            .directory
            .path()
            .join("proxies/cladding/http2-one.sock")
    );
    assert!(first_socket.exists());
    assert!(second_socket.exists());

    if !cfg!(baffle_integration_test) {
        // The upstream TLS trust hook is compiled only for CI's integration
        // build. The regular developer test still creates separate sessions.
        return;
    }

    let first_tls = connect_intercepted_tls_with_alpn(
        &first_socket,
        &format!("localhost:{}", first_upstream.address.port()),
        &daemon.ca_certificate,
        b"h2",
    )
    .await;
    let second_tls = connect_intercepted_tls_with_alpn(
        &second_socket,
        &format!("localhost:{}", second_upstream.address.port()),
        &daemon.ca_certificate,
        b"h2",
    )
    .await;
    assert_eq!(
        first_tls.get_ref().1.alpn_protocol(),
        Some(b"h2".as_slice()),
        "the first live proxy connection should negotiate HTTP/2"
    );
    assert_eq!(
        second_tls.get_ref().1.alpn_protocol(),
        Some(b"h2".as_slice()),
        "the second live proxy connection should negotiate HTTP/2"
    );

    let (first_sender, first_connection) = client::handshake(first_tls)
        .await
        .expect("first HTTP/2 client should connect to the live proxy");
    let (second_sender, second_connection) = client::handshake(second_tls)
        .await
        .expect("second HTTP/2 client should connect to the live proxy");
    let first_driver = tokio::spawn(first_connection);
    let second_driver = tokio::spawn(second_connection);

    let mut first_allowed_a = first_sender
        .clone()
        .ready()
        .await
        .expect("first allowed stream should be ready");
    let mut first_allowed_b = first_sender
        .clone()
        .ready()
        .await
        .expect("second allowed stream should be ready");
    let mut first_denied = first_sender
        .clone()
        .ready()
        .await
        .expect("first denied stream should be ready");
    let mut second_allowed_a = second_sender
        .clone()
        .ready()
        .await
        .expect("third allowed stream should be ready");
    let mut second_allowed_b = second_sender
        .clone()
        .ready()
        .await
        .expect("fourth allowed stream should be ready");
    let mut second_denied = second_sender
        .clone()
        .ready()
        .await
        .expect("second denied stream should be ready");

    let make_request = |port: u16, path: &str, attacker_value: &str| {
        Request::builder()
            .method("GET")
            .version(Version::HTTP_2)
            .uri(format!("https://localhost:{port}/{path}"))
            .header(AUTHORIZATION, attacker_value)
            .body(())
            .expect("HTTP/2 request should build")
    };
    let (first_a, _) = first_allowed_a
        .send_request(
            make_request(
                first_upstream.address.port(),
                "allowed",
                "Bearer attacker-first-a",
            ),
            true,
        )
        .expect("first session's first allowed stream should be sent");
    let (first_b, _) = first_allowed_b
        .send_request(
            make_request(
                first_upstream.address.port(),
                "allowed",
                "Bearer attacker-first-b",
            ),
            true,
        )
        .expect("first session's second allowed stream should be sent");
    let (first_rejected, _) = first_denied
        .send_request(
            make_request(
                first_upstream.address.port(),
                "forbidden",
                "Bearer attacker-first-denied",
            ),
            true,
        )
        .expect("first session's denied stream should be sent");
    let (second_a, _) = second_allowed_a
        .send_request(
            make_request(
                second_upstream.address.port(),
                "allowed",
                "Bearer attacker-second-a",
            ),
            true,
        )
        .expect("second session's first allowed stream should be sent");
    let (second_b, _) = second_allowed_b
        .send_request(
            make_request(
                second_upstream.address.port(),
                "allowed",
                "Bearer attacker-second-b",
            ),
            true,
        )
        .expect("second session's second allowed stream should be sent");
    let (second_rejected, _) = second_denied
        .send_request(
            make_request(
                second_upstream.address.port(),
                "forbidden",
                "Bearer attacker-second-denied",
            ),
            true,
        )
        .expect("second session's denied stream should be sent");

    let (first_a, first_b, first_rejected, second_a, second_b, second_rejected) = tokio::join!(
        timeout(Duration::from_secs(4), first_a),
        timeout(Duration::from_secs(4), first_b),
        timeout(Duration::from_secs(4), first_rejected),
        timeout(Duration::from_secs(4), second_a),
        timeout(Duration::from_secs(4), second_b),
        timeout(Duration::from_secs(4), second_rejected),
    );
    for response in [first_a, first_b, second_a, second_b] {
        assert_eq!(
            response
                .expect("allowed HTTP/2 response should arrive")
                .expect("allowed HTTP/2 response should be readable")
                .status(),
            StatusCode::OK
        );
    }
    for response in [first_rejected, second_rejected] {
        assert_eq!(
            response
                .expect("denied HTTP/2 response should arrive")
                .expect("denied HTTP/2 response should be readable")
                .status(),
            StatusCode::FORBIDDEN
        );
    }

    let mut first_observed = Vec::new();
    for _ in 0..2 {
        first_observed.push(
            timeout(Duration::from_secs(3), first_upstream.requests.recv())
                .await
                .expect("first session's allowed streams should reach its origin")
                .expect("first HTTP/2 origin should remain active"),
        );
    }
    assert!(
        timeout(Duration::from_millis(250), first_upstream.requests.recv())
            .await
            .is_err(),
        "denied streams from the first session must not reach its origin"
    );
    for request in &first_observed {
        assert_eq!(
            request.path, "/allowed",
            "only allowed paths may reach the first origin"
        );
        assert!(!request.authorization.contains("attacker-"));
        assert_eq!(
            request.authorization, "Bearer session-one-secret-91",
            "the first session must inject its own secret: {request:?}"
        );
    }
    let mut second_observed = Vec::new();
    for _ in 0..2 {
        second_observed.push(
            timeout(Duration::from_secs(3), second_upstream.requests.recv())
                .await
                .expect("second session's allowed streams should reach its origin")
                .expect("second HTTP/2 origin should remain active"),
        );
    }
    assert!(
        timeout(Duration::from_millis(250), second_upstream.requests.recv())
            .await
            .is_err(),
        "denied streams from the second session must not reach its origin"
    );
    for request in &second_observed {
        assert_eq!(
            request.path, "/allowed",
            "only allowed paths may reach the second origin"
        );
        assert!(!request.authorization.contains("attacker-"));
        assert_eq!(
            request.authorization, "Bearer session-two-secret-27",
            "the second session must inject its own secret: {request:?}"
        );
    }

    drop((first_sender, second_sender));
    first_driver.abort();
    second_driver.abort();
}

struct EchoOrigin {
    address: std::net::SocketAddr,
    accepted: mpsc::UnboundedReceiver<()>,
    task: JoinHandle<()>,
}

impl Drop for EchoOrigin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn spawn_echo_origin() -> EchoOrigin {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("echo origin should bind");
    let address = listener
        .local_addr()
        .expect("echo address should be available");
    let (accepted_tx, accepted) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let _ = accepted_tx.send(());
            tokio::spawn(async move {
                let mut buffer = [0; 1024];
                while let Ok(count) = stream.read(&mut buffer).await {
                    if count == 0 || stream.write_all(&buffer[..count]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    EchoOrigin {
        address,
        accepted,
        task,
    }
}

struct TlsOrigin {
    address: std::net::SocketAddr,
    requests: mpsc::UnboundedReceiver<String>,
    task: JoinHandle<()>,
}

impl Drop for TlsOrigin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Debug)]
struct Http2ObservedRequest {
    path: String,
    authorization: String,
}

struct Http2TlsOrigin {
    address: std::net::SocketAddr,
    requests: mpsc::UnboundedReceiver<Http2ObservedRequest>,
    task: JoinHandle<()>,
}

impl Drop for Http2TlsOrigin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn spawn_tls_origin(certificate: Vec<u8>, key: Vec<u8>) -> TlsOrigin {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("TLS origin should bind");
    let address = listener
        .local_addr()
        .expect("TLS origin address should exist");
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("TLS versions should be available")
    .with_no_client_auth()
    .with_single_cert(
        vec![rustls::pki_types::CertificateDer::from(certificate)],
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(key)),
    )
    .expect("TLS origin certificate should be accepted");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let (requests_tx, requests) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let requests = requests_tx.clone();
            tokio::spawn(async move {
                let Ok(tls) = timeout(Duration::from_secs(2), acceptor.accept(stream))
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .ok_or(())
                else {
                    return;
                };
                let mut reader = BufReader::new(tls);
                let mut request = String::new();
                loop {
                    let mut line = String::new();
                    let Ok(Ok(read)) =
                        timeout(Duration::from_millis(500), reader.read_line(&mut line)).await
                    else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    request.push_str(&line);
                    if line == "\r\n" {
                        break;
                    }
                }
                let _ = requests.send(request);
                let mut tls = reader.into_inner();
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
            });
        }
    });
    TlsOrigin {
        address,
        requests,
        task,
    }
}

async fn spawn_http2_tls_origin(certificate: Vec<u8>, key: Vec<u8>) -> Http2TlsOrigin {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("HTTP/2 TLS origin should bind");
    let address = listener
        .local_addr()
        .expect("HTTP/2 origin address should exist");
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("TLS versions should be available")
    .with_no_client_auth()
    .with_single_cert(
        vec![rustls::pki_types::CertificateDer::from(certificate)],
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(key)),
    )
    .expect("HTTP/2 origin certificate should be accepted");
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let (requests_tx, requests) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let requests = requests_tx.clone();
            tokio::spawn(async move {
                let Ok(Ok(tls)) = timeout(Duration::from_secs(3), acceptor.accept(stream)).await
                else {
                    return;
                };
                if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
                    return;
                }
                let Ok(mut connection) = h2::server::handshake(tls).await else {
                    return;
                };
                while let Some(Ok((request, mut respond))) = connection.accept().await {
                    let path = request.uri().path().to_owned();
                    let authorization = request
                        .headers()
                        .get(AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default()
                        .to_owned();
                    if requests
                        .send(Http2ObservedRequest {
                            path,
                            authorization,
                        })
                        .is_err()
                    {
                        return;
                    }
                    let response = http::Response::builder()
                        .status(StatusCode::OK)
                        .body(())
                        .expect("HTTP/2 origin response should build");
                    if respond.send_response(response, true).is_err() {
                        return;
                    }
                }
            });
        }
    });
    Http2TlsOrigin {
        address,
        requests,
        task,
    }
}

async fn connect_tunnel(socket: &Path, authority: &str) -> UnixStream {
    let mut stream = UnixStream::connect(socket)
        .await
        .expect("assigned proxy socket should accept a connection");
    stream
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .expect("CONNECT request should be sent");
    let mut reader = BufReader::new(stream);
    let mut status = String::new();
    timeout(Duration::from_secs(3), reader.read_line(&mut status))
        .await
        .expect("CONNECT response should arrive")
        .expect("CONNECT response should be readable");
    assert!(status.starts_with("HTTP/1.1 200"), "{status:?}");
    loop {
        let mut header = String::new();
        timeout(Duration::from_secs(3), reader.read_line(&mut header))
            .await
            .expect("CONNECT headers should arrive")
            .expect("CONNECT header should be readable");
        if header == "\r\n" || header.is_empty() {
            break;
        }
    }
    reader.into_inner()
}

async fn assert_status(socket: &Path, request: &str, expected_codes: &[&str]) {
    let mut stream = UnixStream::connect(socket)
        .await
        .expect("assigned proxy socket should accept a request");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("proxy request should be written");
    let mut reader = BufReader::new(stream);
    let mut status = String::new();
    timeout(Duration::from_secs(3), reader.read_line(&mut status))
        .await
        .expect("proxy rejection should arrive")
        .expect("proxy rejection should be readable");
    assert!(
        expected_codes
            .iter()
            .any(|code| status.split_whitespace().nth(1) == Some(code)),
        "unexpected status for denied request: {status:?}"
    );
}

async fn connect_intercepted_tls(
    socket: &Path,
    authority: &str,
    ca_path: &Path,
) -> tokio_rustls::client::TlsStream<UnixStream> {
    connect_intercepted_tls_with_alpn(socket, authority, ca_path, b"").await
}

async fn connect_intercepted_tls_with_alpn(
    socket: &Path,
    authority: &str,
    ca_path: &Path,
    alpn: &[u8],
) -> tokio_rustls::client::TlsStream<UnixStream> {
    let stream = connect_tunnel(socket, authority).await;
    let mut roots = rustls::RootCertStore::empty();
    let pem = fs::read(ca_path).expect("daemon CA certificate should be readable");
    let (_, certificate) =
        x509_parser::pem::parse_x509_pem(&pem).expect("daemon CA certificate should be PEM");
    roots
        .add(rustls::pki_types::CertificateDer::from(
            certificate.contents,
        ))
        .expect("daemon CA should be a valid TLS trust anchor");
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("TLS versions should be available")
    .with_root_certificates(roots)
    .with_no_client_auth();
    if !alpn.is_empty() {
        config.alpn_protocols = vec![alpn.to_vec()];
    }
    let connector = TlsConnector::from(Arc::new(config));
    timeout(
        Duration::from_secs(4),
        connector.connect(
            rustls::pki_types::ServerName::try_from("localhost".to_owned())
                .expect("localhost should be a valid TLS name"),
            stream,
        ),
    )
    .await
    .expect("intercepted TLS handshake should complete")
    .expect("daemon CA should authenticate the intercepted endpoint")
}

async fn wait_for_path(path: &Path, expected: bool) {
    timeout(Duration::from_secs(3), async {
        loop {
            if path.exists() == expected {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("socket path should reach its expected state");
}

fn tunnel_session(persistent: bool, port: u16) -> String {
    format!(
        "version = 1\noperation = \"create\"\n\n[session]\npersistent = {persistent}\n\n[[rules]]\nhost = \"localhost\"\nmode = \"tunnel\"\nports = [{port}]\n"
    )
}

fn injected_session(host: &str, port: u16, secret: &str) -> String {
    format!(
        "version = 1\noperation = \"create\"\n\n[session]\npersistent = true\n\n[[rules]]\nhost = \"{host}\"\nmode = \"intercept\"\nports = [{port}]\npaths = [\"/allowed\"]\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"{secret}\"\nformat = \"bearer\"\n"
    )
}

fn write_upstream_certificates(directory: &Path) -> (PathBuf, Vec<u8>, Vec<u8>) {
    let root_key = KeyPair::generate().expect("upstream root key should be generated");
    let mut root_parameters = CertificateParams::default();
    root_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root_certificate = root_parameters
        .self_signed(&root_key)
        .expect("upstream root certificate should be generated");
    let root_path = directory.join("upstream-root.pem");
    fs::write(&root_path, root_certificate.pem()).expect("upstream root should be saved");
    let issuer = Issuer::from_ca_cert_pem(&root_certificate.pem(), root_key)
        .expect("upstream root should be a valid issuer");
    let leaf_key = KeyPair::generate().expect("upstream server key should be generated");
    let mut leaf_parameters = CertificateParams::new(vec!["localhost".to_owned()])
        .expect("upstream server certificate parameters should be valid");
    leaf_parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_certificate = leaf_parameters
        .signed_by(&leaf_key, &issuer)
        .expect("upstream server certificate should be signed");
    (
        root_path,
        leaf_certificate.der().to_vec(),
        leaf_key.serialize_der(),
    )
}
