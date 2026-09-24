use std::{fs, net::SocketAddr, sync::Arc, time::Duration};

use baffle_proxy::{
    ca::ManagedCa,
    config::{ControlRequest, SessionConfig},
    proxy_runtime::{ProxyRuntime, ProxyRuntimeEvent, RuntimeId},
};
use hudsucker::rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::mpsc,
    time::timeout,
};

fn session_config() -> SessionConfig {
    let request = ControlRequest::from_toml(
        "version = 1\noperation = \"create\"\n\n[session]\npersistent = true\n\n[[rules]]\nhost = \"example.com\"\nmode = \"tunnel\"\nports = [443]\n",
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
        "deny-all handler should reject {method}: {status:?}"
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
        event_sender.clone(),
    )
    .await
    .expect("first runtime should start");
    let first_address = first.local_addr();
    let second = ProxyRuntime::start(second_id.clone(), session_config(), ca, event_sender)
        .await
        .expect("second runtime should start");
    let second_address = second.local_addr();

    assert!(first_address.ip().is_loopback());
    assert!(second_address.ip().is_loopback());
    assert_ne!(first_address, second_address);
    assert_eq!(first.runtime_id(), &first_id);
    assert_eq!(second.runtime_id(), &second_id);

    assert_denied(first_address, "GET", "http://example.com/").await;
    assert_denied(first_address, "CONNECT", "example.com:443").await;
    assert_denied(second_address, "GET", "http://example.com/").await;

    first.shutdown(Duration::from_secs(2)).await;
    assert_exit(&mut events, &first_id).await;
    assert!(
        TcpStream::connect(first_address).await.is_err(),
        "stopped runtime should close only its own listener"
    );
    assert_denied(second_address, "GET", "http://example.com/").await;

    second.shutdown(Duration::from_secs(2)).await;
    assert_exit(&mut events, &second_id).await;
}
