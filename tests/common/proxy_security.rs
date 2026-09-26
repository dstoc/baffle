//! Backend-neutral fixtures for tests that drive a live Baffle proxy runtime.

use std::{error::Error, fs, path::Path, sync::Arc, time::Duration};

use baffle_proxy::{
    ca::ManagedCa,
    config::{ControlRequest, SessionConfig},
    proxy_runtime::{ProxyRuntimeEvent, RuntimeId},
};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    sync::mpsc,
    time::timeout,
};
use tokio_rustls::rustls::{
    ClientConfig, RootCertStore, crypto::aws_lc_rs, pki_types::CertificateDer,
};
use tokio_rustls::{TlsConnector, client::TlsStream, rustls::pki_types::ServerName};

pub(crate) fn session_config() -> SessionConfig {
    let request = ControlRequest::from_toml(
        "version = 1\noperation = \"create\"\n\n[session]\npersistent = true\n\n[[rules]]\nhost = \"allowed.example\"\nmode = \"tunnel\"\nports = [443]\n",
    )
    .expect("test session should be valid");
    let ControlRequest::Create { session, .. } = request else {
        panic!("test request should create a session");
    };
    session
}

pub(crate) fn intercept_session_config(port: u16) -> SessionConfig {
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

pub(crate) fn loopback_session_config(port: u16) -> SessionConfig {
    let toml = format!(
        "version = 1\noperation = \"create\"\n\n[session]\npersistent = true\n\n[[rules]]\nhost = \"localhost\"\nmode = \"tunnel\"\nports = [{port}]\n"
    );
    let ControlRequest::Create { session, .. } =
        ControlRequest::from_toml(&toml).expect("loopback session should be valid")
    else {
        panic!("test request should create a session");
    };
    session
}

pub(crate) fn write_test_ca(directory: &std::path::Path) -> Arc<ManagedCa> {
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

pub(crate) fn tls_client_config(ca: &ManagedCa, alpn: &[u8]) -> Arc<ClientConfig> {
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

pub(crate) async fn open_connect_tunnel(
    proxy_path: &Path,
    authority: &str,
) -> Result<UnixStream, Box<dyn Error + Send + Sync>> {
    let (status, stream) = open_connect_response(proxy_path, authority).await?;
    if !status.starts_with("HTTP/1.1 200") {
        return Err(format!("CONNECT failed: {status:?}").into());
    }
    Ok(stream)
}

pub(crate) async fn open_connect_response(
    proxy_path: &Path,
    authority: &str,
) -> Result<(String, UnixStream), Box<dyn Error + Send + Sync>> {
    let mut stream = UnixStream::connect(proxy_path).await?;
    stream
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await?;
    let mut reader = BufReader::new(stream);
    let mut status = String::new();
    timeout(Duration::from_secs(2), reader.read_line(&mut status)).await??;
    loop {
        let mut header = String::new();
        timeout(Duration::from_secs(2), reader.read_line(&mut header)).await??;
        if header == "\r\n" || header.is_empty() {
            break;
        }
    }
    Ok((status, reader.into_inner()))
}

pub(crate) async fn connect_intercepted_tls(
    proxy_path: &Path,
    authority: &str,
    server_name: &str,
    ca: &ManagedCa,
    alpn: &[u8],
) -> Result<TlsStream<UnixStream>, Box<dyn Error + Send + Sync>> {
    let stream = open_connect_tunnel(proxy_path, authority).await?;
    let server_name = ServerName::try_from(server_name.to_owned())?;
    let tls = timeout(
        Duration::from_secs(3),
        TlsConnector::from(tls_client_config(ca, alpn)).connect(server_name, stream),
    )
    .await??;
    Ok(tls)
}

pub(crate) async fn read_http1_status<S>(stream: &mut BufReader<S>) -> std::io::Result<String>
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

pub(crate) async fn assert_denied(path: &Path, method: &str, target: &str) {
    let mut stream = UnixStream::connect(path)
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
    assert_denied_status(&status, &format!("{method} {target}"));
}

pub(crate) fn assert_denied_status(status: &str, context: &str) {
    assert!(
        status.starts_with("HTTP/1.1 400")
            || status.starts_with("HTTP/1.0 400")
            || status.starts_with("HTTP/1.1 403")
            || status.starts_with("HTTP/1.0 403"),
        "proxy should reject {context} before egress, received {status:?}"
    );
}

pub(crate) async fn assert_exit(
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
