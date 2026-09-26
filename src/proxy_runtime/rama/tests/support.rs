use super::*;

pub(super) type TestError = Box<dyn Error + Send + Sync>;

pub(super) fn write_managed_ca(directory: &Path) -> Arc<ManagedCa> {
    let key = KeyPair::generate().expect("Baffle CA key should generate");
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let certificate = params
        .self_signed(&key)
        .expect("Baffle CA certificate should generate");
    let cert_path = directory.join("baffle-ca.pem");
    let key_path = directory.join("baffle-ca-key.pem");
    fs::write(&cert_path, certificate.pem()).expect("Baffle CA certificate should be saved");
    fs::write(&key_path, key.serialize_pem()).expect("Baffle CA key should be saved");
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
        .expect("Baffle CA key should be private");
    Arc::new(
        ManagedCa::load(&crate::config::CaConfig {
            certificate: cert_path,
            private_key: key_path,
        })
        .expect("Baffle CA should load"),
    )
}

pub(super) fn upstream_tls_config(server_name: &str) -> rustls::ServerConfig {
    upstream_tls_config_with_expiration(server_name, false)
}

pub(super) fn upstream_tls_config_with_expiration(
    server_name: &str,
    expired: bool,
) -> rustls::ServerConfig {
    let (root_certificate, root_key, root_der) = upstream_root();
    set_test_upstream_trust_anchor(root_der);
    let root_key = KeyPair::from_pem(&root_key).expect("upstream root key should parse");
    let issuer = Issuer::from_ca_cert_pem(&root_certificate, root_key)
        .expect("upstream root should create an issuer");
    let server_key = KeyPair::generate().expect("upstream key should generate");
    let mut params = CertificateParams::new(vec![server_name.to_owned()])
        .expect("upstream leaf parameters should be valid");
    if expired {
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2021, 1, 1);
    }
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let certificate = params
        .signed_by(&server_key, &issuer)
        .expect("upstream leaf should be signed");
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(certificate.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
        )
        .expect("upstream TLS server should accept its key pair");
    // The relay mirrors the client's negotiated ALPN. Advertising h2 lets
    // the same fixture exercise HTTP/2 on both sides of the live proxy.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
}

pub(super) fn upstream_root() -> (String, String, Vec<u8>) {
    use std::sync::OnceLock;
    static ROOT: OnceLock<(String, String, Vec<u8>)> = OnceLock::new();
    ROOT.get_or_init(|| {
        let key = KeyPair::generate().expect("test upstream CA key should generate");
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let certificate = params
            .self_signed(&key)
            .expect("test upstream CA certificate should generate");
        let der = certificate.der().to_vec();
        (certificate.pem(), key.serialize_pem(), der)
    })
    .clone()
}

pub(super) fn intercept_session(port: u16) -> SessionConfig {
    let input = format!(
        "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"localhost\"\nmode = \"intercept\"\nports = [{port}]\npaths = [\"/allowed\"]\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"proxy-token\"\nformat = \"bearer\"\n"
    );
    let ControlRequest::Create { session, .. } =
        ControlRequest::from_toml(&input).expect("interception session should parse")
    else {
        panic!("expected create request");
    };
    session
}

pub(super) fn intercept_session_with_path(port: u16, path: &str) -> SessionConfig {
    let input = format!(
        "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"localhost\"\nmode = \"intercept\"\nports = [{port}]\npaths = [{path:?}]\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"proxy-token\"\nformat = \"bearer\"\n"
    );
    let ControlRequest::Create { session, .. } =
        ControlRequest::from_toml(&input).expect("interception policy should parse")
    else {
        panic!("expected create request");
    };
    session
}

pub(super) fn tunnel_session(port: u16) -> SessionConfig {
    let input = format!(
        "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"localhost\"\nmode = \"tunnel\"\nports = [{port}]\n"
    );
    let ControlRequest::Create { session, .. } =
        ControlRequest::from_toml(&input).expect("tunnel session should parse")
    else {
        panic!("expected create request");
    };
    session
}

pub(super) async fn start_runtime(
    directory: &Path,
    session: SessionConfig,
    ca: Arc<ManagedCa>,
    timeout: Duration,
) -> Result<(ProxyRuntime, mpsc::UnboundedReceiver<ProxyRuntimeEvent>), TestError> {
    start_runtime_named(directory, session, ca, "rama-test", timeout).await
}

pub(super) async fn start_runtime_named(
    directory: &Path,
    session: SessionConfig,
    ca: Arc<ManagedCa>,
    name: &str,
    timeout: Duration,
) -> Result<(ProxyRuntime, mpsc::UnboundedReceiver<ProxyRuntimeEvent>), TestError> {
    start_runtime_limited(directory, session, ca, name, 8, timeout).await
}

pub(super) async fn start_runtime_limited(
    directory: &Path,
    session: SessionConfig,
    ca: Arc<ManagedCa>,
    name: &str,
    max_connections: usize,
    timeout: Duration,
) -> Result<(ProxyRuntime, mpsc::UnboundedReceiver<ProxyRuntimeEvent>), TestError> {
    let (events_tx, events_rx) = mpsc::unbounded_channel();
    let runtime = ProxyRuntime::start_with_metrics(
        RuntimeId::new(name),
        session,
        Arc::new(ResolvedSecrets::from_values([(
            "proxy-token".to_owned(),
            "test-credential".to_owned(),
        )])),
        ca,
        directory.join(format!("{name}.sock")),
        max_connections,
        timeout,
        Arc::new(crate::telemetry::Metrics::default()),
        events_tx,
    )
    .await?;
    Ok((runtime, events_rx))
}

pub(super) async fn start_origin(
    config: rustls::ServerConfig,
    seen: oneshot::Sender<String>,
) -> Result<
    (
        std::net::SocketAddr,
        tokio::task::JoinHandle<()>,
        oneshot::Receiver<()>,
    ),
    TestError,
> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (accepted_tx, accepted_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("origin should accept");
        let _ = accepted_tx.send(());
        let tls = TlsAcceptor::from(Arc::new(config))
            .accept(stream)
            .await
            .expect("BoringSSL should establish TLS with the origin");
        let mut reader = BufReader::new(tls);
        let mut request_line = String::new();
        reader
            .read_line(&mut request_line)
            .await
            .expect("origin request line should be readable");
        let mut authorization = String::new();
        loop {
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .await
                .expect("origin header should be readable");
            if line == "\r\n" || line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':')
                && name.eq_ignore_ascii_case("authorization")
            {
                authorization = value.trim().to_owned();
            }
        }
        let _ = seen.send(format!("{request_line}{authorization}"));
        tokio::time::sleep(Duration::from_millis(200)).await;
        reader
            .get_mut()
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok")
            .await
            .expect("origin response should be written");
        // Keep the connection open so the client can exercise a second
        // request on the same intercepted TLS connection.
        let mut second = String::new();
        if reader.read_line(&mut second).await.unwrap_or_default() > 0 {
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).await.unwrap_or_default() == 0 || line == "\r\n" {
                    break;
                }
            }
            let _ = reader
                .get_mut()
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
                )
                .await;
        }
    });
    Ok((address, task, accepted_rx))
}

pub(super) async fn open_tls_client(
    proxy: &Path,
    authority: &str,
    ca: &ManagedCa,
) -> Result<tokio_rustls::client::TlsStream<UnixStream>, TestError> {
    open_tls_client_for_name(proxy, authority, "localhost", ca).await
}

pub(super) async fn open_tls_client_for_name(
    proxy: &Path,
    authority: &str,
    server_name: &str,
    ca: &ManagedCa,
) -> Result<tokio_rustls::client::TlsStream<UnixStream>, TestError> {
    open_tls_client_with_alpn(proxy, authority, server_name, ca, &[], &[]).await
}

pub(super) async fn open_tls_client_with_alpn(
    proxy: &Path,
    authority: &str,
    server_name: &str,
    ca: &ManagedCa,
    alpn: &[&[u8]],
    extra_roots: &[Vec<u8>],
) -> Result<tokio_rustls::client::TlsStream<UnixStream>, TestError> {
    let mut stream = UnixStream::connect(proxy).await?;
    stream
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await?;
    let mut reader = BufReader::new(stream);
    let mut status = String::new();
    timeout(Duration::from_secs(2), reader.read_line(&mut status)).await??;
    if !status.starts_with("HTTP/1.1 200") {
        return Err(format!("CONNECT failed: {status}").into());
    }
    loop {
        let mut line = String::new();
        timeout(Duration::from_secs(2), reader.read_line(&mut line)).await??;
        if line == "\r\n" || line.is_empty() {
            break;
        }
    }

    let (_, parsed_ca) = x509_parser::pem::parse_x509_pem(ca.public_certificate_pem())?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(parsed_ca.contents))?;
    for root in extra_roots {
        roots.add(CertificateDer::from(root.clone()))?;
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    let connector = TlsConnector::from(Arc::new(config));
    Ok(connector
        .connect(
            rustls::pki_types::ServerName::try_from(server_name.to_owned())?,
            reader.into_inner(),
        )
        .await?)
}

pub(super) async fn start_http2_origin(
    config: rustls::ServerConfig,
    seen: tokio::sync::mpsc::UnboundedSender<(String, String, String)>,
) -> Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>), TestError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("origin should accept");
        let tls = TlsAcceptor::from(Arc::new(config))
            .accept(stream)
            .await
            .expect("origin should establish TLS");
        assert_eq!(
            tls.get_ref().1.alpn_protocol(),
            Some(b"h2".as_slice()),
            "the proxy must negotiate HTTP/2 with the origin"
        );
        let service = rama::service::service_fn(
            move |request: rama::http::Request<rama::http::core::body::Incoming>| {
                let sender = seen.clone();
                async move {
                    let path = request
                        .uri()
                        .path()
                        .map(|path| path.to_string())
                        .unwrap_or_default();
                    let authority = request
                        .uri()
                        .authority()
                        .map(|authority| authority.to_string())
                        .unwrap_or_default();
                    let authorization = request
                        .headers()
                        .get(rama::http::header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default()
                        .to_owned();
                    let _ = sender.send((path, authority, authorization));
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    Ok::<_, std::convert::Infallible>(
                        rama::http::Response::builder()
                            .status(rama::http::StatusCode::OK)
                            .body(rama::http::Body::empty())
                            .expect("origin response should build"),
                    )
                }
            },
        );
        rama::http::core::server::conn::http2::Builder::new(rama::rt::Executor::default())
            .serve_connection(rama::ServiceInput::new(tls), service)
            .await
            .expect("origin HTTP/2 connection should complete");
    });
    Ok((address, task))
}

pub(super) fn h2_request(
    uri: String,
    host: String,
    authorization: Option<&str>,
) -> rama::http::Request {
    let mut request = rama::http::Request::builder()
        .method(rama::http::Method::GET)
        .version(rama::http::Version::HTTP_2)
        .uri(uri)
        .header(rama::http::header::HOST, host);
    if let Some(authorization) = authorization {
        request = request.header(rama::http::header::AUTHORIZATION, authorization);
    }
    request
        .body(rama::http::Body::empty())
        .expect("HTTP/2 request should build")
}

pub(super) struct FragmentFirstWrite<T> {
    inner: T,
    first_byte_written: bool,
    remainder_delay: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<T> FragmentFirstWrite<T> {
    pub(super) fn new(inner: T) -> Self {
        Self {
            inner,
            first_byte_written: false,
            remainder_delay: None,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for FragmentFirstWrite<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for FragmentFirstWrite<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !self.first_byte_written {
            match Pin::new(&mut self.inner).poll_write(context, &buffer[..1]) {
                Poll::Ready(Ok(written)) => {
                    self.first_byte_written = true;
                    self.remainder_delay =
                        Some(Box::pin(tokio::time::sleep(Duration::from_millis(75))));
                    return Poll::Ready(Ok(written));
                }
                result => return result,
            }
        }
        if let Some(delay) = self.remainder_delay.as_mut() {
            if delay.as_mut().poll(context).is_pending() {
                return Poll::Pending;
            }
            self.remainder_delay = None;
        }
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

pub(super) async fn read_http_response<S>(reader: &mut BufReader<S>) -> io::Result<String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut status = String::new();
    reader.read_line(&mut status).await?;
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).await?;
    Ok(format!(
        "{}{}",
        status.trim(),
        String::from_utf8_lossy(&body)
    ))
}
