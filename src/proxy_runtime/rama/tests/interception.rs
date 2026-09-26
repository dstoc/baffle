use super::*;

#[tokio::test]
async fn interception_closes_non_tls_and_fragmented_client_hellos() -> Result<(), TestError> {
    let directory = tempfile::tempdir()?;
    let ca = write_managed_ca(directory.path());
    let upstream = TcpListener::bind("127.0.0.1:0").await?;
    let port = upstream.local_addr()?.port();
    let (runtime, _events) = start_runtime(
        directory.path(),
        intercept_session(port),
        ca,
        Duration::from_millis(100),
    )
    .await?;

    let mut unsupported = UnixStream::connect(runtime.socket_path()).await?;
    unsupported
            .write_all(
                format!(
                    "CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\nContent-Length: 1\r\n\r\nx"
                )
                .as_bytes(),
            )
            .await?;
    let mut response = BufReader::new(unsupported);
    let mut status = String::new();
    timeout(Duration::from_secs(1), response.read_line(&mut status)).await??;
    assert!(
        status.starts_with("HTTP/1.1 400"),
        "CONNECT bodies must be rejected"
    );

    for payload in [
        b"not TLS".as_slice(),
        &[0x16, 0x03, 0x03, 0x00, 0x20, 0x01, 0x00],
    ] {
        let mut stream = UnixStream::connect(runtime.socket_path()).await?;
        stream
            .write_all(
                format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n")
                    .as_bytes(),
            )
            .await?;
        let mut reader = BufReader::new(stream);
        let mut status = String::new();
        timeout(Duration::from_secs(1), reader.read_line(&mut status)).await??;
        assert!(status.starts_with("HTTP/1.1 200"));
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            if line == "\r\n" || line.is_empty() {
                break;
            }
        }
        reader.get_mut().write_all(payload).await?;
        let mut byte = [0u8; 1];
        match timeout(Duration::from_secs(1), reader.read(&mut byte)).await {
            Ok(Ok(0)) => (),
            Ok(Err(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::BrokenPipe
                        | io::ErrorKind::UnexpectedEof
                ) =>
            {
                // Closing without a TLS close-notify can reset the TCP stream.
            }
            other => {
                panic!("failed TLS inspection returned tunnel bytes or stayed open: {other:?}")
            }
        }
    }

    runtime.shutdown(Duration::from_secs(2)).await;
    Ok(())
}

#[tokio::test]
async fn valid_client_hello_split_after_one_byte_is_inspected_before_forwarding()
-> Result<(), TestError> {
    let directory = tempfile::tempdir()?;
    let ca = write_managed_ca(directory.path());
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_address = upstream_listener.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (stream, _) = upstream_listener
            .accept()
            .await
            .expect("upstream should accept the proxy connection");
        let tls = TlsAcceptor::from(Arc::new(upstream_tls_config("localhost")))
            .accept(stream)
            .await
            .expect("upstream TLS should complete");
        let mut tls = tls;
        let mut request = [0; 512];
        match timeout(Duration::from_millis(500), tls.read(&mut request)).await {
            Ok(Ok(read)) if read > 0 => Some(request[..read].to_vec()),
            _ => None,
        }
    });
    let (runtime, _) = start_runtime(
        directory.path(),
        intercept_session(upstream_address.port()),
        Arc::clone(&ca),
        Duration::from_secs(2),
    )
    .await?;

    let authority = format!("localhost:{}", upstream_address.port());
    let mut connect = UnixStream::connect(runtime.socket_path()).await?;
    connect
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await?;
    let mut connect = BufReader::new(connect);
    let mut status = String::new();
    timeout(Duration::from_secs(2), connect.read_line(&mut status)).await??;
    assert!(status.starts_with("HTTP/1.1 200"));
    loop {
        let mut line = String::new();
        connect.read_line(&mut line).await?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
    }

    let (_, parsed_ca) = x509_parser::pem::parse_x509_pem(ca.public_certificate_pem())?;
    let (_, _, upstream_root) = upstream_root();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(parsed_ca.contents))?;
    roots.add(CertificateDer::from(upstream_root))?;
    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls = TlsConnector::from(Arc::new(client_config))
        .connect(
            rustls::pki_types::ServerName::try_from("localhost".to_owned())?,
            FragmentFirstWrite::new(connect.into_inner()),
        )
        .await;

    if let Ok(mut tls) = tls {
        tls.write_all(
            format!("GET /blocked HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
        let mut reader = BufReader::new(tls);
        let mut response = String::new();
        timeout(Duration::from_secs(2), reader.read_line(&mut response)).await??;
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "a valid fragmented ClientHello must reach path policy: {response:?}"
        );
    }

    let origin_request = timeout(Duration::from_secs(2), upstream_task).await??;
    assert!(
        origin_request.is_none(),
        "an interception-required fragmented ClientHello must not turn into an opaque tunnel"
    );
    runtime.shutdown(Duration::from_secs(2)).await;
    Ok(())
}

#[tokio::test]
async fn rejects_tls_sni_that_does_not_match_connect_authority() -> Result<(), TestError> {
    let directory = tempfile::tempdir()?;
    let ca = write_managed_ca(directory.path());
    let upstream = TcpListener::bind("127.0.0.1:0").await?;
    let port = upstream.local_addr()?.port();
    let (runtime, _events) = start_runtime(
        directory.path(),
        intercept_session(port),
        ca.clone(),
        Duration::from_secs(1),
    )
    .await?;

    let result = open_tls_client_for_name(
        runtime.socket_path(),
        &format!("localhost:{port}"),
        "other.example",
        &ca,
    )
    .await;
    assert!(
        result.is_err(),
        "mismatched SNI must not establish interception"
    );
    runtime.shutdown(Duration::from_secs(2)).await;
    Ok(())
}

#[tokio::test]
async fn rejects_upstream_certificate_hostname_mismatch_through_running_proxy()
-> Result<(), TestError> {
    let directory = tempfile::tempdir()?;
    let ca = write_managed_ca(directory.path());
    let (seen_tx, _seen_rx) = oneshot::channel();
    let (origin_address, origin_task, accepted) =
        start_origin(upstream_tls_config("other.example"), seen_tx).await?;
    let port = origin_address.port();
    let (runtime, _events) = start_runtime(
        directory.path(),
        intercept_session(port),
        Arc::clone(&ca),
        Duration::from_secs(2),
    )
    .await?;
    if let Ok(mut tls) =
        open_tls_client(runtime.socket_path(), &format!("localhost:{port}"), &ca).await
    {
        tls.write_all(
            format!("GET /allowed HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes(),
        )
        .await?;
        let mut byte = [0u8; 1];
        let result = timeout(Duration::from_secs(3), tls.read(&mut byte)).await?;
        assert!(
            result.is_err() || result? == 0,
            "mismatched upstream identity must not return data"
        );
    }
    timeout(Duration::from_secs(2), accepted).await??;
    origin_task.abort();
    runtime.shutdown(Duration::from_secs(2)).await;
    Ok(())
}

#[tokio::test]
async fn rejects_expired_upstream_certificate_through_running_proxy() -> Result<(), TestError> {
    let directory = tempfile::tempdir()?;
    let ca = write_managed_ca(directory.path());
    let (seen_tx, _seen_rx) = oneshot::channel();
    let (origin_address, origin_task, accepted) = start_origin(
        upstream_tls_config_with_expiration("localhost", true),
        seen_tx,
    )
    .await?;
    let port = origin_address.port();
    let (runtime, _events) = start_runtime(
        directory.path(),
        intercept_session(port),
        Arc::clone(&ca),
        Duration::from_secs(2),
    )
    .await?;
    if let Ok(mut tls) =
        open_tls_client(runtime.socket_path(), &format!("localhost:{port}"), &ca).await
    {
        tls.write_all(
            format!("GET /allowed HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes(),
        )
        .await?;
        let mut byte = [0u8; 1];
        let result = timeout(Duration::from_secs(3), tls.read(&mut byte)).await?;
        assert!(
            result.is_err() || result? == 0,
            "expired upstream identity must not return data"
        );
    }
    timeout(Duration::from_secs(2), accepted).await??;
    origin_task.abort();
    runtime.shutdown(Duration::from_secs(2)).await;
    Ok(())
}
