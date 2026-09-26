use super::*;

#[tokio::test]
async fn intercepted_session_forwards_allowed_https_and_injects_daemon_secret()
-> Result<(), TestError> {
    let directory = tempfile::tempdir()?;
    let ca = write_managed_ca(directory.path());
    let (seen_tx, seen_rx) = oneshot::channel();
    let (origin_address, origin_task, _accepted) =
        start_origin(upstream_tls_config("localhost"), seen_tx).await?;
    let port = origin_address.port();
    let (runtime, _events) = start_runtime(
        directory.path(),
        intercept_session(port),
        Arc::clone(&ca),
        Duration::from_secs(2),
    )
    .await?;
    let mut tls = open_tls_client(runtime.socket_path(), &format!("localhost:{port}"), &ca).await?;
    tls.write_all(
            format!(
                "GET /allowed HTTP/1.1\r\nHost: localhost:{port}\r\nAuthorization: Bearer attacker-value\r\nConnection: keep-alive\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;
    let mut reader = BufReader::new(tls);
    let observed = seen_rx.await?;
    assert!(observed.starts_with("GET /allowed HTTP/1.1"));
    assert!(observed.contains("Bearer test-credential"));
    let replacement = intercept_session_with_path(port, "/blocked");
    runtime
        .replace_generation(
            &replacement,
            Arc::new(ResolvedSecrets::from_values([(
                "proxy-token".to_owned(),
                "rotated-test-credential".to_owned(),
            )])),
        )
        .expect("same-path HTTP/1.1 cutover should fit within the generation limit");
    let response = timeout(Duration::from_secs(3), read_http_response(&mut reader)).await??;
    assert!(
        response.starts_with("HTTP/1.1 200 OKok"),
        "unexpected origin response: {response}"
    );

    reader
        .get_mut()
        .write_all(format!("GET /blocked HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes())
        .await?;
    let denied = timeout(Duration::from_secs(3), read_http_response(&mut reader)).await??;
    assert!(
        denied.starts_with("HTTP/1.1 403"),
        "unexpected denied response: {denied}"
    );

    reader
        .get_mut()
        .write_all(
            format!("GET /allowed HTTP/1.1\r\nHost: other.example:{port}\r\n\r\n").as_bytes(),
        )
        .await?;
    let mismatched = timeout(Duration::from_secs(3), read_http_response(&mut reader)).await??;
    assert!(
        mismatched.starts_with("HTTP/1.1 400"),
        "decrypted HTTP authority must remain bound to CONNECT: {mismatched}"
    );

    reader
        .get_mut()
        .write_all(b"GET /allowed HTTP/1.1\r\nConnection: close\r\n\r\n")
        .await?;
    let missing_host = timeout(Duration::from_secs(3), read_http_response(&mut reader)).await??;
    assert!(
        missing_host.starts_with("HTTP/1.1 400"),
        "an intercepted HTTP/1.1 request without Host must be rejected: {missing_host}"
    );

    drop(reader);
    origin_task.abort();
    runtime.shutdown(Duration::from_secs(2)).await;
    Ok(())
}

#[tokio::test]
async fn rejects_plaintext_forward_http_before_dialing_the_origin() -> Result<(), TestError> {
    let directory = tempfile::tempdir()?;
    let ca = write_managed_ca(directory.path());
    let upstream = TcpListener::bind("127.0.0.1:0").await?;
    let port = upstream.local_addr()?.port();
    let (runtime, _) = start_runtime(
        directory.path(),
        intercept_session(port),
        ca,
        Duration::from_secs(1),
    )
    .await?;

    let mut client = UnixStream::connect(runtime.socket_path()).await?;
    client
        .write_all(
            format!(
                "GET http://localhost:{port}/allowed HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;
    let mut reader = BufReader::new(client);
    let mut status = String::new();
    timeout(Duration::from_secs(1), reader.read_line(&mut status)).await??;
    assert!(status.starts_with("HTTP/1.1 400"));
    assert!(
        timeout(Duration::from_millis(150), upstream.accept())
            .await
            .is_err(),
        "plaintext forward HTTP must not cause an upstream connection"
    );

    runtime.shutdown(Duration::from_secs(1)).await;
    Ok(())
}

#[tokio::test]
async fn intercepted_http2_streams_apply_path_authority_and_injection_policy()
-> Result<(), TestError> {
    let directory = tempfile::tempdir()?;
    let ca = write_managed_ca(directory.path());
    let (seen_sender, mut seen) = mpsc::unbounded_channel();
    let (origin_address, origin_task) =
        start_http2_origin(upstream_tls_config("localhost"), seen_sender).await?;
    let port = origin_address.port();
    let authority = format!("localhost:{port}");
    let (runtime, _) = start_runtime(
        directory.path(),
        intercept_session(port),
        Arc::clone(&ca),
        Duration::from_secs(2),
    )
    .await?;
    let tls = open_tls_client_with_alpn(
        runtime.socket_path(),
        &authority,
        "localhost",
        &ca,
        &[b"h2"],
        &[],
    )
    .await?;
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (mut sender, connection) =
        rama::http::core::client::conn::http2::handshake::<_, rama::http::Body>(
            rama::rt::Executor::default(),
            rama::ServiceInput::new(tls),
        )
        .await?;
    let driver = tokio::spawn(connection);

    let request_one = h2_request(
        format!("https://{authority}/allowed"),
        authority.clone(),
        Some("Bearer attacker-one"),
    );
    let request_two = h2_request(
        format!("https://{authority}/allowed"),
        authority.clone(),
        Some("Bearer attacker-two"),
    );
    let request_denied = h2_request(
        format!("https://{authority}/blocked"),
        authority.clone(),
        Some("Bearer attacker-denied"),
    );
    let request_mismatched = h2_request(
        format!("https://example.org:{port}/allowed"),
        authority.clone(),
        Some("Bearer attacker-mismatched"),
    );

    sender.ready().await?;
    let mut sender_one = sender.clone();
    let mut sender_two = sender.clone();
    let mut sender_denied = sender.clone();
    let mut sender_mismatched = sender.clone();
    sender_one.ready().await?;
    sender_two.ready().await?;
    sender_denied.ready().await?;
    sender_mismatched.ready().await?;
    let (one, two, denied, mismatched) = tokio::join!(
        timeout(Duration::from_secs(3), sender_one.send_request(request_one)),
        timeout(Duration::from_secs(3), sender_two.send_request(request_two)),
        timeout(
            Duration::from_secs(3),
            sender_denied.send_request(request_denied)
        ),
        timeout(
            Duration::from_secs(3),
            sender_mismatched.send_request(request_mismatched)
        ),
    );
    let one = one??;
    let two = two??;
    let denied = denied??;
    let mismatched = mismatched??;
    assert_eq!(one.status(), rama::http::StatusCode::OK);
    assert_eq!(two.status(), rama::http::StatusCode::OK);
    assert_eq!(denied.status(), rama::http::StatusCode::FORBIDDEN);
    assert_eq!(mismatched.status(), rama::http::StatusCode::BAD_REQUEST);

    for path in ["/allowedness", "/allowed%2fprivate", "/%2e%2e/allowed"] {
        sender_denied.ready().await?;
        let request = h2_request(
            format!("https://{authority}{path}"),
            authority.clone(),
            Some("Bearer attacker-path"),
        );
        let response =
            timeout(Duration::from_secs(3), sender_denied.send_request(request)).await??;
        assert!(
            response.status() == rama::http::StatusCode::BAD_REQUEST
                || response.status() == rama::http::StatusCode::FORBIDDEN,
            "unsafe path {path:?} must be rejected: {}",
            response.status()
        );
    }

    sender_denied.ready().await?;
    let wrong_scheme = h2_request(
        format!("http://{authority}/allowed"),
        authority.clone(),
        Some("Bearer attacker-scheme"),
    );
    let wrong_scheme = timeout(
        Duration::from_secs(3),
        sender_denied.send_request(wrong_scheme),
    )
    .await??;
    assert_eq!(
        wrong_scheme.status(),
        rama::http::StatusCode::BAD_REQUEST,
        "HTTP/2 :scheme http must not enter intercepted HTTPS policy"
    );

    for _ in 0..2 {
        let (path, seen_authority, authorization) = timeout(Duration::from_secs(2), seen.recv())
            .await?
            .ok_or_else(|| io::Error::other("origin event channel should remain open"))?;
        assert_eq!(path, "/allowed");
        assert_eq!(seen_authority, authority);
        assert_eq!(authorization, "Bearer test-credential");
        assert!(!authorization.contains("attacker"));
    }
    assert!(
        timeout(Duration::from_millis(150), seen.recv())
            .await
            .is_err(),
        "denied paths and mismatched authorities must not reach the origin"
    );

    // Hold an HTTP/2 stream in the origin, then switch the listener's
    // active generation. The stream must finish under its connection's
    // original path and credential policy.
    sender.ready().await?;
    let mut pending_sender = sender.clone();
    let pending_request = h2_request(
        format!("https://{authority}/allowed"),
        authority.clone(),
        Some("Bearer attacker-inflight"),
    );
    let pending = tokio::spawn(async move { pending_sender.send_request(pending_request).await });
    let (path, seen_authority, authorization) = timeout(Duration::from_secs(2), seen.recv())
        .await?
        .ok_or_else(|| io::Error::other("origin should start the in-flight stream"))?;
    assert_eq!(path, "/allowed");
    assert_eq!(seen_authority, authority);
    assert_eq!(authorization, "Bearer test-credential");
    let replacement = intercept_session_with_path(port, "/blocked");
    runtime
        .replace_generation(
            &replacement,
            Arc::new(ResolvedSecrets::from_values([(
                "proxy-token".to_owned(),
                "rotated-test-credential".to_owned(),
            )])),
        )
        .expect("one previous generation should fit within the limit");
    let response = timeout(Duration::from_secs(2), pending).await???;
    assert_eq!(response.status(), rama::http::StatusCode::OK);

    drop(sender);
    driver.abort();
    origin_task.abort();
    runtime.shutdown(Duration::from_secs(2)).await;
    Ok(())
}
