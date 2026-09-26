use super::*;

#[tokio::test]
async fn tunnel_and_intercept_sessions_run_and_stop_independently() -> Result<(), TestError> {
    let directory = tempfile::tempdir()?;
    let ca = write_managed_ca(directory.path());

    let echo_origin = TcpListener::bind("127.0.0.1:0").await?;
    let echo_port = echo_origin.local_addr()?.port();
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo_origin.accept().await.expect("tunnel should connect");
        for length in [21, 5] {
            let mut payload = vec![0; length];
            stream
                .read_exact(&mut payload)
                .await
                .expect("opaque tunnel payload should arrive");
            stream
                .write_all(&payload)
                .await
                .expect("opaque payload should be echoed");
        }
    });
    let (tunnel_runtime, _tunnel_events) = start_runtime_named(
        directory.path(),
        tunnel_session(echo_port),
        Arc::clone(&ca),
        "rama-tunnel",
        Duration::from_secs(2),
    )
    .await?;

    let (seen_tx, seen_rx) = oneshot::channel();
    let (origin_address, origin_task, _accepted) =
        start_origin(upstream_tls_config("localhost"), seen_tx).await?;
    let (intercept_runtime, _intercept_events) = start_runtime_named(
        directory.path(),
        intercept_session(origin_address.port()),
        Arc::clone(&ca),
        "rama-intercept",
        Duration::from_secs(2),
    )
    .await?;

    let socket_path = tunnel_runtime.socket_path().to_path_buf();
    let mut tunnel = UnixStream::connect(&socket_path).await?;
    tunnel
        .write_all(
            format!(
                "CONNECT localhost:{echo_port} HTTP/1.1\r\nHost: localhost:{echo_port}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;
    let mut tunnel = BufReader::new(tunnel);
    let mut status = String::new();
    timeout(Duration::from_secs(2), tunnel.read_line(&mut status)).await??;
    assert!(status.starts_with("HTTP/1.1 200"));
    loop {
        let mut line = String::new();
        tunnel.read_line(&mut line).await?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
    }
    tunnel.get_mut().write_all(b"opaque tunnel payload").await?;
    let mut echoed = [0; 21];
    timeout(Duration::from_secs(2), tunnel.read_exact(&mut echoed)).await??;
    assert_eq!(&echoed, b"opaque tunnel payload");

    let tunnel_shutdown = tokio::spawn(tunnel_runtime.shutdown(Duration::from_secs(2)));
    timeout(Duration::from_secs(1), async {
        while socket_path.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("shutdown should remove the session socket before draining");
    tunnel.get_mut().write_all(b"still").await?;
    let mut drained = [0; 5];
    timeout(Duration::from_secs(1), tunnel.read_exact(&mut drained)).await??;
    assert_eq!(&drained, b"still");
    drop(tunnel);
    timeout(Duration::from_secs(2), tunnel_shutdown).await??;
    echo_task.abort();

    let port = origin_address.port();
    let mut tls = open_tls_client(
        intercept_runtime.socket_path(),
        &format!("localhost:{port}"),
        &ca,
    )
    .await?;
    tls.write_all(format!("GET /allowed HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes())
        .await?;
    let mut reader = BufReader::new(tls);
    let response = timeout(Duration::from_secs(3), read_http_response(&mut reader)).await??;
    assert!(response.starts_with("HTTP/1.1 200 OKok"));
    assert!(seen_rx.await?.starts_with("GET /allowed HTTP/1.1"));

    origin_task.abort();
    intercept_runtime.shutdown(Duration::from_secs(2)).await;
    Ok(())
}
