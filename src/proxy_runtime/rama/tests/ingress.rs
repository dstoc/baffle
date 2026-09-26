use super::*;

#[tokio::test]
async fn unix_listener_enforces_the_configured_connection_limit() -> Result<(), TestError> {
    let directory = tempfile::tempdir()?;
    let ca = write_managed_ca(directory.path());
    let (runtime, _) = start_runtime_limited(
        directory.path(),
        tunnel_session(443),
        ca,
        "rama-unix-limited",
        1,
        Duration::from_secs(2),
    )
    .await?;

    let mut admitted = UnixStream::connect(runtime.socket_path()).await?;
    admitted.write_all(b"C").await?;
    tokio::time::sleep(Duration::from_millis(25)).await;
    let mut over_limit = UnixStream::connect(runtime.socket_path()).await?;
    let mut byte = [0; 1];
    let read = timeout(Duration::from_secs(1), over_limit.read(&mut byte)).await??;
    assert_eq!(read, 0, "over-limit Unix clients must be closed");

    drop(admitted);
    runtime.shutdown(Duration::from_secs(1)).await;
    Ok(())
}

#[tokio::test]
async fn nested_socket_directories_are_private_and_removed_on_shutdown() -> Result<(), TestError> {
    let directory = tempfile::tempdir()?;
    let ca = write_managed_ca(directory.path());
    let path = directory.path().join("cladding/github.sock");
    let (events, _) = mpsc::unbounded_channel();
    let runtime = ProxyRuntime::start(
        RuntimeId::new("rama-nested-socket"),
        tunnel_session(443),
        ca,
        path.clone(),
        4,
        events,
    )
    .await?;
    assert!(path.exists());
    assert_eq!(
        fs::metadata(path.parent().expect("named socket has a parent"))?
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert!(UnixStream::connect(&path).await.is_ok());
    runtime.shutdown(Duration::from_secs(1)).await;
    assert!(!path.exists());
    assert!(!path.parent().expect("named socket has a parent").exists());
    Ok(())
}

#[tokio::test]
async fn nested_socket_parent_symlink_is_rejected() -> Result<(), TestError> {
    let directory = tempfile::tempdir()?;
    let target = tempfile::tempdir()?;
    let ca = write_managed_ca(directory.path());
    let link = directory.path().join("cladding");
    std::os::unix::fs::symlink(target.path(), &link)?;
    let path = link.join("github.sock");
    let (events, _) = mpsc::unbounded_channel();
    let result = ProxyRuntime::start(
        RuntimeId::new("rama-symlink-socket"),
        tunnel_session(443),
        ca,
        path.clone(),
        4,
        events,
    )
    .await;
    assert!(result.is_err());
    assert!(!target.path().join("github.sock").exists());
    assert!(fs::symlink_metadata(link)?.file_type().is_symlink());
    Ok(())
}

#[tokio::test]
async fn renamed_socket_parent_cleanup_leaves_replacement_path_untouched() -> Result<(), TestError>
{
    let directory = tempfile::tempdir()?;
    let ca = write_managed_ca(directory.path());
    let original_parent = directory.path().join("cladding");
    let path = original_parent.join("github.sock");
    let (events, _) = mpsc::unbounded_channel();
    let runtime = ProxyRuntime::start(
        RuntimeId::new("rama-renamed-socket-parent"),
        tunnel_session(443),
        ca,
        path,
        4,
        events,
    )
    .await?;
    let renamed_parent = directory.path().join("cladding-old");
    fs::rename(&original_parent, &renamed_parent)?;
    fs::create_dir(&original_parent)?;
    let replacement = original_parent.join("github.sock");
    fs::write(&replacement, b"replacement")?;

    runtime.shutdown(Duration::from_secs(1)).await;
    assert!(!renamed_parent.join("github.sock").exists());
    assert_eq!(fs::read(replacement)?, b"replacement");
    Ok(())
}

#[tokio::test]
async fn startup_rejects_an_existing_socket_path_without_replacing_it() -> Result<(), TestError> {
    let directory = tempfile::tempdir()?;
    let ca = write_managed_ca(directory.path());
    let socket_path = directory.path().join("occupied.sock");
    fs::write(&socket_path, b"owned by another process")?;
    let (events, _receiver) = mpsc::unbounded_channel();
    let result = ProxyRuntime::start_with_metrics(
        RuntimeId::new("rama-startup-conflict"),
        tunnel_session(443),
        Arc::new(ResolvedSecrets::default()),
        ca,
        socket_path.clone(),
        4,
        Duration::from_secs(1),
        Arc::new(crate::telemetry::Metrics::default()),
        events,
    )
    .await;
    assert!(
        result.is_err(),
        "startup must fail when the configured socket path already exists"
    );
    assert_eq!(fs::read(socket_path)?, b"owned by another process");
    Ok(())
}

#[tokio::test]
async fn direct_listener_task_failure_is_reported_to_the_session_event_channel()
-> Result<(), TestError> {
    let directory = tempfile::tempdir()?;
    let ca = write_managed_ca(directory.path());
    let (runtime, mut events) = start_runtime(
        directory.path(),
        tunnel_session(443),
        ca,
        Duration::from_secs(1),
    )
    .await?;
    let id = runtime.runtime_id().clone();

    runtime.task_abort.abort();
    let event = timeout(Duration::from_secs(2), events.recv())
        .await?
        .ok_or_else(|| io::Error::other("session event channel should remain open"))?;
    assert_eq!(event.runtime_id, id);
    assert!(
        event.result.is_err(),
        "listener task failure must reach the supervisor"
    );
    runtime.shutdown(Duration::from_secs(1)).await;
    Ok(())
}

#[tokio::test]
async fn cancelling_shutdown_with_an_active_tunnel_aborts_tasks_and_cleans_up()
-> Result<(), TestError> {
    let directory = tempfile::tempdir()?;
    let ca = write_managed_ca(directory.path());
    let origin = TcpListener::bind("127.0.0.1:0").await?;
    let port = origin.local_addr()?.port();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.expect("origin should accept");
        let mut byte = [0; 1];
        let _ = stream.read(&mut byte).await;
    });
    let (runtime, mut events) = start_runtime_named(
        directory.path(),
        tunnel_session(port),
        ca,
        "rama-cancel-shutdown",
        Duration::from_secs(30),
    )
    .await?;
    let local_address = runtime.socket_path().to_path_buf();
    let socket_path = runtime.socket_path().to_path_buf();
    let runtime_id = runtime.runtime_id().clone();
    let mut tunnel = UnixStream::connect(&socket_path).await?;
    tunnel
        .write_all(
            format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n")
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

    let shutdown = tokio::spawn(runtime.shutdown(Duration::from_secs(10)));
    tokio::task::yield_now().await;
    shutdown.abort();
    let _ = shutdown.await;

    timeout(Duration::from_secs(2), async {
        while socket_path.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert!(UnixStream::connect(local_address).await.is_err());
    let mut byte = [0; 1];
    let read = timeout(Duration::from_secs(1), tunnel.read(&mut byte)).await?;
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "active tunnel should close when its session owner is cancelled"
    );
    let event = timeout(Duration::from_secs(2), events.recv())
        .await?
        .ok_or_else(|| io::Error::other("session event channel should remain open"))?;
    assert_eq!(event.runtime_id, runtime_id);
    assert!(
        event.result.is_err(),
        "cancelled proxy task failure must propagate to the session registry"
    );
    origin_task.abort();
    Ok(())
}

#[tokio::test]
async fn cancelling_shutdown_with_an_inflight_intercepted_request_closes_it()
-> Result<(), TestError> {
    let directory = tempfile::tempdir()?;
    let ca = write_managed_ca(directory.path());
    let origin = TcpListener::bind("127.0.0.1:0").await?;
    let port = origin.local_addr()?.port();
    let (request_seen_sender, request_seen) = oneshot::channel();
    let (release_origin, release_origin_rx) = oneshot::channel::<()>();
    let origin_task = tokio::spawn(async move {
        let (stream, _) = origin.accept().await.expect("origin should accept");
        let tls = TlsAcceptor::from(Arc::new(upstream_tls_config("localhost")))
            .accept(stream)
            .await
            .expect("origin should establish TLS");
        let mut reader = BufReader::new(tls);
        let mut request_line = String::new();
        reader
            .read_line(&mut request_line)
            .await
            .expect("origin request line should be readable");
        loop {
            let mut header = String::new();
            reader
                .read_line(&mut header)
                .await
                .expect("origin request headers should be readable");
            if header == "\r\n" || header.is_empty() {
                break;
            }
        }
        let _ = request_seen_sender.send(request_line);
        let _ = release_origin_rx.await;
        let _ = reader
            .get_mut()
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await;
    });
    let (runtime, mut events) = start_runtime_named(
        directory.path(),
        intercept_session(port),
        Arc::clone(&ca),
        "rama-cancel-intercept",
        Duration::from_secs(30),
    )
    .await?;
    let local_address = runtime.socket_path().to_path_buf();
    let socket_path = runtime.socket_path().to_path_buf();
    let runtime_id = runtime.runtime_id().clone();
    let mut client = open_tls_client(&local_address, &format!("localhost:{port}"), &ca).await?;
    client
        .write_all(format!("GET /allowed HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes())
        .await?;
    let request_line = timeout(Duration::from_secs(2), request_seen)
        .await?
        .map_err(|_| io::Error::other("origin did not receive the intercepted request"))?;
    assert!(request_line.starts_with("GET /allowed HTTP/1.1"));

    let shutdown = tokio::spawn(runtime.shutdown(Duration::from_secs(10)));
    tokio::task::yield_now().await;
    shutdown.abort();
    let _ = shutdown.await;

    timeout(Duration::from_secs(2), async {
        while socket_path.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert!(UnixStream::connect(local_address).await.is_err());
    let mut byte = [0; 1];
    match timeout(Duration::from_secs(1), client.read(&mut byte)).await? {
        Ok(0) | Err(_) => (),
        other => panic!("cancelled intercepted connection remained open: {other:?}"),
    }
    let event = timeout(Duration::from_secs(2), events.recv())
        .await?
        .ok_or_else(|| io::Error::other("session event channel should remain open"))?;
    assert_eq!(event.runtime_id, runtime_id);
    assert!(
        event.result.is_err(),
        "cancelled proxy task failure must propagate to the session registry"
    );
    drop(release_origin);
    origin_task.abort();
    Ok(())
}

#[tokio::test]
async fn proxy_task_failure_is_reported_to_the_session_event_channel() -> Result<(), TestError> {
    let directory = tempfile::tempdir()?;
    let ca = write_managed_ca(directory.path());
    let (runtime, mut events) = start_runtime(
        directory.path(),
        tunnel_session(443),
        ca,
        Duration::from_secs(1),
    )
    .await?;

    runtime.task_abort.abort();
    let event = timeout(Duration::from_secs(2), events.recv())
        .await?
        .ok_or_else(|| io::Error::other("session event channel should remain open"))?;
    assert!(
        event.result.is_err(),
        "proxy task failure must reach its supervisor"
    );
    runtime.shutdown(Duration::from_secs(1)).await;
    Ok(())
}
