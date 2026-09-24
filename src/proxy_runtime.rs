//! One Hudsucker proxy instance hosted by the daemon's shared Tokio runtime.

use std::{
    fmt, fs,
    future::Future,
    io,
    net::SocketAddr,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use hudsucker::{
    Body, HttpContext, HttpHandler, Proxy, RequestOrResponse, WebSocketContext, WebSocketHandler,
    hyper::{Request, Response, StatusCode},
    rustls::crypto::aws_lc_rs,
    tokio_tungstenite::tungstenite::Message,
};
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream, UnixListener},
    sync::Semaphore,
    task::{AbortHandle, JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

use crate::{ca::ManagedCa, config::SessionConfig};

/// A stable identifier for one running Hudsucker instance.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RuntimeId(String);

impl RuntimeId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A startup or fatal error from one proxy instance.
#[derive(Debug)]
pub enum ProxyRuntimeError {
    Bind(io::Error),
    BindSocket(io::Error),
    Bridge(io::Error),
    Build(hudsucker::Error),
    Run(hudsucker::Error),
    Task(String),
}

impl fmt::Display for ProxyRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind(error) => write!(formatter, "could not bind proxy listener: {error}"),
            Self::BindSocket(error) => {
                write!(formatter, "could not bind proxy Unix socket: {error}")
            }
            Self::Bridge(error) => write!(formatter, "proxy Unix socket bridge failed: {error}"),
            Self::Build(error) => write!(formatter, "could not build proxy: {error}"),
            Self::Run(error) => write!(formatter, "proxy runtime failed: {error}"),
            Self::Task(error) => write!(formatter, "proxy runtime task failed: {error}"),
        }
    }
}

/// A typed notification that a proxy runtime exited.
#[derive(Debug)]
pub struct ProxyRuntimeEvent {
    pub runtime_id: RuntimeId,
    pub result: Result<(), ProxyRuntimeError>,
}

/// A running proxy with its dedicated TCP and Unix listeners and tasks.
pub struct ProxyRuntime {
    runtime_id: RuntimeId,
    local_addr: SocketAddr,
    socket_path: PathBuf,
    cancellation: CancellationToken,
    runtime_abort: AbortHandle,
    bridge_abort: AbortHandle,
    task: JoinHandle<()>,
}

impl ProxyRuntime {
    /// Bind and start one proxy from a validated session configuration.
    ///
    /// Hudsucker builds its outbound client inside each `start` call. This
    /// method creates a separate builder and handler for every runtime while
    /// sharing only the daemon-owned CA material.
    pub async fn start(
        runtime_id: RuntimeId,
        session: SessionConfig,
        ca: Arc<ManagedCa>,
        socket_path: PathBuf,
        max_connections: usize,
        events: tokio::sync::mpsc::UnboundedSender<ProxyRuntimeEvent>,
    ) -> Result<Self, ProxyRuntimeError> {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .map_err(ProxyRuntimeError::Bind)?;
        let local_addr = listener.local_addr().map_err(ProxyRuntimeError::Bind)?;
        let (unix_listener, socket_guard) =
            bind_unix_listener(&socket_path).map_err(ProxyRuntimeError::BindSocket)?;
        let cancellation = CancellationToken::new();
        let shutdown = cancellation.clone();

        let proxy = Proxy::builder()
            .with_listener(listener)
            .with_ca(ca.for_proxy())
            .with_rustls_connector(aws_lc_rs::default_provider())
            .with_http_handler(DenyAllHandler {
                runtime_id: runtime_id.clone(),
                _session: session.clone(),
            })
            .with_websocket_handler(DenyAllHandler {
                runtime_id: runtime_id.clone(),
                _session: session,
            })
            .with_graceful_shutdown(async move {
                shutdown.cancelled().await;
            })
            .build()
            .map_err(ProxyRuntimeError::Build)?;

        let mut bridge_task = tokio::spawn(run_bridge(
            unix_listener,
            socket_guard,
            local_addr,
            Arc::new(Semaphore::new(max_connections)),
            cancellation.clone(),
        ));
        let bridge_abort = bridge_task.abort_handle();

        // Keep the Hudsucker task's result observable even if the task panics.
        let mut runtime_task = tokio::spawn(proxy.start());
        let runtime_abort = runtime_task.abort_handle();
        let event_id = runtime_id.clone();
        let supervisor_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            let (runtime_result, bridge_result) = tokio::select! {
                runtime_result = &mut runtime_task => {
                    supervisor_cancellation.cancel();
                    (map_runtime_result(runtime_result), map_bridge_result(bridge_task.await))
                }
                bridge_result = &mut bridge_task => {
                    supervisor_cancellation.cancel();
                    (map_runtime_result(runtime_task.await), map_bridge_result(bridge_result))
                }
            };
            let result = runtime_result.and(bridge_result);
            let _ = events.send(ProxyRuntimeEvent {
                runtime_id: event_id,
                result,
            });
        });

        Ok(Self {
            runtime_id,
            local_addr,
            socket_path,
            cancellation,
            runtime_abort,
            bridge_abort,
            task,
        })
    }

    pub fn runtime_id(&self) -> &RuntimeId {
        &self.runtime_id
    }

    /// Return the pre-bound loopback listener address used by Hudsucker.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Return the private Unix-domain socket used to reach this proxy.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Ask Hudsucker to drain active connections, then bound the wait.
    pub async fn shutdown(mut self, grace: Duration) {
        self.cancellation.cancel();
        if tokio::time::timeout(grace, &mut self.task).await.is_err() {
            self.runtime_abort.abort();
            self.bridge_abort.abort();
            let _ = (&mut self.task).await;
        }
    }
}

fn map_runtime_result(
    result: Result<Result<(), hudsucker::Error>, tokio::task::JoinError>,
) -> Result<(), ProxyRuntimeError> {
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(ProxyRuntimeError::Run(error)),
        Err(error) => Err(ProxyRuntimeError::Task(error.to_string())),
    }
}

fn map_bridge_result(
    result: Result<io::Result<()>, tokio::task::JoinError>,
) -> Result<(), ProxyRuntimeError> {
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(ProxyRuntimeError::Bridge(error)),
        Err(error) => Err(ProxyRuntimeError::Task(error.to_string())),
    }
}

struct UnixSocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl UnixSocketGuard {
    fn bind(path: &Path) -> io::Result<(UnixListener, Self)> {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "Unix socket path already exists",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let listener = UnixListener::bind(path)?;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket() {
            return Err(io::Error::other("bound Unix path is not a socket"));
        }
        let guard = Self {
            path: path.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };

        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        let metadata = fs::symlink_metadata(path)?;
        if !guard.matches(&metadata) || metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(io::Error::other(
                "bound Unix socket has unexpected identity or permissions",
            ));
        }

        Ok((listener, guard))
    }

    fn matches(&self, metadata: &fs::Metadata) -> bool {
        metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
    }
}

impl Drop for UnixSocketGuard {
    fn drop(&mut self) {
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) if self.matches(&metadata) => {
                if let Err(error) = fs::remove_file(&self.path)
                    && error.kind() != io::ErrorKind::NotFound
                {
                    tracing::warn!(path = %self.path.display(), %error, "failed to remove proxy Unix socket");
                }
            }
            Ok(_) => tracing::warn!(
                path = %self.path.display(),
                "proxy Unix socket path changed; leaving replacement untouched"
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(
                path = %self.path.display(),
                %error,
                "could not inspect proxy Unix socket during cleanup"
            ),
        }
    }
}

fn bind_unix_listener(path: &Path) -> io::Result<(UnixListener, UnixSocketGuard)> {
    UnixSocketGuard::bind(path)
}

async fn run_bridge(
    listener: UnixListener,
    _socket_guard: UnixSocketGuard,
    upstream: SocketAddr,
    permits: Arc<Semaphore>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    tracing::debug!(%error, "proxy bridge connection task failed");
                }
            }
            accepted = listener.accept() => {
                let (mut unix_stream, _) = accepted?;
                let permit = match Arc::clone(&permits).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        drop(unix_stream);
                        continue;
                    }
                };
                let connection_cancellation = cancellation.clone();
                connections.spawn(async move {
                    tokio::select! {
                        biased;
                        _ = connection_cancellation.cancelled() => {}
                        result = async {
                            let mut tcp_stream = TcpStream::connect(upstream).await?;
                            copy_bidirectional(&mut unix_stream, &mut tcp_stream).await?;
                            Ok::<(), io::Error>(())
                        } => {
                            if let Err(error) = result {
                                tracing::debug!(%error, "proxy bridge connection closed with an error");
                            }
                        }
                    }
                    drop(permit);
                });
            }
        }
    }

    while let Some(result) = connections.join_next().await {
        if let Err(error) = result {
            tracing::debug!(%error, "proxy bridge connection task failed during shutdown");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use tokio::{
        io::AsyncReadExt,
        net::{TcpListener, UnixStream},
        sync::Semaphore,
        time::timeout,
    };
    use tokio_util::sync::CancellationToken;

    use super::{UnixSocketGuard, run_bridge};

    #[tokio::test]
    async fn admission_limit_rejects_before_opening_another_upstream_connection() {
        let directory = tempfile::tempdir().expect("test directory should be created");
        let socket_path = directory.path().join("bridge.sock");
        let (unix_listener, socket_guard) =
            UnixSocketGuard::bind(&socket_path).expect("Unix bridge should bind");
        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test upstream should bind");
        let upstream_address = upstream
            .local_addr()
            .expect("test upstream address should be available");
        let cancellation = CancellationToken::new();
        let bridge = tokio::spawn(run_bridge(
            unix_listener,
            socket_guard,
            upstream_address,
            Arc::new(Semaphore::new(1)),
            cancellation.clone(),
        ));

        let _first_client = UnixStream::connect(&socket_path)
            .await
            .expect("first Unix client should connect");
        let (_first_upstream, _) = timeout(Duration::from_secs(2), upstream.accept())
            .await
            .expect("first bridge should open an upstream connection")
            .expect("first upstream connection should succeed");

        let mut rejected_client = UnixStream::connect(&socket_path)
            .await
            .expect("Unix listener should accept a client while at capacity");
        let mut byte = [0; 1];
        let read = timeout(Duration::from_secs(2), rejected_client.read(&mut byte))
            .await
            .expect("over-limit client should be closed")
            .expect("over-limit client close should be readable");
        assert_eq!(read, 0, "over-limit client must not be bridged");
        assert!(
            timeout(Duration::from_millis(50), upstream.accept())
                .await
                .is_err(),
            "admission must happen before opening an upstream TCP connection"
        );

        cancellation.cancel();
        timeout(Duration::from_secs(2), bridge)
            .await
            .expect("bridge should stop when its session is cancelled")
            .expect("bridge task should join")
            .expect("bridge should shut down cleanly");
        assert!(
            !socket_path.exists(),
            "session cancellation removes its socket"
        );
    }
}

impl Drop for ProxyRuntime {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

#[derive(Clone)]
struct DenyAllHandler {
    runtime_id: RuntimeId,
    // Retain the validated, immutable policy with its own handler state. Policy
    // decisions are added in the filtering milestone; this runtime denies all.
    _session: SessionConfig,
}

impl HttpHandler for DenyAllHandler {
    fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        _request: Request<Body>,
    ) -> impl Future<Output = RequestOrResponse> + Send {
        tracing::debug!(runtime_id = %self.runtime_id.as_str(), "denying outbound proxy request");
        async {
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::empty())
                .expect("static deny response is valid")
                .into()
        }
    }
}

impl WebSocketHandler for DenyAllHandler {
    async fn handle_message(
        &mut self,
        _ctx: &WebSocketContext,
        _message: Message,
    ) -> Option<Message> {
        None
    }
}
