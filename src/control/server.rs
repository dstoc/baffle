use std::{
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::UnixStream as StdUnixStream,
        },
    },
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};
use tracing::{info, warn};

use crate::config::{ControlRequest, DaemonConfig, PROTOCOL_VERSION, SessionCreateMode};
use crate::secrets::{SecretStore, SecretStoreError};
use crate::{
    ca::ManagedCa,
    config::SessionConfig,
    proxy_runtime::ProxyRuntimeEvent,
    telemetry::{Metrics, MetricsSnapshot},
};

use super::{
    file_config::{SessionConfigFileError, SessionConfigStore},
    session::{SessionError, SessionManager},
};

const MAX_REQUEST_BYTES: usize = 256 * 1024;

const ERR_UNAUTHORIZED: (&str, &str) = ("unauthorized", "client is not authorized");
const ERR_INVALID_REQUEST: (&str, &str) = ("invalid_request", "request is invalid");
const ERR_UNSUPPORTED_VERSION: (&str, &str) =
    ("unsupported_version", "protocol version is not supported");
const ERR_FRAME_TOO_LARGE: (&str, &str) =
    ("frame_too_large", "request exceeds the maximum frame size");
const ERR_TRUNCATED_FRAME: (&str, &str) = ("truncated_frame", "request frame is incomplete");
const ERR_READ_TIMEOUT: (&str, &str) = ("read_timeout", "request read timed out");
const ERR_BUSY: (&str, &str) = ("busy", "server is busy");
const ERR_SESSION_LIMIT: (&str, &str) = ("session_limit", "session limit has been reached");
const ERR_SESSION_NOT_FOUND: (&str, &str) = ("session_not_found", "session was not found");
const ERR_SECRET_UNAVAILABLE: (&str, &str) = (
    "secret_unavailable",
    "one or more requested secrets are unavailable",
);
const ERR_INTERNAL: (&str, &str) = ("internal_error", "request could not be completed");
const ERR_SHUTTING_DOWN: (&str, &str) = ("shutting_down", "daemon is shutting down");
const ERR_OPERATION_NOT_ALLOWED: (&str, &str) = (
    "operation_not_allowed",
    "session creation operation is not allowed by daemon configuration",
);
const ERR_CONFIG_FILE_NOT_FOUND: (&str, &str) = (
    "config_file_not_found",
    "session configuration file was not found",
);
const ERR_CONFIG_FILE_UNAVAILABLE: (&str, &str) = (
    "config_file_unavailable",
    "session configuration file is unavailable",
);
const ERR_CONFIG_FILE_INVALID: (&str, &str) = (
    "config_file_invalid",
    "session configuration file is invalid",
);

pub struct ControlServer {
    listener: Option<UnixListener>,
    socket_guard: Option<SocketGuard>,
    state: Arc<ControlState>,
    connections: JoinSet<()>,
    session_cleanups: JoinSet<()>,
    runtime_events: tokio::sync::mpsc::UnboundedReceiver<ProxyRuntimeEvent>,
    metrics: Arc<Metrics>,
}

struct ControlState {
    trusted_operator_uid: u32,
    create_mode: SessionCreateMode,
    read_timeout: Duration,
    secret_store: SecretStore,
    sessions: SessionManager,
    provisioning_slots: Arc<Semaphore>,
    session_configs: Option<SessionConfigStore>,
}

struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        match fs::symlink_metadata(&self.path) {
            Ok(metadata)
                if metadata.file_type().is_socket()
                    && metadata.dev() == self.device
                    && metadata.ino() == self.inode =>
            {
                if let Err(error) = fs::remove_file(&self.path)
                    && error.kind() != io::ErrorKind::NotFound
                {
                    warn!(path = %self.path.display(), %error, "failed to remove control socket");
                }
            }
            Ok(_) => warn!(
                path = %self.path.display(),
                "control socket path changed; leaving replacement untouched"
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => warn!(
                path = %self.path.display(),
                %error,
                "could not inspect control socket during cleanup"
            ),
        }
    }
}

impl ControlServer {
    pub fn bind(config: &DaemonConfig, ca: Arc<ManagedCa>) -> Result<Self> {
        let control_socket = &config.daemon.control_socket;
        let socket_dir = &config.daemon.socket_dir;
        let trusted_uid = config.daemon.trusted_operator_uid;

        let parent = control_socket
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        ensure_private_directory(parent, trusted_uid)?;
        ensure_private_directory(socket_dir, trusted_uid)?;

        // Keep this lock until the control listener is bound. A lock file is
        // intentionally retained: unlinking it while another process waits
        // would let a third process lock a different inode.
        let _startup_lock = StartupLock::acquire(control_socket, trusted_uid)?;

        match fs::symlink_metadata(control_socket) {
            Ok(metadata) if metadata.file_type().is_socket() => {
                if !remove_stale_socket(control_socket, trusted_uid)? {
                    bail!("control socket path already exists");
                }
            }
            Ok(_) => bail!("control socket path already exists"),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("could not inspect control socket path"),
        }

        remove_stale_session_sockets(socket_dir, trusted_uid)?;

        let listener = UnixListener::bind(control_socket).with_context(|| {
            format!("could not bind control socket {}", control_socket.display())
        })?;
        let metadata = fs::symlink_metadata(control_socket)
            .context("could not inspect bound control socket")?;
        if !metadata.file_type().is_socket() {
            bail!("bound control socket has unexpected file type");
        }
        let socket_guard = SocketGuard {
            path: control_socket.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        fs::set_permissions(control_socket, fs::Permissions::from_mode(0o600))
            .context("could not restrict control socket permissions")?;

        let metadata = fs::symlink_metadata(control_socket)
            .context("could not inspect bound control socket")?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != trusted_uid
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            bail!("bound control socket has unexpected owner or permissions");
        }

        info!(
            path = %control_socket.display(),
            trusted_operator_uid = trusted_uid,
            "control socket listening"
        );

        let (runtime_event_sender, runtime_events) = tokio::sync::mpsc::unbounded_channel();
        let metrics = Arc::new(Metrics::default());
        let session_configs = match config.daemon.create_mode {
            SessionCreateMode::Inline => None,
            SessionCreateMode::FileOnly => Some(SessionConfigStore::open(
                config
                    .daemon
                    .session_config_dir
                    .as_deref()
                    .context("file-only mode requires a session configuration directory")?,
                trusted_uid,
            )?),
        };

        Ok(Self {
            listener: Some(listener),
            socket_guard: Some(socket_guard),
            state: Arc::new(ControlState {
                trusted_operator_uid: trusted_uid,
                create_mode: config.daemon.create_mode,
                read_timeout: Duration::from_millis(config.daemon.control_read_timeout_ms),
                secret_store: SecretStore::new(
                    config.secrets.directory.clone(),
                    trusted_uid,
                    config.secrets.allowed.clone(),
                ),
                sessions: SessionManager::new(
                    &config.daemon,
                    ca,
                    runtime_event_sender,
                    Arc::clone(&metrics),
                ),
                provisioning_slots: Arc::new(Semaphore::new(
                    config.daemon.max_provisioning_requests,
                )),
                session_configs,
            }),
            connections: JoinSet::new(),
            session_cleanups: JoinSet::new(),
            runtime_events,
            metrics,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        loop {
            let listener = self
                .listener
                .as_ref()
                .context("control server is shutting down")?;
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, _) = accepted.context("control socket accept failed")?;
                    let state = Arc::clone(&self.state);
                    self.connections.spawn(async move {
                        handle_connection(stream, state).await;
                    });
                }
                Some(result) = self.connections.join_next(), if !self.connections.is_empty() => {
                    if let Err(error) = result {
                        warn!(%error, "control connection task failed");
                    }
                }
                Some(result) = self.session_cleanups.join_next(), if !self.session_cleanups.is_empty() => {
                    if let Err(error) = result {
                        warn!(%error, "session cleanup task failed");
                    }
                }
                Some(event) = self.runtime_events.recv() => {
                    let ProxyRuntimeEvent { runtime_id, listener_generation, retired, result } = event;
                    match result {
                        Ok(()) => info!(event = "session_lifecycle", session_id = %runtime_id.as_str(), state = if retired { "drained" } else { "stopped" }, "proxy runtime stopped"),
                        Err(error) => warn!(event = "session_lifecycle", session_id = %runtime_id.as_str(), state = "failed", error_class = error.class(), error = %error, "proxy runtime failed"),
                    }
                    let sessions = self.state.sessions.clone();
                    let session_id = runtime_id.as_str().to_owned();
                    self.session_cleanups.spawn(async move {
                        sessions
                            .runtime_exit(&session_id, listener_generation)
                            .await;
                    });
                }
            }
        }
    }

    /// Stop all owned proxy instances, allowing each runtime to drain.
    pub async fn shutdown(&mut self) {
        // Close the listening socket before stopping sessions. Existing
        // handlers are cancelled below so no request can outlive shutdown.
        self.listener.take();
        self.state.sessions.reject_new_sessions().await;
        self.connections.abort_all();
        while self.connections.join_next().await.is_some() {}
        while self.session_cleanups.join_next().await.is_some() {}
        self.state.sessions.shutdown_all().await;
        let MetricsSnapshot {
            active_sessions,
            accepted_connections,
            active_connections,
            denied_requests,
            upstream_failures,
            interception_errors,
            forced_shutdowns,
        } = self.metrics.snapshot();
        info!(
            event = "daemon_metrics",
            active_sessions,
            accepted_connections,
            active_connections,
            denied_requests,
            upstream_failures,
            interception_errors,
            forced_shutdowns,
            "daemon counters at shutdown"
        );
        self.socket_guard.take();
    }
}

struct StartupLock {
    _file: File,
}

impl StartupLock {
    fn acquire(control_socket: &Path, expected_uid: u32) -> Result<Self> {
        let lock_name = format!(
            "{}.lock",
            control_socket
                .file_name()
                .context("control socket path has no file name")?
                .to_string_lossy()
        );
        let lock_path = control_socket.with_file_name(lock_name);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&lock_path)
            .with_context(|| format!("could not open startup lock {}", lock_path.display()))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("could not inspect startup lock {}", lock_path.display()))?;
        if !metadata.is_file()
            || metadata.uid() != expected_uid
            || metadata.permissions().mode() & 0o077 != 0
        {
            bail!("startup lock has unexpected owner, type, or permissions");
        }

        // flock is released by closing the file if startup fails.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == -1 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("could not lock startup file {}", lock_path.display()));
        }

        Ok(Self { _file: file })
    }
}

fn ensure_private_directory(path: &Path, expected_uid: u32) -> Result<()> {
    let absolute_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("could not resolve working directory")?
            .join(path)
    };

    let mut current = PathBuf::new();
    for component in absolute_path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    bail!("control socket directory path contains a non-directory component");
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current)
                    .with_context(|| format!("could not create directory {}", current.display()))?;
                fs::set_permissions(&current, fs::Permissions::from_mode(0o700))
                    .context("could not restrict control directory permissions")?;
            }
            Err(error) => return Err(error).context("could not inspect control socket directory"),
        }
    }

    let metadata = fs::symlink_metadata(&absolute_path)
        .context("could not inspect control socket directory")?;
    if metadata.uid() != expected_uid {
        bail!("control socket directory is not owned by the trusted operator");
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("control socket directory permissions must be 0700 or more restrictive");
    }
    Ok(())
}

/// Remove a disconnected Unix socket without deleting an active listener or a
/// path that changed while it was being checked. Returns true only when this
/// call removed a stale socket.
fn remove_stale_socket(path: &Path, expected_uid: u32) -> Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("could not inspect {}", path.display()));
        }
    };
    if !metadata.file_type().is_socket() || metadata.uid() != expected_uid {
        return Ok(false);
    }

    match StdUnixStream::connect(path) {
        Ok(stream) => {
            drop(stream);
            Ok(false)
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) =>
        {
            let current = match fs::symlink_metadata(path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("could not recheck {}", path.display()));
                }
            };
            if !current.file_type().is_socket()
                || current.uid() != expected_uid
                || current.dev() != metadata.dev()
                || current.ino() != metadata.ino()
            {
                bail!("socket path changed during stale socket cleanup");
            }
            fs::remove_file(path)
                .with_context(|| format!("could not remove stale socket {}", path.display()))?;
            Ok(true)
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "could not check whether socket {} is active",
                path.display()
            )
        }),
    }
}

fn remove_stale_session_sockets(directory: &Path, expected_uid: u32) -> Result<()> {
    for entry in fs::read_dir(directory).with_context(|| {
        format!(
            "could not read session socket directory {}",
            directory.display()
        )
    })? {
        let entry = entry.context("could not inspect session socket directory entry")?;
        let path = entry.path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("could not inspect {}", path.display()));
            }
        };
        if metadata.file_type().is_socket() {
            remove_stale_socket(&path, expected_uid)?;
        }
    }
    Ok(())
}

async fn handle_connection(mut stream: UnixStream, state: Arc<ControlState>) {
    let client_uid = match stream.peer_cred() {
        Ok(credentials) if credentials.uid() == state.trusted_operator_uid => credentials.uid(),
        Ok(_) => {
            let _ = write_error(&mut stream, ERR_UNAUTHORIZED).await;
            return;
        }
        Err(_) => {
            let _ = write_error(&mut stream, ERR_UNAUTHORIZED).await;
            return;
        }
    };

    let request_body = match read_request_frame(&mut stream, state.read_timeout).await {
        Ok(Some(body)) => body,
        Ok(None) => return,
        Err(error) => {
            let _ = write_error(&mut stream, error).await;
            return;
        }
    };
    let request_text = match std::str::from_utf8(&request_body) {
        Ok(text) => text,
        Err(_) => {
            let _ = write_error(&mut stream, ERR_INVALID_REQUEST).await;
            return;
        }
    };
    let request = match ControlRequest::from_toml(request_text) {
        Ok(request) => request,
        Err(error) if error.is_unsupported_protocol_version() => {
            let _ = write_error(&mut stream, ERR_UNSUPPORTED_VERSION).await;
            return;
        }
        Err(_) => {
            let _ = write_error(&mut stream, ERR_INVALID_REQUEST).await;
            return;
        }
    };

    let mut lease_id = None;
    let response = match request {
        ControlRequest::Create { session, .. } => {
            if state.create_mode != SessionCreateMode::Inline {
                error_value(ERR_OPERATION_NOT_ALLOWED)
            } else {
                match state.provisioning_slots.clone().try_acquire_owned() {
                    Ok(permit) => {
                        create_session_response(
                            &state,
                            client_uid,
                            session,
                            None,
                            permit,
                            &mut lease_id,
                        )
                        .await
                    }
                    Err(_) => error_value(ERR_BUSY),
                }
            }
        }
        ControlRequest::CreateFromFile { name, .. } => {
            if state.create_mode != SessionCreateMode::FileOnly {
                error_value(ERR_OPERATION_NOT_ALLOWED)
            } else {
                let permit = match state.provisioning_slots.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        let _ = write_error(&mut stream, ERR_BUSY).await;
                        return;
                    }
                };
                let Some(store) = &state.session_configs else {
                    let _ = write_error(&mut stream, ERR_INTERNAL).await;
                    return;
                };
                let text = match store.read_snapshot(&name) {
                    Ok(text) => text,
                    Err(SessionConfigFileError::NotFound) => {
                        let _ = write_error(&mut stream, ERR_CONFIG_FILE_NOT_FOUND).await;
                        return;
                    }
                    Err(SessionConfigFileError::Unavailable) => {
                        let _ = write_error(&mut stream, ERR_CONFIG_FILE_UNAVAILABLE).await;
                        return;
                    }
                    Err(SessionConfigFileError::Invalid) => {
                        let _ = write_error(&mut stream, ERR_CONFIG_FILE_INVALID).await;
                        return;
                    }
                };
                let session = match ControlRequest::from_toml(&text) {
                    Ok(ControlRequest::Create { session, .. }) => session,
                    _ => {
                        let _ = write_error(&mut stream, ERR_CONFIG_FILE_INVALID).await;
                        return;
                    }
                };
                create_session_response(
                    &state,
                    client_uid,
                    session,
                    Some(name),
                    permit,
                    &mut lease_id,
                )
                .await
            }
        }
        ControlRequest::Stop { session_id, .. } => {
            if state.sessions.stop(&session_id, client_uid).await {
                success(json!({ "stopped": true }))
            } else {
                error_value(ERR_SESSION_NOT_FOUND)
            }
        }
        ControlRequest::Reload { session_id, .. } => {
            match state
                .sessions
                .reload(
                    &session_id,
                    client_uid,
                    state.session_configs.as_ref(),
                    &state.secret_store,
                )
                .await
            {
                Ok(result) => success(json!(result)),
                Err(()) => error_value(ERR_SESSION_NOT_FOUND),
            }
        }
        ControlRequest::ReloadAll { .. } => {
            let results = state
                .sessions
                .reload_all(
                    client_uid,
                    state.session_configs.as_ref(),
                    &state.secret_store,
                )
                .await;
            success(json!({ "results": results }))
        }
        ControlRequest::List { .. } => success(json!({
            "sessions": state.sessions.list(client_uid).await,
        })),
    };

    if write_value(&mut stream, response).await.is_err() {
        if let Some(id) = lease_id {
            state.sessions.remove(&id, "response_write_failed").await;
        }
        return;
    }

    // An ephemeral create connection is also its lease. Any bytes after the
    // request violate the one-request rule and revoke the placeholder session.
    if let Some(id) = lease_id {
        let mut extra = [0; 1];
        let _ = stream.read(&mut extra).await;
        state.sessions.remove(&id, "lease_closed").await;
    }
}

async fn create_session_response(
    state: &ControlState,
    client_uid: u32,
    session: SessionConfig,
    config_source: Option<String>,
    permit: tokio::sync::OwnedSemaphorePermit,
    lease_id: &mut Option<String>,
) -> Value {
    let secrets = match state.secret_store.resolve(client_uid, &session) {
        Ok(secrets) => secrets,
        Err(
            SecretStoreError::UnauthorizedClient
            | SecretStoreError::NotEntitled
            | SecretStoreError::Unavailable,
        ) => return error_value(ERR_SECRET_UNAVAILABLE),
    };
    let result = state
        .sessions
        .create(client_uid, session, secrets, config_source)
        .await;
    drop(permit);
    match result {
        Ok(created) => {
            if !created.persistent {
                *lease_id = Some(created.id.clone());
            }
            success(json!({
                "id": created.id,
                "socket": created.socket,
                "persistent": created.persistent,
            }))
        }
        Err(SessionError::AtCapacity) => error_value(ERR_SESSION_LIMIT),
        Err(SessionError::Runtime(error)) => {
            warn!(error_class = error.class(), "failed to start proxy runtime");
            error_value(ERR_INTERNAL)
        }
        Err(SessionError::ShuttingDown) => error_value(ERR_SHUTTING_DOWN),
        Err(SessionError::Internal) => error_value(ERR_INTERNAL),
    }
}

async fn read_request_frame(
    stream: &mut UnixStream,
    read_timeout: Duration,
) -> std::result::Result<Option<Vec<u8>>, (&'static str, &'static str)> {
    let mut header = [0; 4];
    match timeout(read_timeout, stream.read(&mut header[..1])).await {
        Err(_) => return Err(ERR_READ_TIMEOUT),
        Ok(Err(_)) => return Err(ERR_TRUNCATED_FRAME),
        Ok(Ok(0)) => return Ok(None),
        Ok(Ok(_)) => {}
    }

    read_exact_timed(stream, &mut header[1..], read_timeout).await?;
    let frame_length = u32::from_be_bytes(header) as usize;
    if frame_length > MAX_REQUEST_BYTES {
        return Err(ERR_FRAME_TOO_LARGE);
    }
    if frame_length == 0 {
        return Err(ERR_INVALID_REQUEST);
    }

    let mut body = vec![0; frame_length];
    read_exact_timed(stream, &mut body, read_timeout).await?;
    Ok(Some(body))
}

async fn read_exact_timed(
    stream: &mut UnixStream,
    bytes: &mut [u8],
    read_timeout: Duration,
) -> std::result::Result<(), (&'static str, &'static str)> {
    match timeout(read_timeout, stream.read_exact(bytes)).await {
        Err(_) => Err(ERR_READ_TIMEOUT),
        Ok(Err(_)) => Err(ERR_TRUNCATED_FRAME),
        Ok(Ok(_)) => Ok(()),
    }
}

async fn write_error(
    stream: &mut UnixStream,
    error: (&'static str, &'static str),
) -> io::Result<()> {
    write_value(stream, error_value(error)).await
}

fn error_value((code, message): (&'static str, &'static str)) -> Value {
    json!({
        "version": PROTOCOL_VERSION,
        "ok": false,
        "error": { "code": code, "message": message },
    })
}

fn success(result: Value) -> Value {
    json!({
        "version": PROTOCOL_VERSION,
        "ok": true,
        "result": result,
    })
}

async fn write_value(stream: &mut UnixStream, value: Value) -> io::Result<()> {
    let bytes = serde_json::to_vec(&value).map_err(io::Error::other)?;
    let length = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response frame is too large"))?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await
}

#[cfg(test)]
#[path = "tests/server.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/socket.rs"]
mod socket_tests;
