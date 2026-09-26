//! Private Unix control socket and framed request/response transport.

use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{self, Read},
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, net::UnixStream as StdUnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{Mutex, Semaphore},
    task::JoinSet,
    time::timeout,
};
use tracing::{info, warn};

use crate::config::{
    ControlRequest, DaemonConfig, DaemonSettings, PROTOCOL_VERSION, SessionCreateMode,
};
use crate::secrets::{ResolvedSecrets, SecretStore, SecretStoreError};
use crate::{
    ca::ManagedCa,
    config::SessionConfig,
    proxy_runtime::{ProxyRuntime, ProxyRuntimeError, ProxyRuntimeEvent, RuntimeId},
    telemetry::{Metrics, MetricsSnapshot},
};

const MAX_REQUEST_BYTES: usize = 256 * 1024;
const MAX_SESSION_CONFIG_BYTES: usize = 256 * 1024;

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

#[derive(Clone)]
struct SessionConfigStore {
    directory: Arc<File>,
    trusted_uid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionConfigFileError {
    NotFound,
    Unavailable,
    Invalid,
}

impl SessionConfigStore {
    fn open(directory: &Path, trusted_uid: u32) -> Result<Self> {
        let directory = open_trusted_directory_tree(directory, trusted_uid)?;
        Ok(Self {
            directory: Arc::new(directory),
            trusted_uid,
        })
    }

    fn read_snapshot(&self, name: &str) -> std::result::Result<String, SessionConfigFileError> {
        let mut components = name.split('/').peekable();
        let mut directory = self
            .directory
            .try_clone()
            .map_err(|_| SessionConfigFileError::Unavailable)?;

        while let Some(component) = components.next() {
            let component = std::ffi::CString::new(component.as_bytes())
                .map_err(|_| SessionConfigFileError::Unavailable)?;
            if components.peek().is_some() {
                directory = openat_file(
                    directory.as_raw_fd(),
                    &component,
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
                .map_err(classify_config_file_io)?;
                let metadata = directory
                    .metadata()
                    .map_err(|_| SessionConfigFileError::Unavailable)?;
                validate_config_directory_metadata(&metadata, self.trusted_uid, false)
                    .map_err(|_| SessionConfigFileError::Unavailable)?;
            } else {
                let file = openat_file(
                    directory.as_raw_fd(),
                    &component,
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                )
                .map_err(classify_config_file_io)?;
                let metadata = file
                    .metadata()
                    .map_err(|_| SessionConfigFileError::Unavailable)?;
                let mode = metadata.permissions().mode();
                if !metadata.is_file()
                    || !trusted_owner(metadata.uid(), self.trusted_uid)
                    || mode & 0o7022 != 0
                    || mode & 0o444 == 0
                {
                    return Err(SessionConfigFileError::Unavailable);
                }
                if metadata.len() > MAX_SESSION_CONFIG_BYTES as u64 {
                    return Err(SessionConfigFileError::Invalid);
                }
                let mut bytes = Vec::with_capacity(metadata.len() as usize);
                file.take((MAX_SESSION_CONFIG_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)
                    .map_err(|_| SessionConfigFileError::Unavailable)?;
                if bytes.len() > MAX_SESSION_CONFIG_BYTES {
                    return Err(SessionConfigFileError::Invalid);
                }
                return String::from_utf8(bytes).map_err(|_| SessionConfigFileError::Invalid);
            }
        }
        Err(SessionConfigFileError::Invalid)
    }
}

fn open_trusted_directory_tree(path: &Path, trusted_uid: u32) -> Result<File> {
    if !path.is_absolute() {
        bail!("session configuration directory must be absolute");
    }
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/")
        .context("could not open filesystem root for session configuration")?;
    let components = path
        .components()
        .filter_map(|component| match component {
            std::path::Component::RootDir => None,
            std::path::Component::Normal(component) => Some(Ok(component)),
            _ => Some(Err(())),
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| anyhow::anyhow!("session configuration directory path is invalid"))?;
    if components.is_empty() {
        bail!("session configuration directory must not be the filesystem root");
    }

    for (index, component) in components.iter().enumerate() {
        let component = std::ffi::CString::new(component.as_bytes())
            .map_err(|_| anyhow::anyhow!("session configuration directory path is invalid"))?;
        directory = openat_file(
            directory.as_raw_fd(),
            &component,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
        .context("could not securely open session configuration directory")?;
        let is_root = index + 1 == components.len();
        let metadata = directory
            .metadata()
            .context("could not inspect session configuration directory")?;
        validate_config_directory_metadata(&metadata, trusted_uid, !is_root)
            .context("session configuration directory has unsafe ownership or permissions")?;
    }
    Ok(directory)
}

fn validate_config_directory_metadata(
    metadata: &fs::Metadata,
    trusted_uid: u32,
    allow_sticky_parent: bool,
) -> io::Result<()> {
    if !metadata.is_dir() || !trusted_owner(metadata.uid(), trusted_uid) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe session configuration directory",
        ));
    }
    let mode = metadata.permissions().mode();
    let sticky_parent = allow_sticky_parent && mode & 0o1000 != 0;
    if mode & 0o022 != 0 && !sticky_parent {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "writable session configuration directory",
        ));
    }
    let executable = if metadata.uid() == trusted_uid {
        mode & 0o100 != 0
    } else {
        mode & 0o111 != 0
    };
    if !executable {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "untraversable session configuration directory",
        ));
    }
    Ok(())
}

fn trusted_owner(owner_uid: u32, trusted_uid: u32) -> bool {
    owner_uid == trusted_uid || owner_uid == 0
}

fn openat_file(parent_fd: i32, name: &std::ffi::CStr, flags: i32) -> io::Result<File> {
    // SAFETY: the path is a NUL-terminated CString and the descriptor remains
    // owned by the caller for the duration of openat.
    let fd = unsafe { libc::openat(parent_fd, name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new descriptor, now owned by this File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn classify_config_file_io(error: io::Error) -> SessionConfigFileError {
    if error.kind() == io::ErrorKind::NotFound {
        SessionConfigFileError::NotFound
    } else {
        SessionConfigFileError::Unavailable
    }
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

#[derive(Clone)]
struct SessionManager {
    socket_dir: PathBuf,
    max_sessions: usize,
    max_connections_per_session: usize,
    io_timeout: Duration,
    shutdown_grace: Duration,
    ca: Arc<ManagedCa>,
    runtime_events: tokio::sync::mpsc::UnboundedSender<ProxyRuntimeEvent>,
    registry: Arc<Mutex<SessionRegistry>>,
    metrics: Arc<Metrics>,
}

const MAX_RETIRED_LISTENERS: usize = 8;

struct SessionRegistry {
    accepting_sessions: bool,
    sessions: HashMap<String, ManagedSession>,
    provisioning: HashSet<String>,
}

impl SessionManager {
    fn new(
        settings: &DaemonSettings,
        ca: Arc<ManagedCa>,
        runtime_events: tokio::sync::mpsc::UnboundedSender<ProxyRuntimeEvent>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            socket_dir: settings.socket_dir.clone(),
            max_sessions: settings.max_sessions,
            max_connections_per_session: settings.max_connections_per_session,
            io_timeout: Duration::from_millis(settings.io_timeout_ms),
            shutdown_grace: Duration::from_secs(settings.shutdown_grace_seconds),
            ca,
            runtime_events,
            registry: Arc::new(Mutex::new(SessionRegistry {
                accepting_sessions: true,
                sessions: HashMap::new(),
                provisioning: HashSet::new(),
            })),
            metrics,
        }
    }

    async fn create(
        &self,
        owner_uid: u32,
        session: SessionConfig,
        secrets: ResolvedSecrets,
        config_source: Option<String>,
    ) -> std::result::Result<SessionInfo, SessionError> {
        let secrets = Arc::new(secrets);
        let id = new_session_id().map_err(|_| SessionError::Internal)?;
        let persistent = session.persistent;
        {
            let mut registry = self.registry.lock().await;
            if !registry.accepting_sessions {
                return Err(SessionError::ShuttingDown);
            }
            if registry.sessions.len() + registry.provisioning.len() >= self.max_sessions {
                return Err(SessionError::AtCapacity);
            }
            if registry.sessions.contains_key(&id) || !registry.provisioning.insert(id.clone()) {
                return Err(SessionError::Internal);
            }
        }

        let socket_name = session
            .socket_name
            .clone()
            .unwrap_or_else(|| format!("{id}.sock"));
        let socket_path = match absolute_socket_path(&self.socket_dir.join(socket_name)) {
            Ok(path) => path,
            Err(_) => {
                self.registry.lock().await.provisioning.remove(&id);
                return Err(SessionError::Internal);
            }
        };
        let listener_gate = Arc::new(AtomicU64::new(1));
        let runtime = match ProxyRuntime::start_session_with_metrics(
            RuntimeId::new(id.clone()),
            session.clone(),
            Arc::clone(&secrets),
            Arc::clone(&self.ca),
            socket_path,
            self.max_connections_per_session,
            self.io_timeout,
            Arc::clone(&self.metrics),
            self.runtime_events.clone(),
            Arc::clone(&listener_gate),
            1,
        )
        .await
        {
            Ok(runtime) => runtime,
            Err(error) => {
                self.registry.lock().await.provisioning.remove(&id);
                return Err(SessionError::Runtime(error));
            }
        };
        let info = SessionInfo {
            socket: runtime.socket_path().to_string_lossy().into_owned(),
            id: id.clone(),
            persistent,
            state: SessionLifecycle::Running,
            generation: 1,
            draining_generations: 0,
        };
        let mut registry = self.registry.lock().await;
        registry.provisioning.remove(&id);
        if !registry.accepting_sessions {
            drop(registry);
            drop(runtime);
            return Err(SessionError::ShuttingDown);
        }
        registry.sessions.insert(
            id,
            ManagedSession {
                info: info.clone(),
                owner_uid,
                configuration: session,
                secrets,
                config_source,
                runtime: Some(runtime),
                retired_runtimes: Vec::new(),
                reload_lock: Arc::new(Mutex::new(())),
                listener_gate,
                listener_generation: 1,
            },
        );
        let active_sessions = self.metrics.session_started();
        tracing::info!(
            event = "session_lifecycle",
            session_id = %info.id,
            state = "running",
            active_sessions,
            "proxy session started"
        );
        Ok(info)
    }

    async fn reject_new_sessions(&self) {
        self.registry.lock().await.accepting_sessions = false;
    }

    async fn stop(&self, id: &str, owner_uid: u32) -> bool {
        let reload_lock = {
            let registry = self.registry.lock().await;
            let Some(session) = registry.sessions.get(id) else {
                return false;
            };
            if session.owner_uid != owner_uid {
                return false;
            }
            Arc::clone(&session.reload_lock)
        };
        let _serial = reload_lock.lock().await;
        let runtimes = {
            let mut registry = self.registry.lock().await;
            let Some(session) = registry.sessions.get_mut(id) else {
                return false;
            };
            if session.owner_uid != owner_uid {
                return false;
            }
            if session.info.state == SessionLifecycle::Stopping {
                return true;
            }
            session.info.state = SessionLifecycle::Stopping;
            let mut runtimes = std::mem::take(&mut session.retired_runtimes);
            runtimes.extend(session.runtime.take());
            runtimes
        };
        self.shutdown_runtimes(runtimes).await;
        if self.registry.lock().await.sessions.remove(id).is_some() {
            let active_sessions = self.metrics.session_stopped();
            tracing::info!(
                event = "session_lifecycle",
                session_id = id,
                state = "stopped",
                reason = "explicit_stop",
                active_sessions,
                "proxy session removed"
            );
        }
        true
    }

    async fn remove(&self, id: &str, reason: &'static str) {
        let reload_lock = {
            let registry = self.registry.lock().await;
            let Some(session) = registry.sessions.get(id) else {
                return;
            };
            Arc::clone(&session.reload_lock)
        };
        let _serial = reload_lock.lock().await;
        let runtimes = {
            let mut registry = self.registry.lock().await;
            let Some(session) = registry.sessions.get_mut(id) else {
                return;
            };
            if session.info.state == SessionLifecycle::Stopping && session.runtime.is_none() {
                return;
            }
            session.info.state = SessionLifecycle::Stopping;
            let mut runtimes = std::mem::take(&mut session.retired_runtimes);
            runtimes.extend(session.runtime.take());
            runtimes
        };
        self.shutdown_runtimes(runtimes).await;
        if self.registry.lock().await.sessions.remove(id).is_some() {
            let active_sessions = self.metrics.session_stopped();
            tracing::info!(
                event = "session_lifecycle",
                session_id = id,
                state = "stopped",
                reason,
                active_sessions,
                "proxy session removed"
            );
        }
    }

    async fn runtime_exit(&self, id: &str, listener_generation: u64) {
        let reload_lock = {
            let registry = self.registry.lock().await;
            let Some(session) = registry.sessions.get(id) else {
                return;
            };
            Arc::clone(&session.reload_lock)
        };
        let _serial = reload_lock.lock().await;
        let runtimes = {
            let mut registry = self.registry.lock().await;
            let Some(session) = registry.sessions.get_mut(id) else {
                return;
            };
            if session.listener_generation != listener_generation {
                session
                    .retired_runtimes
                    .retain(|runtime| runtime.listener_generation() != listener_generation);
                session.info.draining_generations = session.retired_runtimes.len();
                return;
            }
            if session.info.state == SessionLifecycle::Stopping && session.runtime.is_none() {
                return;
            }
            session.info.state = SessionLifecycle::Stopping;
            let mut runtimes = std::mem::take(&mut session.retired_runtimes);
            runtimes.extend(session.runtime.take());
            runtimes
        };
        self.shutdown_runtimes(runtimes).await;
        if self.registry.lock().await.sessions.remove(id).is_some() {
            let active_sessions = self.metrics.session_stopped();
            tracing::info!(
                event = "session_lifecycle",
                session_id = id,
                state = "stopped",
                reason = "runtime_exit",
                active_sessions,
                "proxy session removed"
            );
        }
    }

    async fn shutdown_all(&self) {
        let session_ids = {
            let mut registry = self.registry.lock().await;
            registry.accepting_sessions = false;
            registry.provisioning.clear();
            registry.sessions.keys().cloned().collect::<Vec<_>>()
        };
        let mut runtimes = Vec::new();
        let mut session_count = 0;
        for id in session_ids {
            let reload_lock = {
                let registry = self.registry.lock().await;
                registry
                    .sessions
                    .get(&id)
                    .map(|session| Arc::clone(&session.reload_lock))
            };
            let Some(reload_lock) = reload_lock else {
                continue;
            };
            let _serial = reload_lock.lock().await;
            if let Some(session) = self.registry.lock().await.sessions.get_mut(&id) {
                session.info.state = SessionLifecycle::Stopping;
                runtimes.append(&mut session.retired_runtimes);
                runtimes.extend(session.runtime.take());
                session_count += 1;
            }
        }
        self.shutdown_runtimes(runtimes).await;
        self.registry.lock().await.sessions.clear();
        for _ in 0..session_count {
            self.metrics.session_stopped();
        }
    }

    async fn shutdown_runtimes(&self, runtimes: Vec<ProxyRuntime>) {
        let mut shutdowns = JoinSet::new();
        for runtime in runtimes {
            let grace = self.shutdown_grace;
            shutdowns.spawn(async move { runtime.shutdown(grace).await });
        }
        while shutdowns.join_next().await.is_some() {}
    }

    async fn list(&self, owner_uid: u32) -> Vec<SessionInfo> {
        let mut registry = self.registry.lock().await;
        for session in registry.sessions.values_mut() {
            session
                .retired_runtimes
                .retain(|runtime| !runtime.is_finished());
            session.info.draining_generations = session.retired_runtimes.len();
        }
        let mut sessions = registry
            .sessions
            .values()
            .filter(|session| session.owner_uid == owner_uid)
            .map(|session| session.info.clone())
            .collect::<Vec<_>>();
        sessions.sort_by(|left, right| left.id.cmp(&right.id));
        sessions
    }

    async fn reload(
        &self,
        id: &str,
        owner_uid: u32,
        configs: Option<&SessionConfigStore>,
        secret_store: &SecretStore,
    ) -> std::result::Result<SessionReloadResult, ()> {
        let reload_lock = {
            let registry = self.registry.lock().await;
            let Some(session) = registry.sessions.get(id) else {
                return Err(());
            };
            if session.owner_uid != owner_uid {
                return Err(());
            }
            Arc::clone(&session.reload_lock)
        };
        let _serial = reload_lock.lock().await;
        Ok(self
            .reload_locked(id, owner_uid, configs, secret_store)
            .await)
    }

    async fn reload_all(
        &self,
        owner_uid: u32,
        configs: Option<&SessionConfigStore>,
        secret_store: &SecretStore,
    ) -> Vec<SessionReloadResult> {
        let sessions = {
            let registry = self.registry.lock().await;
            let mut sessions = registry
                .sessions
                .values()
                .filter(|session| {
                    session.owner_uid == owner_uid
                        && session.config_source.is_some()
                        && session.info.state == SessionLifecycle::Running
                })
                .map(|session| (session.info.id.clone(), session.info.socket.clone()))
                .collect::<Vec<_>>();
            sessions.sort_by(|left, right| left.0.cmp(&right.0));
            sessions
        };
        let mut results = Vec::with_capacity(sessions.len());
        for (id, socket) in sessions {
            match self.reload(&id, owner_uid, configs, secret_store).await {
                Ok(result) => results.push(result),
                Err(()) => results.push(SessionReloadResult::failed(
                    &id,
                    socket,
                    "session_unavailable",
                )),
            }
        }
        results
    }

    async fn reload_locked(
        &self,
        id: &str,
        owner_uid: u32,
        configs: Option<&SessionConfigStore>,
        secret_store: &SecretStore,
    ) -> SessionReloadResult {
        let (config_source, current_secrets, current_socket, persistent) = {
            let mut registry = self.registry.lock().await;
            let accepting = registry.accepting_sessions;
            let Some(session) = registry.sessions.get_mut(id) else {
                return SessionReloadResult::failed(id, "".to_owned(), "session_unavailable");
            };
            if session.owner_uid != owner_uid {
                return SessionReloadResult::failed(id, "".to_owned(), "session_unavailable");
            }
            session
                .retired_runtimes
                .retain(|runtime| !runtime.is_finished());
            session.info.draining_generations = session.retired_runtimes.len();
            if session.info.state != SessionLifecycle::Running || !accepting {
                return SessionReloadResult::failed(
                    id,
                    session.info.socket.clone(),
                    "session_stopping",
                );
            }
            let Some(source) = session.config_source.clone() else {
                return SessionReloadResult::failed(
                    id,
                    session.info.socket.clone(),
                    "inline_session",
                );
            };
            (
                source,
                Arc::clone(&session.secrets),
                session.info.socket.clone(),
                session.configuration.persistent,
            )
        };

        let Some(configs) = configs else {
            return SessionReloadResult::failed(id, current_socket, "configuration_unavailable");
        };
        let text = match configs.read_snapshot(&config_source) {
            Ok(text) => text,
            Err(SessionConfigFileError::NotFound) => {
                return SessionReloadResult::failed(id, current_socket, "configuration_not_found");
            }
            Err(SessionConfigFileError::Unavailable) => {
                return SessionReloadResult::failed(
                    id,
                    current_socket,
                    "configuration_unavailable",
                );
            }
            Err(SessionConfigFileError::Invalid) => {
                return SessionReloadResult::failed(id, current_socket, "configuration_invalid");
            }
        };
        let mut candidate = match ControlRequest::from_toml(&text) {
            Ok(ControlRequest::Create { session, .. }) => session,
            _ => {
                return SessionReloadResult::failed(id, current_socket, "configuration_invalid");
            }
        };
        // Persistence is the lifetime chosen at creation. A file edit cannot
        // turn a leased session into a persistent one or end its lease.
        candidate.persistent = persistent;
        let candidate_secrets = match secret_store.resolve(owner_uid, &candidate) {
            Ok(secrets) => Arc::new(secrets),
            Err(_) => {
                return SessionReloadResult::failed(id, current_socket, "credentials_unavailable");
            }
        };
        let target_path = self.socket_dir.join(
            candidate
                .socket_name
                .as_deref()
                .map(str::to_owned)
                .unwrap_or_else(|| format!("{id}.sock")),
        );
        let target_path = match absolute_socket_path(&target_path) {
            Ok(path) => path,
            Err(_) => {
                return SessionReloadResult::failed(id, current_socket, "listener_unavailable");
            }
        };
        let current_path = PathBuf::from(&current_socket);
        let same_path = target_path == current_path;
        let configuration_unchanged = same_effective_rules(&candidate.rules, &{
            let registry = self.registry.lock().await;
            let Some(session) = registry.sessions.get(id) else {
                return SessionReloadResult::failed(id, current_socket, "session_unavailable");
            };
            session.configuration.rules.clone()
        });
        if configuration_unchanged
            && same_path
            && current_secrets.has_same_values(&candidate_secrets)
        {
            return SessionReloadResult::unchanged(id, current_socket);
        }

        if same_path {
            let mut registry = self.registry.lock().await;
            if !registry.accepting_sessions {
                return SessionReloadResult::failed(id, current_socket, "session_stopping");
            }
            let Some(session) = registry.sessions.get_mut(id) else {
                return SessionReloadResult::failed(id, current_socket, "session_unavailable");
            };
            let Some(runtime) = session.runtime.as_ref() else {
                return SessionReloadResult::failed(id, current_socket, "session_stopping");
            };
            if runtime
                .replace_generation(&candidate, Arc::clone(&candidate_secrets))
                .is_err()
            {
                return SessionReloadResult::failed(id, current_socket, "generation_limit");
            }
            session.configuration = candidate;
            session.secrets = candidate_secrets;
            session.info.generation = session.info.generation.saturating_add(1);
            session.info.draining_generations = session.retired_runtimes.len();
            return SessionReloadResult::reloaded(id, current_socket);
        }

        let (permits, listener_gate, next_listener_generation, can_retire) = {
            let mut registry = self.registry.lock().await;
            if !registry.accepting_sessions {
                return SessionReloadResult::failed(id, current_socket, "session_stopping");
            }
            let Some(session) = registry.sessions.get_mut(id) else {
                return SessionReloadResult::failed(id, current_socket, "session_unavailable");
            };
            session
                .retired_runtimes
                .retain(|runtime| !runtime.is_finished());
            let Some(runtime) = session.runtime.as_ref() else {
                return SessionReloadResult::failed(id, current_socket, "session_stopping");
            };
            let Some(next_listener_generation) = session.listener_generation.checked_add(1) else {
                return SessionReloadResult::failed(id, current_socket, "generation_limit");
            };
            (
                runtime.connection_permits(),
                Arc::clone(&session.listener_gate),
                next_listener_generation,
                session.retired_runtimes.len() < MAX_RETIRED_LISTENERS,
            )
        };
        if !can_retire {
            return SessionReloadResult::failed(id, current_socket, "generation_limit");
        }
        let replacement = match ProxyRuntime::start_replacement_with_metrics(
            RuntimeId::new(id.to_owned()),
            candidate.clone(),
            Arc::clone(&candidate_secrets),
            Arc::clone(&self.ca),
            target_path.clone(),
            permits,
            self.io_timeout,
            Arc::clone(&self.metrics),
            self.runtime_events.clone(),
            Arc::clone(&listener_gate),
            next_listener_generation,
        )
        .await
        {
            Ok(runtime) => runtime,
            Err(_) => {
                return SessionReloadResult::failed(id, current_socket, "listener_unavailable");
            }
        };

        let mut registry = self.registry.lock().await;
        if !registry.accepting_sessions {
            drop(registry);
            replacement.shutdown(self.shutdown_grace).await;
            return SessionReloadResult::failed(id, current_socket, "session_stopping");
        }
        let Some(session) = registry.sessions.get_mut(id) else {
            drop(registry);
            replacement.shutdown(self.shutdown_grace).await;
            return SessionReloadResult::failed(id, current_socket, "session_unavailable");
        };
        if session.info.state != SessionLifecycle::Running {
            drop(registry);
            replacement.shutdown(self.shutdown_grace).await;
            return SessionReloadResult::failed(id, current_socket, "session_stopping");
        }
        let Some(old_runtime) = session.runtime.replace(replacement) else {
            session.runtime = None;
            drop(registry);
            return SessionReloadResult::failed(id, current_socket, "session_stopping");
        };
        session.configuration = candidate;
        session.secrets = candidate_secrets;
        session.info.socket = target_path.to_string_lossy().into_owned();
        session.info.generation = session.info.generation.saturating_add(1);
        session.listener_generation = next_listener_generation;
        old_runtime.mark_retiring();
        session
            .listener_gate
            .store(next_listener_generation, Ordering::Release);
        old_runtime.retire();
        session.retired_runtimes.push(old_runtime);
        session.info.draining_generations = session.retired_runtimes.len();
        SessionReloadResult::reloaded(id, session.info.socket.clone())
    }
}

fn absolute_socket_path(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

struct ManagedSession {
    info: SessionInfo,
    owner_uid: u32,
    // Keep the validated configuration with its runtime. Secret values are
    // held separately and neither value is included in list responses.
    configuration: SessionConfig,
    // Secret values remain scoped to this session and are never serialized.
    secrets: Arc<ResolvedSecrets>,
    config_source: Option<String>,
    runtime: Option<ProxyRuntime>,
    retired_runtimes: Vec<ProxyRuntime>,
    reload_lock: Arc<Mutex<()>>,
    listener_gate: Arc<AtomicU64>,
    listener_generation: u64,
}

#[derive(Debug)]
enum SessionError {
    AtCapacity,
    Runtime(ProxyRuntimeError),
    ShuttingDown,
    Internal,
}

#[derive(Debug, Clone, Serialize)]
struct SessionInfo {
    id: String,
    socket: String,
    persistent: bool,
    state: SessionLifecycle,
    generation: u64,
    draining_generations: usize,
}

#[derive(Debug, Clone, Serialize)]
struct SessionReloadResult {
    id: String,
    status: ReloadStatus,
    socket: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

impl SessionReloadResult {
    fn reloaded(id: &str, socket: String) -> Self {
        Self {
            id: id.to_owned(),
            status: ReloadStatus::Reloaded,
            socket,
            reason: None,
        }
    }

    fn unchanged(id: &str, socket: String) -> Self {
        Self {
            id: id.to_owned(),
            status: ReloadStatus::Unchanged,
            socket,
            reason: None,
        }
    }

    fn failed(id: &str, socket: String, reason: &'static str) -> Self {
        Self {
            id: id.to_owned(),
            status: ReloadStatus::Failed,
            socket,
            reason: Some(reason),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReloadStatus {
    Reloaded,
    Unchanged,
    Failed,
}

fn same_effective_rules(
    left: &[crate::config::HostRule],
    right: &[crate::config::HostRule],
) -> bool {
    fn canonical(rules: &[crate::config::HostRule]) -> Vec<crate::config::HostRule> {
        let mut rules = rules.to_vec();
        for rule in &mut rules {
            rule.ports.sort_unstable();
            rule.paths.sort_by_key(|path| path.as_str());
            for injection in &mut rule.inject {
                injection.header.make_ascii_lowercase();
            }
            rule.inject
                .sort_by(|left, right| left.header.cmp(&right.header));
        }
        rules.sort_by(|left, right| left.host.cmp(&right.host));
        rules
    }

    canonical(left) == canonical(right)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SessionLifecycle {
    Running,
    Stopping,
}

fn new_session_id() -> io::Result<String> {
    let mut random = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let mut id = String::with_capacity(random.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in random {
        id.push(char::from(HEX[usize::from(byte >> 4)]));
        id.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
        sync::Arc,
        time::Duration,
    };

    use serde_json::Value;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{UnixListener, UnixStream},
        sync::{Semaphore, mpsc},
    };

    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};

    use crate::{
        ca::ManagedCa,
        config::{CaConfig, ControlRequest, DaemonSettings, SessionCreateMode},
        secrets::SecretStore,
        telemetry::Metrics,
    };

    use super::{ControlState, SessionError, SessionManager, handle_connection};

    fn session_manager(directory: &std::path::Path, max_sessions: usize) -> SessionManager {
        let key_pair = KeyPair::generate().expect("CA key should be generated");
        let mut parameters = CertificateParams::default();
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let certificate = parameters
            .self_signed(&key_pair)
            .expect("CA certificate should be generated");
        let certificate_path = directory.join("control-test-ca.pem");
        let private_key_path = directory.join("control-test-ca-key.pem");
        fs::write(&certificate_path, certificate.pem()).expect("CA certificate should be saved");
        fs::write(&private_key_path, key_pair.serialize_pem()).expect("CA key should be saved");
        fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600))
            .expect("CA key permissions should be restricted");
        let ca = Arc::new(
            ManagedCa::load(&CaConfig {
                certificate: certificate_path,
                private_key: private_key_path,
            })
            .expect("test CA should load"),
        );
        let (runtime_events, _receiver) = mpsc::unbounded_channel();
        let trusted_operator_uid = fs::metadata(directory)
            .expect("test directory should have metadata")
            .uid();
        let settings = DaemonSettings {
            control_socket: directory.join("control.sock"),
            socket_dir: directory.to_path_buf(),
            trusted_operator_uid,
            max_sessions,
            max_connections_per_session: 128,
            shutdown_grace_seconds: 1,
            control_read_timeout_ms: 1_000,
            max_provisioning_requests: 1,
            connection_timeout_ms: 1_000,
            io_timeout_ms: 1_000,
            session_config_dir: None,
            create_mode: SessionCreateMode::Inline,
        };
        SessionManager::new(&settings, ca, runtime_events, Arc::new(Metrics::default()))
    }

    fn state(directory: &std::path::Path, uid: u32, allowed: &[&str]) -> ControlState {
        ControlState {
            trusted_operator_uid: uid,
            create_mode: SessionCreateMode::Inline,
            read_timeout: Duration::from_secs(1),
            secret_store: SecretStore::new(
                directory.to_path_buf(),
                uid,
                allowed.iter().map(|name| (*name).to_owned()).collect(),
            ),
            sessions: session_manager(directory, 1),
            provisioning_slots: Arc::new(Semaphore::new(1)),
            session_configs: None,
        }
    }

    async fn connect_handler(
        listener: &UnixListener,
        state: Arc<ControlState>,
    ) -> (UnixStream, tokio::task::JoinHandle<()>) {
        let client = UnixStream::connect(listener.local_addr().unwrap().as_pathname().unwrap())
            .await
            .expect("test client should connect");
        let (server, _) = listener
            .accept()
            .await
            .expect("server should accept client");
        let task = tokio::spawn(async move {
            handle_connection(server, state).await;
        });
        (client, task)
    }

    async fn write_request(client: &mut UnixStream, body: &str) {
        client
            .write_all(&(body.len() as u32).to_be_bytes())
            .await
            .expect("frame header should be written");
        client
            .write_all(body.as_bytes())
            .await
            .expect("frame payload should be written");
    }

    async fn read_response(client: &mut UnixStream) -> (Vec<u8>, Value) {
        let mut header = [0; 4];
        client
            .read_exact(&mut header)
            .await
            .expect("response header should be complete");
        let mut body = vec![0; u32::from_be_bytes(header) as usize];
        client
            .read_exact(&mut body)
            .await
            .expect("response body should be complete");
        let response = serde_json::from_slice(&body).expect("response should be JSON");
        (body, response)
    }

    #[tokio::test]
    async fn denies_a_peer_whose_uid_differs_from_the_configured_operator() {
        let directory = tempfile::tempdir().expect("test directory should be created");
        let socket = directory.path().join("auth.sock");
        let listener = UnixListener::bind(&socket).expect("test socket should bind");
        let mut client = UnixStream::connect(&socket)
            .await
            .expect("test client should connect");
        let (server, _) = listener
            .accept()
            .await
            .expect("server should accept client");
        let peer_uid = server
            .peer_cred()
            .expect("peer credentials should be available")
            .uid();
        let state = Arc::new(ControlState {
            trusted_operator_uid: peer_uid.wrapping_add(1),
            create_mode: SessionCreateMode::Inline,
            read_timeout: Duration::from_secs(1),
            secret_store: SecretStore::new(
                directory.path().to_path_buf(),
                peer_uid.wrapping_add(1),
                Default::default(),
            ),
            sessions: session_manager(directory.path(), 1),
            provisioning_slots: Arc::new(Semaphore::new(1)),
            session_configs: None,
        });
        let task = tokio::spawn(async move {
            handle_connection(server, state).await;
        });

        let request = b"version = 1\noperation = \"list\"\n";
        client
            .write_all(&(request.len() as u32).to_be_bytes())
            .await
            .expect("frame header should be written");
        client
            .write_all(request)
            .await
            .expect("frame payload should be written");
        let mut header = [0; 4];
        client
            .read_exact(&mut header)
            .await
            .expect("error response header should be complete");
        let mut body = vec![0; u32::from_be_bytes(header) as usize];
        client
            .read_exact(&mut body)
            .await
            .expect("error response body should be complete");
        let response: Value = serde_json::from_slice(&body).expect("response should be JSON");
        assert_eq!(response["error"]["code"], "unauthorized");
        task.await.expect("connection handler should finish");
    }

    #[tokio::test]
    async fn refuses_unentitled_secret_before_creating_a_session() {
        let directory = tempfile::tempdir().expect("test directory should be created");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("secret directory should be private");
        let secret_path = directory.path().join("api-token");
        fs::write(&secret_path, "credential-must-not-leak").expect("test secret should be written");
        fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600))
            .expect("test secret should be private");

        let socket = directory.path().join("control.sock");
        let listener = UnixListener::bind(&socket).expect("test socket should bind");
        let uid = fs::metadata(directory.path())
            .expect("test directory should have metadata")
            .uid();
        let control_state = Arc::new(state(directory.path(), uid, &[]));
        let (mut client, task) = connect_handler(&listener, Arc::clone(&control_state)).await;
        let request = "version = 1\noperation = \"create\"\n\n[session]\npersistent = true\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"api-token\"\nformat = \"bearer\"\n";
        write_request(&mut client, request).await;
        let (body, response) = read_response(&mut client).await;

        assert_eq!(response["error"]["code"], "secret_unavailable");
        assert!(!String::from_utf8_lossy(&body).contains("credential-must-not-leak"));
        task.await.expect("control handler should finish");
        assert!(
            control_state.sessions.list(uid).await.is_empty(),
            "unauthorized references must fail before session creation"
        );
    }

    #[tokio::test]
    async fn provisioning_limit_rejects_an_excess_create_request() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let uid = fs::metadata(directory.path())
            .expect("test directory should have metadata")
            .uid();
        let control_state = state(directory.path(), uid, &[]);
        let occupied = control_state
            .provisioning_slots
            .clone()
            .try_acquire_owned()
            .expect("the configured single provisioning slot should be available");
        let control_state = Arc::new(control_state);
        let socket = directory.path().join("provisioning.sock");
        let listener = UnixListener::bind(&socket).expect("test socket should bind");
        let (mut client, task) = connect_handler(&listener, Arc::clone(&control_state)).await;
        write_request(
            &mut client,
            "version = 1\noperation = \"create\"\n\n[session]\npersistent = true\n\n[[rules]]\nhost = \"busy.example.test\"\nmode = \"tunnel\"\n",
        )
        .await;
        let (_, response) = read_response(&mut client).await;
        assert_eq!(response["error"]["code"], "busy");
        assert!(control_state.sessions.list(uid).await.is_empty());
        drop(occupied);
        task.await.expect("control handler should finish");
    }

    #[tokio::test]
    async fn concurrent_provisioning_reservations_enforce_the_session_limit() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("test directory should be private");
        let uid = fs::metadata(directory.path())
            .expect("test directory should have metadata")
            .uid();
        let manager = session_manager(directory.path(), 1);
        let request = ControlRequest::from_toml(
            "version = 1\noperation = \"create\"\n\n[session]\npersistent = true\n\n[[rules]]\nhost = \"limit.example.test\"\nmode = \"tunnel\"\n",
        )
        .expect("test request should parse");
        let ControlRequest::Create { session, .. } = request else {
            panic!("test request should create a session");
        };
        let secret_store =
            SecretStore::new(directory.path().to_path_buf(), uid, Default::default());
        let first_secrets = secret_store
            .resolve(uid, &session)
            .expect("empty secret requirements should resolve");
        let second_secrets = secret_store
            .resolve(uid, &session)
            .expect("empty secret requirements should resolve");

        let (first, second) = tokio::join!(
            manager.create(uid, session.clone(), first_secrets, None),
            manager.create(uid, session.clone(), second_secrets, None),
        );
        assert_eq!(u8::from(first.is_ok()) + u8::from(second.is_ok()), 1);
        let created = match (first, second) {
            (Ok(created), Err(SessionError::AtCapacity))
            | (Err(SessionError::AtCapacity), Ok(created)) => created,
            _ => panic!("one create should reserve the only session slot"),
        };
        assert_eq!(manager.list(uid).await.len(), 1);
        assert!(matches!(
            manager
                .create(
                    uid,
                    session.clone(),
                    secret_store
                        .resolve(uid, &session)
                        .expect("empty secret requirements should resolve"),
                    None,
                )
                .await,
            Err(super::SessionError::AtCapacity)
        ));
        assert!(manager.stop(&created.id, uid).await);
    }

    #[tokio::test]
    async fn authorized_create_keeps_secret_private_from_control_responses() {
        let directory = tempfile::tempdir().expect("test directory should be created");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("secret directory should be private");
        let secret_path = directory.path().join("api-token");
        fs::write(&secret_path, "credential-must-not-leak").expect("test secret should be written");
        fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600))
            .expect("test secret should be private");
        let uid = fs::metadata(directory.path())
            .expect("test directory should have metadata")
            .uid();
        let state = Arc::new(state(directory.path(), uid, &["api-token"]));
        let socket = directory.path().join("control.sock");
        let listener = UnixListener::bind(&socket).expect("test socket should bind");
        let (mut client, task) = connect_handler(&listener, Arc::clone(&state)).await;
        let request = "version = 1\noperation = \"create\"\n\n[session]\npersistent = true\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"api-token\"\nformat = \"bearer\"\n";
        write_request(&mut client, request).await;
        let (body, response) = read_response(&mut client).await;
        task.await.expect("control handler should finish");

        assert!(response["ok"].as_bool().expect("ok should be boolean"));
        assert!(!String::from_utf8_lossy(&body).contains("credential-must-not-leak"));
        let id = response["result"]["id"]
            .as_str()
            .expect("created session should have an id");
        assert!(state.sessions.list(uid.wrapping_add(1)).await.is_empty());
        assert!(!state.sessions.stop(id, uid.wrapping_add(1)).await);
        let registry = state.sessions.registry.lock().await;
        let created = registry
            .sessions
            .get(id)
            .expect("session should be retained");
        assert_eq!(created.owner_uid, uid);
        assert_eq!(created.configuration.rules[0].host, "example.com");
        assert_eq!(
            created
                .secrets
                .get("api-token")
                .expect("session should own its resolved secret")
                .as_str(),
            "credential-must-not-leak"
        );
    }
}

#[cfg(test)]
mod startup_lock_tests {
    use super::{StartupLock, remove_stale_socket};
    use std::{
        os::unix::{
            fs::{MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
        sync::mpsc,
        thread,
        time::Duration,
    };

    #[test]
    fn serializes_stale_socket_cleanup_through_listener_bind() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("control directory should be private");
        let uid = std::fs::metadata(directory.path())
            .expect("control directory metadata should be readable")
            .uid();
        let socket = directory.path().join("control.sock");

        drop(UnixListener::bind(&socket).expect("stale test socket should bind"));
        let first_lock = StartupLock::acquire(&socket, uid).expect("first startup should lock");
        assert!(
            remove_stale_socket(&socket, uid).expect("stale socket should be removed"),
            "the first startup should remove the disconnected socket"
        );
        let listener = UnixListener::bind(&socket).expect("first startup should bind listener");

        let socket_for_second = socket.clone();
        let (started_sender, started_receiver) = mpsc::channel();
        let (finished_sender, finished_receiver) = mpsc::channel();
        let second_start = thread::spawn(move || {
            started_sender
                .send(())
                .expect("test should observe the second start");
            let _lock = StartupLock::acquire(&socket_for_second, uid)
                .expect("second startup should acquire the lock after the first binds");
            let removed = remove_stale_socket(&socket_for_second, uid)
                .expect("active socket check should succeed");
            let bind_failed = UnixListener::bind(&socket_for_second).is_err();
            finished_sender
                .send((removed, bind_failed))
                .expect("test should observe the second start result");
        });

        started_receiver
            .recv()
            .expect("second startup should reach the lock");
        assert!(
            finished_receiver
                .recv_timeout(Duration::from_millis(50))
                .is_err(),
            "second startup must wait while the first holds the lock through bind"
        );
        drop(first_lock);

        assert_eq!(
            finished_receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("second startup should continue after the first binds"),
            (false, true),
            "second startup must preserve the active socket and fail to bind"
        );
        second_start
            .join()
            .expect("second startup thread should finish");
        assert!(
            UnixStream::connect(&socket).is_ok(),
            "first startup's listener should remain reachable"
        );
        drop(listener);
    }
}
