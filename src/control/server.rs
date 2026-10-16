use std::{
    ffi::{CStr, CString, OsStr, OsString},
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::{OsStrExt, OsStringExt},
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

use crate::config::{
    ControlRequest, DaemonConfig, PROTOCOL_VERSION, SESSION_FILE_INVALID_MESSAGE, SessionCreateMode,
};
use crate::secrets::{SecretStore, SecretStoreError};
use crate::{
    ca::ManagedCa,
    config::SessionConfig,
    platform::normalize_system_path,
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
const ERR_CONFIG_FILE_INVALID: (&str, &str) = ("config_file_invalid", SESSION_FILE_INVALID_MESSAGE);

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

        let (runtime_event_sender, runtime_events) = tokio::sync::mpsc::unbounded_channel();
        let metrics = Arc::new(Metrics::default());
        let server = Self {
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
        };

        info!(
            path = %control_socket.display(),
            trusted_operator_uid = trusted_uid,
            "control socket listening"
        );

        Ok(server)
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
    let absolute_path = normalize_system_path(&absolute_path);

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
    let parent_path = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = CString::new(
        path.file_name()
            .ok_or_else(|| anyhow::anyhow!("socket path has no file name"))?
            .as_bytes(),
    )
    .context("socket path contains a null byte")?;
    let parent = open_socket_directory(parent_path)
        .with_context(|| format!("could not open socket directory {}", parent_path.display()))?;
    remove_stale_socket_at(&parent, &name, path, expected_uid)
}

fn remove_stale_session_sockets(directory: &Path, expected_uid: u32) -> Result<()> {
    let directory_fd = open_socket_directory(directory).with_context(|| {
        format!(
            "could not open session socket directory {}",
            directory.display()
        )
    })?;
    remove_stale_session_sockets_at(&directory_fd, directory, expected_uid, &mut |_| {})
}

fn open_socket_directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
}

fn remove_stale_session_sockets_at(
    directory: &File,
    display_path: &Path,
    expected_uid: u32,
    on_directory_open: &mut impl FnMut(&Path),
) -> Result<()> {
    for name in directory_entry_names(directory.as_raw_fd()).with_context(|| {
        format!(
            "could not read session socket directory {}",
            display_path.display()
        )
    })? {
        let name_c =
            CString::new(name.as_bytes()).context("directory entry contains a null byte")?;
        let path = display_path.join(&name);
        let Some(metadata) = stat_at(directory.as_raw_fd(), &name_c)
            .with_context(|| format!("could not inspect {}", path.display()))?
        else {
            continue;
        };
        match metadata.st_mode & libc::S_IFMT {
            libc::S_IFDIR => {
                let child_fd = unsafe {
                    libc::openat(
                        directory.as_raw_fd(),
                        name_c.as_ptr(),
                        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                    )
                };
                if child_fd == -1 {
                    let error = io::Error::last_os_error();
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                    ) || error.raw_os_error() == Some(libc::ELOOP)
                    {
                        continue;
                    }
                    return Err(error).with_context(|| {
                        format!(
                            "could not open nested session socket directory {}",
                            path.display()
                        )
                    });
                }
                // SAFETY: openat returned a new descriptor owned by this File.
                let child = unsafe { File::from_raw_fd(child_fd) };
                let opened = child
                    .metadata()
                    .with_context(|| format!("could not inspect {}", path.display()))?;
                if opened.dev() != metadata.st_dev || opened.ino() != metadata.st_ino {
                    continue;
                }
                on_directory_open(&path);
                remove_stale_session_sockets_at(&child, &path, expected_uid, on_directory_open)?;
            }
            libc::S_IFSOCK => {
                remove_stale_socket_at(directory, &name_c, &path, expected_uid)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn remove_stale_socket_at(
    parent: &File,
    name: &CString,
    display_path: &Path,
    expected_uid: u32,
) -> Result<bool> {
    let Some(metadata) = stat_at(parent.as_raw_fd(), name)
        .with_context(|| format!("could not inspect {}", display_path.display()))?
    else {
        return Ok(false);
    };
    if metadata.st_mode & libc::S_IFMT != libc::S_IFSOCK || metadata.st_uid != expected_uid {
        return Ok(false);
    }

    let socket_path = pinned_socket_path(parent.as_raw_fd(), name).with_context(|| {
        format!(
            "could not make a pinned path for {}",
            display_path.display()
        )
    })?;
    match StdUnixStream::connect(&socket_path) {
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
            let Some(current) = stat_at(parent.as_raw_fd(), name)
                .with_context(|| format!("could not recheck {}", display_path.display()))?
            else {
                return Ok(false);
            };
            if current.st_mode & libc::S_IFMT != libc::S_IFSOCK
                || current.st_uid != expected_uid
                || current.st_dev != metadata.st_dev
                || current.st_ino != metadata.st_ino
            {
                bail!("socket path changed during stale socket cleanup");
            }
            if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } == -1 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::NotFound {
                    return Ok(false);
                }
                return Err(error).with_context(|| {
                    format!("could not remove stale socket {}", display_path.display())
                });
            }
            Ok(true)
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "could not check whether socket {} is active",
                display_path.display()
            )
        }),
    }
}

fn stat_at(parent_fd: libc::c_int, name: &CString) -> io::Result<Option<libc::stat>> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent_fd,
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        // SAFETY: fstatat initialized metadata when it returned success.
        return Ok(Some(unsafe { metadata.assume_init() }));
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(None)
    } else {
        Err(error)
    }
}

struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // SAFETY: this stream was returned by fdopendir and is closed exactly once.
        unsafe { libc::closedir(self.0) };
    }
}

fn directory_entry_names(directory_fd: libc::c_int) -> io::Result<Vec<OsString>> {
    let stream_fd = unsafe { libc::fcntl(directory_fd, libc::F_DUPFD_CLOEXEC, 0) };
    if stream_fd == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fdopendir takes ownership of stream_fd on success.
    let stream = unsafe { libc::fdopendir(stream_fd) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: fdopendir did not take ownership when it failed.
        unsafe { libc::close(stream_fd) };
        return Err(error);
    }
    let stream = DirectoryStream(stream);
    let mut names = Vec::new();
    loop {
        clear_errno();
        // SAFETY: stream is valid until DirectoryStream is dropped.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error().unwrap_or_default() != 0 {
                return Err(error);
            }
            break;
        }
        // SAFETY: readdir returned a dirent with a nul-terminated d_name.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        names.push(OsString::from_vec(name.to_bytes().to_vec()));
    }
    Ok(names)
}

#[cfg(target_os = "linux")]
fn clear_errno() {
    // SAFETY: libc exposes the calling thread's errno slot.
    unsafe { *libc::__errno_location() = 0 };
}

#[cfg(target_os = "macos")]
fn clear_errno() {
    // SAFETY: libc exposes the calling thread's errno slot.
    unsafe { *libc::__error() = 0 };
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn clear_errno() {}

#[cfg(target_os = "linux")]
fn pinned_socket_path(parent_fd: libc::c_int, name: &CString) -> io::Result<std::path::PathBuf> {
    let mut path = std::path::PathBuf::from(format!("/proc/self/fd/{parent_fd}"));
    path.push(OsStr::from_bytes(name.as_bytes()));
    Ok(path)
}

#[cfg(target_os = "macos")]
fn pinned_socket_path(parent_fd: libc::c_int, name: &CString) -> io::Result<std::path::PathBuf> {
    let mut path = std::path::PathBuf::from(format!("/dev/fd/{parent_fd}"));
    path.push(OsStr::from_bytes(name.as_bytes()));
    Ok(path)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn pinned_socket_path(_parent_fd: libc::c_int, _name: &CString) -> io::Result<std::path::PathBuf> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "descriptor-relative Unix socket connections are unavailable on this platform",
    ))
}

async fn handle_connection(mut stream: UnixStream, state: Arc<ControlState>) {
    match stream.peer_cred() {
        Ok(credentials) if credentials.uid() == state.trusted_operator_uid => {}
        _ => {
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
                        create_session_response(&state, session, None, permit, &mut lease_id).await
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
                let session = match crate::config::SessionFile::from_toml(&text) {
                    Ok(session) => session,
                    Err(_) => {
                        let _ = write_error(&mut stream, ERR_CONFIG_FILE_INVALID).await;
                        return;
                    }
                };
                create_session_response(&state, session, Some(name), permit, &mut lease_id).await
            }
        }
        ControlRequest::Stop { session_id, .. } => {
            if state.sessions.stop(&session_id).await {
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
                .reload_all(state.session_configs.as_ref(), &state.secret_store)
                .await;
            success(json!({ "results": results }))
        }
        ControlRequest::List { .. } => success(json!({
            "sessions": state.sessions.list().await,
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
    session: SessionConfig,
    config_source: Option<String>,
    permit: tokio::sync::OwnedSemaphorePermit,
    lease_id: &mut Option<String>,
) -> Value {
    let secrets = match state.secret_store.resolve(&session) {
        Ok(secrets) => secrets,
        Err(SecretStoreError::NotEntitled | SecretStoreError::Unavailable) => {
            return error_value(ERR_SECRET_UNAVAILABLE);
        }
    };
    let result = state.sessions.create(session, secrets, config_source).await;
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
            #[cfg(baffle_integration_test)]
            eprintln!("test-only proxy runtime startup error: {error:?}");
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
