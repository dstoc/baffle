//! Direct Unix-socket acceptance, connection admission, and socket ownership.

use std::{
    collections::HashMap,
    ffi::CString,
    fs, io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{ffi::OsStrExt, fs::PermissionsExt},
    },
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::{
    net::UnixListener,
    sync::{Semaphore, watch},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

use crate::{ca::ManagedCa, telemetry::Metrics};

use super::{ProxyGeneration, ProxyRuntimeError, connect};

pub(super) struct ProxySettings {
    pub(super) generations: watch::Receiver<Arc<ProxyGeneration>>,
    pub(super) ca: Arc<ManagedCa>,
    pub(super) permits: Arc<Semaphore>,
    pub(super) cancellation: CancellationToken,
    pub(super) retirement: CancellationToken,
    pub(super) listener_gate: Arc<AtomicU64>,
    pub(super) listener_generation: u64,
    pub(super) metrics: Arc<Metrics>,
    pub(super) io_timeout: Duration,
}

pub(super) async fn run_proxy(
    listener: UnixListener,
    socket_guard: Arc<Mutex<Option<UnixSocketGuard>>>,
    settings: ProxySettings,
) -> Result<(), ProxyRuntimeError> {
    let ProxySettings {
        generations,
        ca,
        permits,
        cancellation,
        retirement,
        listener_gate,
        listener_generation,
        metrics,
        io_timeout,
    } = settings;
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            _ = retirement.cancelled() => break,
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    return Err(ProxyRuntimeError::Task(error.to_string()));
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(ProxyRuntimeError::BindSocket)?;
                if listener_gate.load(Ordering::Acquire) != listener_generation {
                    drop(stream);
                    continue;
                }
                let generation = Arc::clone(&generations.borrow());
                let permit = match Arc::clone(&permits).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => continue,
                };
                let ca = Arc::clone(&ca);
                let metrics = Arc::clone(&metrics);
                connections.spawn(async move {
                    let _permit = permit;
                    metrics.connection_started();
                    let _guard = ConnectionGuard(Arc::clone(&metrics));
                    if let Err(error) = connect::handle_client(
                        stream,
                        Arc::clone(&generation.policy),
                        Arc::clone(&generation.secrets),
                        ca,
                        metrics,
                        io_timeout,
                    ).await {
                        tracing::debug!(?error, "Rama connection closed after a proxy error");
                    }
                });
            }
        }
    }
    drop(listener);
    if let Ok(mut socket_guard) = socket_guard.lock() {
        socket_guard.take();
    }
    while connections.join_next().await.is_some() {}
    Ok(())
}

pub(super) struct UnixSocketGuard {
    path: PathBuf,
    parent: OwnedFd,
    name: CString,
    device: u64,
    inode: u64,
    _created_directories: CreatedDirectorySet,
}

impl UnixSocketGuard {
    fn bind(path: &Path) -> io::Result<(UnixListener, Self)> {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        if absolute.as_os_str().as_bytes().len() >= 108 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unix socket path is too long",
            ));
        }
        let name = CString::new(
            absolute
                .file_name()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing socket name"))?
                .as_bytes(),
        )
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid socket name"))?;
        let (parent, created_directories, normalized) = open_socket_parent(&absolute)?;
        if stat_at(parent.as_raw_fd(), &name)?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "socket path exists",
            ));
        }
        // Binding through the held directory FD makes the final component
        // directory-confined even if an ancestor is renamed during setup.
        let bind_path = PathBuf::from(format!(
            "/proc/self/fd/{}/{}",
            parent.as_raw_fd(),
            name.to_string_lossy()
        ));
        let listener = UnixListener::bind(&bind_path)?;
        let identity = stat_at(parent.as_raw_fd(), &name)?
            .ok_or_else(|| io::Error::other("bound Unix socket disappeared"))?;
        let guard = Self {
            path: normalized,
            parent,
            name,
            device: identity.st_dev as u64,
            inode: identity.st_ino as u64,
            _created_directories: created_directories,
        };
        fs::set_permissions(&bind_path, fs::Permissions::from_mode(0o600))?;
        let current = stat_at(guard.parent.as_raw_fd(), &guard.name)?;
        if !current
            .as_ref()
            .is_some_and(|metadata| guard.matches(metadata))
            || current
                .as_ref()
                .is_some_and(|metadata| metadata.st_mode & 0o777 != 0o600)
        {
            return Err(io::Error::other(
                "bound Unix socket identity or permissions changed",
            ));
        }
        Ok((listener, guard))
    }

    fn matches(&self, metadata: &libc::stat) -> bool {
        metadata.st_mode & libc::S_IFMT == libc::S_IFSOCK
            && metadata.st_dev == self.device
            && metadata.st_ino == self.inode
    }

    pub(super) fn unlink_owned(&self) {
        match stat_at(self.parent.as_raw_fd(), &self.name) {
            Ok(Some(metadata)) if self.matches(&metadata) => {
                if unsafe { libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0) } == -1 {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::NotFound {
                        tracing::warn!(path = %self.path.display(), %error, "failed to remove Rama proxy Unix socket");
                    }
                }
            }
            Ok(Some(_)) => tracing::warn!(
                path = %self.path.display(),
                "Rama proxy socket path changed; leaving replacement untouched"
            ),
            Ok(None) => {}
            Err(error) => tracing::warn!(
                path = %self.path.display(),
                %error,
                "could not inspect Rama proxy socket during cleanup"
            ),
        }
    }
}

impl Drop for UnixSocketGuard {
    fn drop(&mut self) {
        self.unlink_owned();
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct DirectoryKey {
    device: u64,
    inode: u64,
}

struct DirectoryRecord {
    parent: OwnedFd,
    name: CString,
    device: u64,
    inode: u64,
    path: PathBuf,
    created_by_baffle: bool,
    leases: usize,
}

static DIRECTORY_REGISTRY: OnceLock<Mutex<HashMap<DirectoryKey, DirectoryRecord>>> =
    OnceLock::new();
static SOCKET_PARENT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

struct CreatedDirectorySet(Vec<DirectoryKey>);

impl Drop for CreatedDirectorySet {
    fn drop(&mut self) {
        // Provisioning holds this lock while it walks and registers directory
        // descriptors. Serialize removal with that walk so a newly opened
        // directory cannot be unlinked before its lease is registered.
        let path_lock = SOCKET_PARENT_LOCK.get_or_init(|| Mutex::new(()));
        let _path_lock = path_lock.lock().unwrap_or_else(|error| error.into_inner());
        let registry = DIRECTORY_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
        let mut registry = registry.lock().unwrap_or_else(|error| error.into_inner());
        while let Some(key) = self.0.pop() {
            let Some(record) = registry.get_mut(&key) else {
                continue;
            };
            record.leases = record.leases.saturating_sub(1);
            if record.leases != 0 {
                continue;
            }
            if !record.created_by_baffle {
                registry.remove(&key);
                continue;
            }
            let matches = stat_at(record.parent.as_raw_fd(), &record.name)
                .ok()
                .flatten()
                .is_some_and(|metadata| {
                    metadata.st_mode & libc::S_IFMT == libc::S_IFDIR
                        && metadata.st_dev == record.device
                        && metadata.st_ino == record.inode
                });
            if !matches {
                registry.remove(&key);
                continue;
            }
            if unsafe {
                libc::unlinkat(
                    record.parent.as_raw_fd(),
                    record.name.as_ptr(),
                    libc::AT_REMOVEDIR,
                )
            } == 0
            {
                registry.remove(&key);
            } else {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::NotFound {
                    registry.remove(&key);
                } else {
                    tracing::debug!(path = %record.path.display(), %error, "left non-empty session socket directory");
                }
            }
        }
    }
}

fn register_directory(
    parent: &OwnedFd,
    name: &CString,
    metadata: &libc::stat,
    path: PathBuf,
    created_by_baffle: bool,
) -> io::Result<DirectoryKey> {
    let key = DirectoryKey {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    };
    let registry = DIRECTORY_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let mut registry = registry.lock().unwrap_or_else(|error| error.into_inner());
    let record = registry.entry(key).or_insert(DirectoryRecord {
        parent: parent.try_clone()?,
        name: name.clone(),
        device: key.device,
        inode: key.inode,
        path,
        created_by_baffle,
        leases: 0,
    });
    record.created_by_baffle |= created_by_baffle;
    record.leases += 1;
    Ok(key)
}

fn open_socket_parent(path: &Path) -> io::Result<(OwnedFd, CreatedDirectorySet, PathBuf)> {
    let path_lock = SOCKET_PARENT_LOCK.get_or_init(|| Mutex::new(()));
    let mut created = CreatedDirectorySet(Vec::new());
    let result = {
        let _path_lock = path_lock.lock().unwrap_or_else(|error| error.into_inner());
        open_socket_parent_locked(path, &mut created)
    };
    match result {
        Ok((parent, normalized)) => Ok((parent, created, normalized)),
        Err(error) => {
            drop(created);
            Err(error)
        }
    }
}

fn open_socket_parent_locked(
    path: &Path,
    created: &mut CreatedDirectorySet,
) -> io::Result<(OwnedFd, PathBuf)> {
    let parent_path = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let absolute_parent = if parent_path.is_absolute() {
        parent_path.to_path_buf()
    } else {
        std::env::current_dir()?.join(parent_path)
    };
    let root = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut current = unsafe { OwnedFd::from_raw_fd(root) };
    let mut normalized = PathBuf::from("/");
    for component in absolute_parent.components() {
        let component = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::ParentDir => {
                CString::new("..").expect("parent component contains no nul byte")
            }
            Component::Normal(name) => CString::new(name.as_bytes()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid directory name")
            })?,
            Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid socket path",
                ));
            }
        };
        let mut made = false;
        let mut fd = unsafe {
            libc::openat(
                current.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd == -1 && io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
            let mkdir = unsafe { libc::mkdirat(current.as_raw_fd(), component.as_ptr(), 0o700) };
            if mkdir == 0 {
                made = true;
            } else if io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
                return Err(io::Error::last_os_error());
            }
            fd = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    component.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
        }
        if fd == -1 {
            return Err(io::Error::last_os_error());
        }
        let next = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(next.as_raw_fd(), metadata.as_mut_ptr()) } == -1 {
            return Err(io::Error::last_os_error());
        }
        let metadata = unsafe { metadata.assume_init() };
        if made {
            unsafe {
                libc::fchmod(next.as_raw_fd(), 0o700);
            }
        }
        normalized.push(component.to_string_lossy().as_ref());
        let registered =
            register_directory(&current, &component, &metadata, normalized.clone(), made);
        match registered {
            Ok(key) => created.0.push(key),
            Err(error) => {
                if made {
                    unsafe {
                        libc::unlinkat(current.as_raw_fd(), component.as_ptr(), libc::AT_REMOVEDIR);
                    }
                }
                return Err(error);
            }
        }
        current = next;
    }
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing socket name"))?;
    let normalized = normalized.join(name);
    Ok((current, normalized))
}

fn stat_at(parent: libc::c_int, name: &CString) -> io::Result<Option<libc::stat>> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent,
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        return Ok(Some(unsafe { metadata.assume_init() }));
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(None)
    } else {
        Err(error)
    }
}

pub(super) fn bind_unix_listener(path: &Path) -> io::Result<(UnixListener, UnixSocketGuard)> {
    UnixSocketGuard::bind(path)
}

struct ConnectionGuard(Arc<Metrics>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.connection_stopped();
    }
}
