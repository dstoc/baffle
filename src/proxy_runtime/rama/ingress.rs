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

use crate::{
    platform::{directory_open_flags, normalize_system_path},
    telemetry::Metrics,
};

use super::{ProxyGeneration, ProxyRuntimeError, connect, tls};

const UNIX_SOCKET_PATH_BYTES: usize =
    std::mem::size_of::<libc::sockaddr_un>() - std::mem::offset_of!(libc::sockaddr_un, sun_path);

pub(super) struct ProxySettings {
    pub(super) generations: watch::Receiver<Arc<ProxyGeneration>>,
    pub(super) tls_relay: Arc<tls::CachedRelay>,
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
        tls_relay,
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
                let tls_relay = Arc::clone(&tls_relay);
                let metrics = Arc::clone(&metrics);
                connections.spawn(async move {
                    let _permit = permit;
                    metrics.connection_started();
                    let _guard = ConnectionGuard(Arc::clone(&metrics));
                    if let Err(error) = connect::handle_client(
                        stream,
                        Arc::clone(&generation.policy),
                        Arc::clone(&generation.secrets),
                        tls_relay,
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
    device: libc::dev_t,
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
        if absolute.as_os_str().as_bytes().len() >= UNIX_SOCKET_PATH_BYTES {
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
        #[cfg(target_os = "linux")]
        let bind_path = PathBuf::from(format!(
            "/proc/self/fd/{}/{}",
            parent.as_raw_fd(),
            name.to_string_lossy()
        ));
        #[cfg(not(target_os = "linux"))]
        let bind_path = normalized.clone();
        let listener = UnixListener::bind(&bind_path)?;
        let identity = stat_at(parent.as_raw_fd(), &name)?
            .ok_or_else(|| io::Error::other("bound Unix socket disappeared"))?;
        let guard = Self {
            path: normalized,
            parent,
            name,
            device: identity.st_dev,
            inode: identity.st_ino,
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
    device: libc::dev_t,
    inode: u64,
}

struct DirectoryRecord {
    parent: OwnedFd,
    name: CString,
    device: libc::dev_t,
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
            release_directory_lease(&mut registry, key, unlink_directory_at);
        }
    }
}

fn release_directory_lease(
    registry: &mut HashMap<DirectoryKey, DirectoryRecord>,
    key: DirectoryKey,
    remove_directory: impl FnOnce(&DirectoryRecord) -> io::Result<()>,
) {
    let removal = {
        let Some(record) = registry.get_mut(&key) else {
            return;
        };
        record.leases = record.leases.saturating_sub(1);
        if record.leases != 0 {
            return;
        }
        if !record.created_by_baffle {
            None
        } else {
            let matches = stat_at(record.parent.as_raw_fd(), &record.name)
                .ok()
                .flatten()
                .is_some_and(|metadata| {
                    metadata.st_mode & libc::S_IFMT == libc::S_IFDIR
                        && metadata.st_dev == record.device
                        && metadata.st_ino == record.inode
                });
            matches.then(|| (record.path.clone(), remove_directory(record)))
        }
    };

    if let Some((path, Err(error))) = removal
        && error.kind() != io::ErrorKind::NotFound
    {
        tracing::debug!(path = %path.display(), %error, "failed to remove session socket directory");
    }

    // The registry owns a descriptor clone for each record. Its lifetime must
    // end with the last lease even when the filesystem directory remains.
    registry.remove(&key);
}

fn unlink_directory_at(record: &DirectoryRecord) -> io::Result<()> {
    if unsafe {
        libc::unlinkat(
            record.parent.as_raw_fd(),
            record.name.as_ptr(),
            libc::AT_REMOVEDIR,
        )
    } == -1
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
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
    let logical_absolute_parent = if parent_path.is_absolute() {
        parent_path.to_path_buf()
    } else {
        std::env::current_dir()?.join(parent_path)
    };
    let absolute_parent = normalize_system_path(&logical_absolute_parent);
    let root = unsafe {
        libc::open(
            c"/".as_ptr(),
            directory_open_flags() | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
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
                directory_open_flags() | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
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
                    directory_open_flags() | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
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
        if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "socket path component is not a directory",
            ));
        }
        if made
            && let Err(error) =
                set_created_directory_mode(current.as_raw_fd(), &component, &metadata)
        {
            remove_created_directory_if_unchanged(current.as_raw_fd(), &component, &metadata);
            return Err(error);
        }
        normalized.push(component.to_string_lossy().as_ref());
        let registered =
            register_directory(&current, &component, &metadata, normalized.clone(), made);
        match registered {
            Ok(key) => created.0.push(key),
            Err(error) => {
                if made {
                    remove_created_directory_if_unchanged(
                        current.as_raw_fd(),
                        &component,
                        &metadata,
                    );
                }
                return Err(error);
            }
        }
        current = next;
    }
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing socket name"))?;
    let logical_path = logical_absolute_parent.join(name);
    Ok((current, logical_path))
}

fn set_created_directory_mode(
    parent: libc::c_int,
    name: &CString,
    expected: &libc::stat,
) -> io::Result<()> {
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    let directory = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(directory.as_raw_fd(), metadata.as_mut_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let metadata = unsafe { metadata.assume_init() };
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
        || metadata.st_dev != expected.st_dev
        || metadata.st_ino != expected.st_ino
    {
        return Err(io::Error::other(
            "created socket directory changed before permission setup",
        ));
    }
    if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn remove_created_directory_if_unchanged(
    parent: libc::c_int,
    name: &CString,
    expected: &libc::stat,
) {
    if stat_at(parent, name).is_ok_and(|current| {
        current.is_some_and(|metadata| {
            metadata.st_mode & libc::S_IFMT == libc::S_IFDIR
                && metadata.st_dev == expected.st_dev
                && metadata.st_ino == expected.st_ino
        })
    }) {
        unsafe {
            libc::unlinkat(parent, name.as_ptr(), libc::AT_REMOVEDIR);
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::File, os::fd::RawFd};

    fn register_test_directory(parent_path: &Path, name: &str) -> (DirectoryKey, RawFd, OwnedFd) {
        let parent = OwnedFd::from(File::open(parent_path).expect("open test directory parent"));
        let name = CString::new(name).expect("test directory name has no nul byte");
        let metadata = stat_at(parent.as_raw_fd(), &name)
            .expect("inspect test directory")
            .expect("test directory exists");
        let path = parent_path.join(name.to_string_lossy().as_ref());
        let key = register_directory(&parent, &name, &metadata, path, true)
            .expect("register test directory");
        let registry = DIRECTORY_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
        let descriptor = registry
            .lock()
            .expect("lock directory registry")
            .get(&key)
            .expect("registered directory record")
            .parent
            .as_raw_fd();
        (key, descriptor, parent)
    }

    fn assert_descriptor_released(descriptor: RawFd, parent: &OwnedFd) {
        let mut actual = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(descriptor, actual.as_mut_ptr()) } == -1 {
            let error = io::Error::last_os_error();
            assert_eq!(
                error.raw_os_error(),
                Some(libc::EBADF),
                "released descriptor returned an unexpected error: {error}"
            );
            return;
        }
        let actual = unsafe { actual.assume_init() };
        let mut expected = std::mem::MaybeUninit::<libc::stat>::uninit();
        assert_eq!(
            unsafe { libc::fstat(parent.as_raw_fd(), expected.as_mut_ptr()) },
            0,
            "test parent descriptor must remain open"
        );
        let expected = unsafe { expected.assume_init() };
        assert!(
            actual.st_dev != expected.st_dev || actual.st_ino != expected.st_ino,
            "released descriptor number must not still refer to its directory parent"
        );
    }

    fn assert_registry_entry(key: DirectoryKey, expected: bool) {
        let registry = DIRECTORY_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
        assert_eq!(
            registry
                .lock()
                .expect("lock directory registry")
                .contains_key(&key),
            expected
        );
    }

    #[test]
    fn zero_lease_removes_empty_directory_and_releases_record() {
        let parent = tempfile::tempdir().expect("create parent directory");
        let path = parent.path().join("session-sockets");
        fs::create_dir(&path).expect("create session socket directory");
        let (key, descriptor, parent_fd) =
            register_test_directory(parent.path(), "session-sockets");

        drop(CreatedDirectorySet(vec![key]));

        assert!(!path.exists());
        assert_registry_entry(key, false);
        assert_descriptor_released(descriptor, &parent_fd);
    }

    #[test]
    fn not_found_after_identity_check_releases_zero_lease_record() {
        let parent = tempfile::tempdir().expect("create parent directory");
        let path = parent.path().join("session-sockets");
        fs::create_dir(&path).expect("create session socket directory");
        let (key, descriptor, parent_fd) =
            register_test_directory(parent.path(), "session-sockets");
        let registry = DIRECTORY_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
        let mut registry = registry.lock().expect("lock directory registry");

        // Simulate a concurrent removal after the inode check. The following
        // unlinkat must return NotFound, and the zero-lease record must still go.
        release_directory_lease(&mut registry, key, |record| {
            fs::remove_dir(&path)?;
            let error = unlink_directory_at(record).expect_err("missing directory must fail");
            assert_eq!(error.kind(), io::ErrorKind::NotFound);
            Err(error)
        });

        assert!(!path.exists());
        assert!(!registry.contains_key(&key));
        drop(registry);
        assert_descriptor_released(descriptor, &parent_fd);
    }

    #[test]
    fn nonempty_directory_keeps_contents_and_releases_record_and_descriptor() {
        let parent = tempfile::tempdir().expect("create parent directory");
        let path = parent.path().join("session-sockets");
        fs::create_dir(&path).expect("create session socket directory");
        fs::write(path.join("in-use.sock"), b"preserve").expect("add directory content");
        let (key, descriptor, parent_fd) =
            register_test_directory(parent.path(), "session-sockets");

        drop(CreatedDirectorySet(vec![key]));

        assert!(path.is_dir());
        assert_eq!(
            fs::read(path.join("in-use.sock")).expect("read preserved content"),
            b"preserve"
        );
        assert_registry_entry(key, false);
        assert_descriptor_released(descriptor, &parent_fd);

        let name = CString::new("session-sockets").expect("valid directory name");
        let metadata = stat_at(parent_fd.as_raw_fd(), &name)
            .expect("inspect existing session directory")
            .expect("nonempty session directory remains");
        let new_key = register_directory(&parent_fd, &name, &metadata, path.clone(), false)
            .expect("register existing directory for a later session");
        assert_eq!(new_key, key);
        let new_descriptor = {
            let registry = DIRECTORY_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
            let registry = registry.lock().expect("lock directory registry");
            assert_eq!(registry.get(&new_key).expect("new lease record").leases, 1);
            registry
                .get(&new_key)
                .expect("new lease record")
                .parent
                .as_raw_fd()
        };
        drop(CreatedDirectorySet(vec![new_key]));

        assert!(path.is_dir());
        assert_registry_entry(new_key, false);
        assert_descriptor_released(new_descriptor, &parent_fd);
    }
}
