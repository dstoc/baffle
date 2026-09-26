use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::Path,
    sync::Arc,
};

use anyhow::{Context, Result, bail};

const MAX_SESSION_CONFIG_BYTES: usize = 256 * 1024;

#[derive(Clone)]
pub(super) struct SessionConfigStore {
    directory: Arc<File>,
    trusted_uid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SessionConfigFileError {
    NotFound,
    Unavailable,
    Invalid,
}

impl SessionConfigStore {
    pub(super) fn open(directory: &Path, trusted_uid: u32) -> Result<Self> {
        let directory = open_trusted_directory_tree(directory, trusted_uid)?;
        Ok(Self {
            directory: Arc::new(directory),
            trusted_uid,
        })
    }

    pub(super) fn read_snapshot(
        &self,
        name: &str,
    ) -> std::result::Result<String, SessionConfigFileError> {
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
