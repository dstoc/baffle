use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File},
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, PermissionsExt},
        },
    },
    path::Path,
    sync::Arc,
};

use anyhow::{Context, Result, bail};

use crate::config::{
    CredentialMode, MAX_SESSION_CONFIG_NAME_BYTES, SessionConfig, SessionFile, UnmatchedHostPolicy,
};
use crate::platform::{directory_open_flags, normalize_system_path};

const MAX_SESSION_CONFIG_BYTES: usize = 256 * 1024;
const MAX_SESSION_IMPORT_DEPTH: usize = 32;
const MAX_SESSION_IMPORT_FILES: usize = 128;

#[derive(Clone)]
pub(super) struct SessionConfigStore {
    directory: Arc<File>,
    trusted_uid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SessionConfigFileErrorKind {
    NotFound,
    Unavailable,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SessionConfigFileError {
    pub(super) kind: SessionConfigFileErrorKind,
    pub(super) detail: String,
}

impl SessionConfigFileError {
    fn new(kind: SessionConfigFileErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    fn invalid(detail: impl Into<String>) -> Self {
        Self::new(SessionConfigFileErrorKind::Invalid, detail)
    }

    pub(super) fn create_code(&self) -> &'static str {
        match self.kind {
            SessionConfigFileErrorKind::NotFound => "config_file_not_found",
            SessionConfigFileErrorKind::Unavailable => "config_file_unavailable",
            SessionConfigFileErrorKind::Invalid => "config_file_invalid",
        }
    }

    pub(super) fn reload_reason(&self) -> &'static str {
        match self.kind {
            SessionConfigFileErrorKind::NotFound => "configuration_not_found",
            SessionConfigFileErrorKind::Unavailable => "configuration_unavailable",
            SessionConfigFileErrorKind::Invalid => "configuration_invalid",
        }
    }
}

impl SessionConfigStore {
    pub(super) fn open(directory: &Path, trusted_uid: u32) -> Result<Self> {
        let normalized_directory = normalize_system_path(directory);
        let directory = open_trusted_directory_tree(&normalized_directory, trusted_uid)?;
        Ok(Self {
            directory: Arc::new(directory),
            trusted_uid,
        })
    }

    pub(super) fn read_session(
        &self,
        name: &str,
    ) -> std::result::Result<SessionConfig, SessionConfigFileError> {
        let mut composition = Composition::default();
        self.compose_file(name, true, &mut composition)?;
        let root = composition.root.ok_or_else(|| {
            SessionConfigFileError::invalid("the root session configuration was not loaded")
        })?;
        Ok(SessionConfig {
            persistent: root.persistent,
            socket_name: root.socket_name,
            unmatched: composition.root_unmatched.unwrap_or_default(),
            default_credential_mode: composition.root_credential_default,
            credential_modes: composition.credential_modes,
            rules: composition.rules,
        })
    }

    fn compose_file(
        &self,
        name: &str,
        is_root: bool,
        composition: &mut Composition,
    ) -> std::result::Result<(), SessionConfigFileError> {
        if composition.stack.iter().any(|path| path == name) {
            return Err(SessionConfigFileError::invalid(format!(
                "session configuration import cycle includes `{name}`"
            )));
        }
        if composition.loaded.contains(name) {
            return Ok(());
        }
        if composition.stack.len() >= MAX_SESSION_IMPORT_DEPTH {
            return Err(SessionConfigFileError::invalid(format!(
                "session configuration import depth exceeds {MAX_SESSION_IMPORT_DEPTH} files"
            )));
        }
        if composition.stack.len() + composition.loaded.len() >= MAX_SESSION_IMPORT_FILES {
            return Err(SessionConfigFileError::invalid(format!(
                "session configuration imports exceed {MAX_SESSION_IMPORT_FILES} unique files"
            )));
        }

        composition.stack.push(name.to_owned());
        let result = self.compose_file_contents(name, is_root, composition);
        composition.stack.pop();
        if result.is_ok() {
            composition.loaded.insert(name.to_owned());
        }
        result
    }

    fn compose_file_contents(
        &self,
        name: &str,
        is_root: bool,
        composition: &mut Composition,
    ) -> std::result::Result<(), SessionConfigFileError> {
        let text = self.read_snapshot(name)?;
        let mut document: toml::Value = toml::from_str(&text).map_err(|_| {
            SessionConfigFileError::invalid(format!(
                "session configuration `{name}` has invalid TOML syntax or values"
            ))
        })?;
        let table = document.as_table_mut().ok_or_else(|| {
            SessionConfigFileError::invalid(format!(
                "session configuration `{name}` must contain a TOML table"
            ))
        })?;

        if !is_root && (table.contains_key("persistent") || table.contains_key("socket_name")) {
            return Err(SessionConfigFileError::invalid(format!(
                "imported session configuration `{name}` cannot set `persistent` or `socket_name`; set lifecycle and identity fields in the root file"
            )));
        }

        let imports = match table.remove("imports") {
            None => Vec::new(),
            Some(toml::Value::Array(imports)) => imports
                .into_iter()
                .map(|import| {
                    import.as_str().map(str::to_owned).ok_or_else(|| {
                        SessionConfigFileError::invalid(format!(
                            "`imports` in `{name}` must contain only relative path strings"
                        ))
                    })
                })
                .collect::<std::result::Result<Vec<_>, _>>()?,
            Some(_) => {
                return Err(SessionConfigFileError::invalid(format!(
                    "`imports` in `{name}` must be an array of relative path strings"
                )));
            }
        };

        for import in imports {
            let imported_name = resolve_import_name(name, &import)?;
            self.compose_file(&imported_name, false, composition)?;
        }

        let explicit_unmatched = table.contains_key("unmatched");
        let policy_text = toml::to_string(&document).map_err(|_| {
            SessionConfigFileError::invalid(format!(
                "session configuration `{name}` could not be decoded"
            ))
        })?;
        let policy = SessionFile::from_toml(&policy_text).map_err(|error| {
            SessionConfigFileError::invalid(format!("session configuration `{name}`: {error}"))
        })?;

        if explicit_unmatched {
            let current = if is_root {
                &mut composition.root_unmatched
            } else {
                &mut composition.imported_unmatched
            };
            if current.is_some_and(|current| current != policy.unmatched) {
                return Err(SessionConfigFileError::invalid(format!(
                    "conflicting `unmatched` settings in the import graph at `{name}`; imported values must agree"
                )));
            }
            *current = Some(policy.unmatched);
        }

        if let Some(mode) = policy.default_credential_mode {
            let current = if is_root {
                &mut composition.root_credential_default
            } else {
                &mut composition.imported_credential_default
            };
            if current.is_some_and(|current| current != mode) {
                return Err(SessionConfigFileError::invalid(format!(
                    "conflicting credential default modes in the import graph at `{name}`; imported values must agree"
                )));
            }
            *current = Some(mode);
        }

        for (secret, mode) in policy.credential_modes {
            if composition
                .credential_modes
                .insert(secret.clone(), mode)
                .is_some_and(|existing| existing != mode)
            {
                return Err(SessionConfigFileError::invalid(format!(
                    "conflicting mode for credential `{secret}` in the import graph"
                )));
            }
        }

        for rule in policy.rules {
            if !composition.hosts.insert(rule.host.clone()) {
                return Err(SessionConfigFileError::invalid(format!(
                    "host rule `{}` is defined more than once in the import graph; define it in one file only",
                    rule.host
                )));
            }
            composition.rules.push(rule);
        }

        if is_root {
            let root_unmatched = composition.root_unmatched.unwrap_or_default();
            if composition
                .imported_unmatched
                .is_some_and(|imported| imported != root_unmatched)
            {
                return Err(SessionConfigFileError::invalid(format!(
                    "imported `unmatched` settings conflict with the root file's effective value `{}`; set the same value in the root file",
                    match root_unmatched {
                        UnmatchedHostPolicy::Deny => "deny",
                        UnmatchedHostPolicy::Tunnel => "tunnel",
                    }
                )));
            }
            let root_credential_mode = composition
                .root_credential_default
                .unwrap_or(CredentialMode::Inject);
            if composition
                .imported_credential_default
                .is_some_and(|imported| imported != root_credential_mode)
            {
                return Err(SessionConfigFileError::invalid(format!(
                    "imported credential default modes conflict with the root file's effective value `{}`; set the same value in the root file",
                    credential_mode_name(root_credential_mode)
                )));
            }
            composition.root = Some(RootSettings {
                persistent: policy.persistent,
                socket_name: policy.socket_name,
            });
        }
        Ok(())
    }

    fn read_snapshot(&self, name: &str) -> std::result::Result<String, SessionConfigFileError> {
        let mut components = name.split('/').peekable();
        let mut directory = self
            .directory
            .try_clone()
            .map_err(|_| unavailable_file(name))?;

        while let Some(component) = components.next() {
            let component = std::ffi::CString::new(component.as_bytes())
                .map_err(|_| invalid_file(name, "contains an invalid path component"))?;
            if components.peek().is_some() {
                directory = openat_file(
                    directory.as_raw_fd(),
                    &component,
                    directory_open_flags() | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
                .map_err(|error| classify_config_file_io(error, name))?;
                let metadata = directory.metadata().map_err(|_| unavailable_file(name))?;
                validate_config_directory_metadata(&metadata, self.trusted_uid, false)
                    .map_err(|_| unavailable_file(name))?;
            } else {
                let file = openat_file(
                    directory.as_raw_fd(),
                    &component,
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                )
                .map_err(|error| classify_config_file_io(error, name))?;
                let metadata = file.metadata().map_err(|_| unavailable_file(name))?;
                let mode = metadata.permissions().mode();
                if !metadata.is_file()
                    || !trusted_owner(metadata.uid(), self.trusted_uid)
                    || mode & 0o7022 != 0
                    || mode & 0o444 == 0
                {
                    return Err(unavailable_file(name));
                }
                if metadata.len() > MAX_SESSION_CONFIG_BYTES as u64 {
                    return Err(invalid_file(name, "exceeds the 256 KiB size limit"));
                }
                let mut bytes = Vec::with_capacity(metadata.len() as usize);
                file.take((MAX_SESSION_CONFIG_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)
                    .map_err(|_| unavailable_file(name))?;
                if bytes.len() > MAX_SESSION_CONFIG_BYTES {
                    return Err(invalid_file(name, "exceeds the 256 KiB size limit"));
                }
                return String::from_utf8(bytes)
                    .map_err(|_| invalid_file(name, "must contain UTF-8 text"));
            }
        }
        Err(invalid_file(name, "has an empty path"))
    }
}

fn credential_mode_name(mode: CredentialMode) -> &'static str {
    match mode {
        CredentialMode::Inject => "inject",
        CredentialMode::Substitute => "substitute",
        CredentialMode::Disabled => "disabled",
    }
}

#[derive(Default)]
struct Composition {
    stack: Vec<String>,
    loaded: HashSet<String>,
    hosts: HashSet<String>,
    rules: Vec<crate::config::HostRule>,
    imported_unmatched: Option<UnmatchedHostPolicy>,
    root_unmatched: Option<UnmatchedHostPolicy>,
    imported_credential_default: Option<CredentialMode>,
    root_credential_default: Option<CredentialMode>,
    credential_modes: BTreeMap<String, CredentialMode>,
    root: Option<RootSettings>,
}

struct RootSettings {
    persistent: bool,
    socket_name: Option<String>,
}

fn resolve_import_name(
    importing_name: &str,
    import: &str,
) -> std::result::Result<String, SessionConfigFileError> {
    let invalid = || {
        SessionConfigFileError::invalid(format!(
            "`imports` in `{importing_name}` must contain relative TOML file paths within the session configuration directory"
        ))
    };
    if import.is_empty()
        || import.len() > MAX_SESSION_CONFIG_NAME_BYTES
        || import.starts_with('/')
        || import.contains(['\\', ':'])
        || import.chars().any(char::is_control)
    {
        return Err(invalid());
    }

    let mut components = importing_name
        .rsplit_once('/')
        .map(|(parent, _)| parent.split('/').map(str::to_owned).collect::<Vec<_>>())
        .unwrap_or_default();
    for component in import.split('/') {
        match component {
            "" => return Err(invalid()),
            "." => {}
            ".." => {
                if components.pop().is_none() {
                    return Err(invalid());
                }
            }
            component => components.push(component.to_owned()),
        }
    }
    let name = components.join("/");
    baffle_client::validate_session_config_name(&name).map_err(|_| invalid())?;
    Ok(name)
}

fn invalid_file(name: &str, detail: &str) -> SessionConfigFileError {
    SessionConfigFileError::invalid(format!("session configuration `{name}` {detail}"))
}

fn unavailable_file(name: &str) -> SessionConfigFileError {
    SessionConfigFileError::new(
        SessionConfigFileErrorKind::Unavailable,
        format!("session configuration `{name}` could not be read safely"),
    )
}

fn open_trusted_directory_tree(path: &Path, trusted_uid: u32) -> Result<File> {
    if !path.is_absolute() {
        bail!("session configuration directory must be absolute");
    }
    let root = unsafe {
        libc::open(
            c"/".as_ptr(),
            directory_open_flags() | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if root == -1 {
        return Err(io::Error::last_os_error())
            .context("could not open filesystem root for session configuration");
    }
    let mut directory = unsafe { File::from_raw_fd(root) };
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
            directory_open_flags() | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
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

fn classify_config_file_io(error: io::Error, name: &str) -> SessionConfigFileError {
    if error.kind() == io::ErrorKind::NotFound {
        SessionConfigFileError::new(
            SessionConfigFileErrorKind::NotFound,
            format!("session configuration `{name}` was not found"),
        )
    } else {
        unavailable_file(name)
    }
}
