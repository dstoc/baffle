use std::{
    collections::HashSet,
    fs,
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
};

use serde::Deserialize;

const DEFAULT_MAX_SESSIONS: usize = 64;
const DEFAULT_MAX_CONNECTIONS_PER_SESSION: usize = 128;
const DEFAULT_SHUTDOWN_GRACE_SECONDS: u64 = 5;
const DEFAULT_CONTROL_READ_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_MAX_PROVISIONING_REQUESTS: usize = 8;
const DEFAULT_IO_TIMEOUT_MS: u64 = 30_000;
use super::{ConfigError, deserialize, policy::validate_allowed_secrets};

/// Validated daemon configuration, ready for use by the daemon runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonConfig {
    pub daemon: DaemonSettings,
    pub ca: CaConfig,
    pub secrets: SecretStoreConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonSettings {
    pub control_socket: PathBuf,
    pub socket_dir: PathBuf,
    pub trusted_operator_uid: u32,
    pub max_sessions: usize,
    pub max_connections_per_session: usize,
    pub shutdown_grace_seconds: u64,
    pub control_read_timeout_ms: u64,
    pub max_provisioning_requests: usize,
    pub io_timeout_ms: u64,
    pub session_config_dir: Option<PathBuf>,
    pub create_mode: SessionCreateMode,
}

/// Selects how the daemon accepts requests to create sessions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionCreateMode {
    /// Accept session policy TOML in the control request.
    #[default]
    Inline,
    /// Accept only names of daemon-managed TOML files.
    FileOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaConfig {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretStoreConfig {
    pub directory: PathBuf,
    pub allowed: HashSet<String>,
}

impl DaemonConfig {
    /// Parse and validate a daemon TOML document.
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        Self::from_toml_in_directory(input, None)
    }

    fn from_toml_in_directory(
        input: &str,
        config_directory: Option<&Path>,
    ) -> Result<Self, ConfigError> {
        let raw: RawDaemonConfig = deserialize(input)?;
        let raw = match config_directory {
            Some(directory) => raw.resolve_paths(directory),
            None => raw,
        };

        let session_config_dir = match (raw.daemon.create_mode, raw.daemon.session_config_dir) {
            (SessionCreateMode::Inline, None) => None,
            (SessionCreateMode::Inline, Some(_)) => {
                return Err(ConfigError::new(
                    "daemon.session_config_dir requires daemon.create_mode = \"file_only\"",
                ));
            }
            (SessionCreateMode::FileOnly, None) => {
                return Err(ConfigError::new(
                    "daemon.session_config_dir is required when daemon.create_mode is \"file_only\"",
                ));
            }
            (SessionCreateMode::FileOnly, Some(path)) => {
                validate_session_config_dir(&path)?;
                Some(path)
            }
        };

        let daemon = DaemonSettings {
            control_socket: required_path(raw.daemon.control_socket, "daemon.control_socket")?,
            socket_dir: required_path(raw.daemon.socket_dir, "daemon.socket_dir")?,
            trusted_operator_uid: raw.daemon.trusted_operator_uid,
            max_sessions: raw.daemon.max_sessions,
            max_connections_per_session: raw.daemon.max_connections_per_session,
            shutdown_grace_seconds: raw.daemon.shutdown_grace_seconds,
            control_read_timeout_ms: raw.daemon.control_read_timeout_ms,
            max_provisioning_requests: raw.daemon.max_provisioning_requests,
            io_timeout_ms: raw.daemon.io_timeout_ms,
            session_config_dir,
            create_mode: raw.daemon.create_mode,
        };
        if daemon.max_sessions == 0 {
            return Err(ConfigError::new(
                "daemon.max_sessions must be greater than zero",
            ));
        }
        if daemon.max_connections_per_session == 0 {
            return Err(ConfigError::new(
                "daemon.max_connections_per_session must be greater than zero",
            ));
        }
        if daemon.control_read_timeout_ms == 0 {
            return Err(ConfigError::new(
                "daemon.control_read_timeout_ms must be greater than zero",
            ));
        }
        if daemon.max_provisioning_requests == 0 {
            return Err(ConfigError::new(
                "daemon.max_provisioning_requests must be greater than zero",
            ));
        }
        if daemon.io_timeout_ms == 0 {
            return Err(ConfigError::new(
                "daemon.io_timeout_ms must be greater than zero",
            ));
        }

        Ok(Self {
            daemon,
            ca: CaConfig {
                certificate: required_path(raw.ca.certificate, "ca.certificate")?,
                private_key: required_path(raw.ca.private_key, "ca.private_key")?,
            },
            secrets: SecretStoreConfig {
                directory: required_path(raw.secrets.directory, "secrets.directory")?,
                allowed: validate_allowed_secrets(raw.secrets.allowed)?,
            },
        })
    }

    /// Read, parse, and validate a daemon TOML file without performing runtime operations.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let input = fs::read_to_string(path)
            .map_err(|_| ConfigError::new("could not read daemon configuration file"))?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let absolute_parent = if parent.is_absolute() {
            parent.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|_| ConfigError::new("could not resolve daemon configuration directory"))?
                .join(parent)
        };
        // Drop `.` components without resolving `..` or symlinks. Later path
        // validation must still see those components in configured paths.
        let config_directory = absolute_parent
            .components()
            .filter(|component| !matches!(component, Component::CurDir))
            .fold(PathBuf::new(), |mut path, component| {
                path.push(component.as_os_str());
                path
            });
        Self::from_toml_in_directory(&input, Some(&config_directory))
    }
}

impl RawDaemonConfig {
    fn resolve_paths(mut self, directory: &Path) -> Self {
        self.daemon.control_socket = resolve_config_path(self.daemon.control_socket, directory);
        self.daemon.socket_dir = resolve_config_path(self.daemon.socket_dir, directory);
        self.daemon.session_config_dir = self
            .daemon
            .session_config_dir
            .map(|path| resolve_config_path(path, directory));
        self.ca.certificate = resolve_config_path(self.ca.certificate, directory);
        self.ca.private_key = resolve_config_path(self.ca.private_key, directory);
        self.secrets.directory = resolve_config_path(self.secrets.directory, directory);
        self
    }
}

fn resolve_config_path(path: PathBuf, directory: &Path) -> PathBuf {
    if path.as_os_str().is_empty() || path.is_absolute() {
        path
    } else {
        directory.join(path)
    }
}

fn required_path(path: PathBuf, field: &str) -> Result<PathBuf, ConfigError> {
    if path.as_os_str().is_empty() {
        return Err(ConfigError::new(format!("{field} must not be empty")));
    }
    Ok(path)
}
fn validate_session_config_dir(path: &Path) -> Result<(), ConfigError> {
    let path_bytes = path.as_os_str().as_bytes();
    if !path.is_absolute()
        || path.as_os_str().is_empty()
        || path_bytes.contains(&0)
        || path_bytes
            .split(|byte| *byte == b'/')
            .any(|component| component == b"." || component == b"..")
        || path.components().any(|component| {
            !matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
        || path.components().count() < 2
    {
        return Err(ConfigError::new(
            "daemon.session_config_dir must be an absolute directory path without dot components",
        ));
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDaemonConfig {
    daemon: RawDaemonSettings,
    ca: RawCaConfig,
    secrets: RawSecretStoreConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDaemonSettings {
    control_socket: PathBuf,
    socket_dir: PathBuf,
    trusted_operator_uid: u32,
    #[serde(default = "default_max_sessions")]
    max_sessions: usize,
    #[serde(default = "default_max_connections_per_session")]
    max_connections_per_session: usize,
    #[serde(default = "default_shutdown_grace_seconds")]
    shutdown_grace_seconds: u64,
    #[serde(default = "default_control_read_timeout_ms")]
    control_read_timeout_ms: u64,
    #[serde(default = "default_max_provisioning_requests")]
    max_provisioning_requests: usize,
    #[serde(default = "default_io_timeout_ms")]
    io_timeout_ms: u64,
    #[serde(default)]
    session_config_dir: Option<PathBuf>,
    #[serde(default)]
    create_mode: SessionCreateMode,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCaConfig {
    certificate: PathBuf,
    private_key: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSecretStoreConfig {
    directory: PathBuf,
    #[serde(default)]
    allowed: Vec<String>,
}

fn default_max_sessions() -> usize {
    DEFAULT_MAX_SESSIONS
}

fn default_max_connections_per_session() -> usize {
    DEFAULT_MAX_CONNECTIONS_PER_SESSION
}

fn default_shutdown_grace_seconds() -> u64 {
    DEFAULT_SHUTDOWN_GRACE_SECONDS
}

fn default_control_read_timeout_ms() -> u64 {
    DEFAULT_CONTROL_READ_TIMEOUT_MS
}

fn default_max_provisioning_requests() -> usize {
    DEFAULT_MAX_PROVISIONING_REQUESTS
}

fn default_io_timeout_ms() -> u64 {
    DEFAULT_IO_TIMEOUT_MS
}
