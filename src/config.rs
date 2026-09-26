//! TOML configuration parsing and validation.
//!
//! Parsing this module's public configuration types performs all schema and
//! policy validation. It does not open sockets, resolve secrets, or make
//! network requests.

use std::{
    collections::HashSet,
    error::Error,
    fmt, fs,
    net::IpAddr,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, de::DeserializeOwned};
use url::Host;

pub const PROTOCOL_VERSION: u16 = 1;

const DEFAULT_MAX_SESSIONS: usize = 64;
const DEFAULT_MAX_CONNECTIONS_PER_SESSION: usize = 128;
const DEFAULT_SHUTDOWN_GRACE_SECONDS: u64 = 5;
const DEFAULT_CONTROL_READ_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_MAX_PROVISIONING_REQUESTS: usize = 8;
const DEFAULT_CONNECTION_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_IO_TIMEOUT_MS: u64 = 30_000;
pub(crate) const MAX_SESSION_CONFIG_NAME_BYTES: usize = 1_024;
const MAX_SESSION_CONFIG_COMPONENT_BYTES: usize = 255;

/// A safe configuration error. Error text never contains input values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    message: String,
    kind: ConfigErrorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigErrorKind {
    Invalid,
    UnsupportedProtocolVersion,
}

impl ConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: ConfigErrorKind::Invalid,
        }
    }

    fn unsupported_protocol_version() -> Self {
        Self {
            message: "unsupported control protocol version".into(),
            kind: ConfigErrorKind::UnsupportedProtocolVersion,
        }
    }

    pub(crate) fn is_unsupported_protocol_version(&self) -> bool {
        self.kind == ConfigErrorKind::UnsupportedProtocolVersion
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for ConfigError {}

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
    pub connection_timeout_ms: u64,
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
        let raw: RawDaemonConfig = deserialize(input)?;

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
            connection_timeout_ms: raw.daemon.connection_timeout_ms,
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
        Self::from_toml(&input)
    }
}

fn required_path(path: PathBuf, field: &str) -> Result<PathBuf, ConfigError> {
    if path.as_os_str().is_empty() {
        return Err(ConfigError::new(format!("{field} must not be empty")));
    }
    Ok(path)
}

/// A validated policy for one proxy session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfig {
    pub persistent: bool,
    /// Optional path relative to the daemon's session socket directory.
    pub socket_name: Option<String>,
    pub rules: Vec<HostRule>,
}

/// The supported per-host action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleMode {
    Tunnel,
    Intercept,
}

/// A validated exact-host policy rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRule {
    /// Lowercase DNS hostname without a trailing dot.
    pub host: String,
    pub mode: RuleMode,
    pub ports: Vec<u16>,
    pub paths: Vec<PathRule>,
    pub inject: Vec<HeaderInjection>,
}

/// A validated exact path or recursive path prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRule {
    path: String,
    recursive: bool,
}

impl PathRule {
    /// Return the canonical path pattern used by this rule.
    pub fn as_str(&self) -> String {
        if self.recursive {
            format!("{}**", self.path)
        } else {
            self.path.clone()
        }
    }

    pub fn is_recursive(&self) -> bool {
        self.recursive
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub(crate) fn matches_canonical_path(&self, path: &str) -> bool {
        if self.recursive {
            path.starts_with(&self.path)
        } else {
            path == self.path
        }
    }

    fn overlaps(&self, other: &Self) -> bool {
        match (self.recursive, other.recursive) {
            (false, false) => self.path == other.path,
            (true, false) => other.path.starts_with(&self.path),
            (false, true) => self.path.starts_with(&other.path),
            (true, true) => {
                self.path.starts_with(&other.path) || other.path.starts_with(&self.path)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectionFormat {
    Raw,
    Bearer,
    BasicPassword,
}

/// A symbolic secret reference. Its value is never a secret credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef(String);

impl SecretRef {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated declaration for injecting a daemon-managed secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderInjection {
    pub header: String,
    pub secret: SecretRef,
    pub format: InjectionFormat,
    pub username: Option<String>,
}

/// A validated control request. `Create` carries a validated policy, not raw TOML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlRequest {
    Create {
        version: u16,
        session: SessionConfig,
    },
    CreateFromFile {
        version: u16,
        name: String,
    },
    Stop {
        version: u16,
        session_id: String,
    },
    List {
        version: u16,
    },
}

impl ControlRequest {
    /// Parse and validate one TOML control request.
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let raw: RawControlRequest = deserialize(input)?;
        match raw {
            RawControlRequest::Create {
                version,
                session,
                rules,
            } => {
                validate_protocol_version(version)?;
                let rules = validate_rules(rules)?;
                Ok(Self::Create {
                    version,
                    session: SessionConfig {
                        persistent: session.persistent,
                        socket_name: session
                            .socket_name
                            .map(|name| validate_socket_name(&name))
                            .transpose()?,
                        rules,
                    },
                })
            }
            RawControlRequest::Stop {
                version,
                session_id,
            } => {
                validate_protocol_version(version)?;
                validate_session_id(&session_id)?;
                Ok(Self::Stop {
                    version,
                    session_id,
                })
            }
            RawControlRequest::CreateFromFile { version, name } => {
                validate_protocol_version(version)?;
                let name = validate_session_config_name(&name)?;
                Ok(Self::CreateFromFile { version, name })
            }
            RawControlRequest::List { version } => {
                validate_protocol_version(version)?;
                Ok(Self::List { version })
            }
        }
    }
}

fn validate_session_config_name(name: &str) -> Result<String, ConfigError> {
    if name.is_empty()
        || name.len() > MAX_SESSION_CONFIG_NAME_BYTES
        || !name.ends_with(".toml")
        || name.contains('\\')
        || name.contains(':')
        || name.chars().any(char::is_control)
    {
        return Err(ConfigError::new("session configuration name is invalid"));
    }

    let mut component_count = 0;
    for component in name.split('/') {
        component_count += 1;
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.len() > MAX_SESSION_CONFIG_COMPONENT_BYTES
        {
            return Err(ConfigError::new("session configuration name is invalid"));
        }
    }
    if component_count == 0 {
        return Err(ConfigError::new("session configuration name is invalid"));
    }
    Ok(name.to_owned())
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

fn validate_socket_name(input: &str) -> Result<String, ConfigError> {
    if input.is_empty() || input.starts_with('/') || input.contains(['\\', '\0']) {
        return Err(ConfigError::new(
            "session.socket_name must be a relative Unix socket path",
        ));
    }
    let components = input.split('/').collect::<Vec<_>>();
    if components
        .iter()
        .any(|component| component.is_empty() || *component == "." || *component == "..")
    {
        return Err(ConfigError::new(
            "session.socket_name must not contain empty, dot, or parent components",
        ));
    }
    if input.len() > 107 {
        return Err(ConfigError::new("session.socket_name is too long"));
    }
    Ok(input.to_owned())
}

fn validate_protocol_version(version: u16) -> Result<(), ConfigError> {
    if version != PROTOCOL_VERSION {
        return Err(ConfigError::unsupported_protocol_version());
    }
    Ok(())
}

fn validate_session_id(id: &str) -> Result<(), ConfigError> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ConfigError::new(
            "session_id must be a non-empty opaque identifier",
        ));
    }
    Ok(())
}

fn validate_rules(raw_rules: Vec<RawHostRule>) -> Result<Vec<HostRule>, ConfigError> {
    if raw_rules.is_empty() {
        return Err(ConfigError::new("create requires at least one rule"));
    }

    let mut hosts = HashSet::new();
    let mut rules = Vec::with_capacity(raw_rules.len());
    for (index, raw) in raw_rules.into_iter().enumerate() {
        let context = format!("rules[{index}]");
        let host = validate_hostname(&raw.host)
            .map_err(|message| ConfigError::new(format!("{context}.host {message}")))?;
        if !hosts.insert(host.clone()) {
            return Err(ConfigError::new(format!(
                "{context}.host duplicates another rule; use one rule per exact host"
            )));
        }

        if raw.ports.is_empty() {
            return Err(ConfigError::new(format!(
                "{context}.ports must not be empty"
            )));
        }
        let mut ports = HashSet::new();
        for port in &raw.ports {
            if *port == 0 {
                return Err(ConfigError::new(format!(
                    "{context}.ports entries must be between 1 and 65535"
                )));
            }
            if !ports.insert(*port) {
                return Err(ConfigError::new(format!(
                    "{context}.ports contains a duplicate"
                )));
            }
        }

        if raw.mode == RuleMode::Tunnel && !raw.inject.is_empty() {
            return Err(ConfigError::new(format!(
                "{context} tunnel rules cannot inject headers"
            )));
        }
        let mut paths = Vec::with_capacity(raw.paths.len());
        for (path_index, raw_path) in raw.paths.into_iter().enumerate() {
            let path = validate_path(&raw_path.0).map_err(|message| {
                ConfigError::new(format!("{context}.paths[{path_index}] {message}"))
            })?;
            if paths
                .iter()
                .any(|existing: &PathRule| existing.overlaps(&path))
            {
                return Err(ConfigError::new(format!(
                    "{context}.paths contains duplicate or overlapping patterns"
                )));
            }
            paths.push(path);
        }

        let mut inject = Vec::with_capacity(raw.inject.len());
        let mut headers = HashSet::new();
        for (inject_index, raw_injection) in raw.inject.into_iter().enumerate() {
            let injection_context = format!("{context}.inject[{inject_index}]");
            let header = validate_header(&raw_injection.header).map_err(|message| {
                ConfigError::new(format!("{injection_context}.header {message}"))
            })?;
            if !headers.insert(header.to_ascii_lowercase()) {
                return Err(ConfigError::new(format!(
                    "{injection_context}.header duplicates another injected header"
                )));
            }
            let secret = validate_secret_id(&raw_injection.secret.0).map_err(|message| {
                ConfigError::new(format!("{injection_context}.secret {message}"))
            })?;
            let username = match (raw_injection.format, raw_injection.username) {
                (InjectionFormat::BasicPassword, Some(username)) => {
                    validate_basic_username(&username).map_err(|message| {
                        ConfigError::new(format!("{injection_context}.username {message}"))
                    })?;
                    Some(username)
                }
                (InjectionFormat::BasicPassword, None) => {
                    return Err(ConfigError::new(format!(
                        "{injection_context}.username is required for basic_password"
                    )));
                }
                (_, Some(_)) => {
                    return Err(ConfigError::new(format!(
                        "{injection_context}.username is only valid for basic_password"
                    )));
                }
                (_, None) => None,
            };

            inject.push(HeaderInjection {
                header,
                secret,
                format: raw_injection.format,
                username,
            });
        }

        rules.push(HostRule {
            host,
            mode: raw.mode,
            ports: raw.ports,
            paths,
            inject,
        });
    }

    Ok(rules)
}

fn validate_hostname(input: &str) -> Result<String, &'static str> {
    if input.is_empty() || input.contains('*') {
        return Err("must be an exact DNS hostname");
    }
    let host = input.to_ascii_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host);
    if host.is_empty() || host.len() > 253 || host.parse::<IpAddr>().is_ok() || !host.is_ascii() {
        return Err("must be an exact DNS hostname, not an IP address or wildcard");
    }

    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err("contains an invalid DNS label");
        }
    }

    // Match the URL host parser used for HTTP destinations. It recognizes
    // non-canonical IPv4 forms such as 127.1, octal components, and a single
    // integer. Parsing is local and does not perform DNS resolution.
    match Host::parse(host) {
        Ok(Host::Domain(domain)) => Ok(domain),
        Ok(Host::Ipv4(_) | Host::Ipv6(_)) => {
            Err("must be an exact DNS hostname, not an IP address or wildcard")
        }
        Err(_) => Err("must be a valid exact DNS hostname"),
    }
}

fn validate_path(input: &str) -> Result<PathRule, &'static str> {
    if !input.starts_with('/') || input.contains(['?', '#', '\\']) {
        return Err("must be an absolute URL path without query, fragment, or backslash");
    }

    let (path, recursive) = if let Some(prefix) = input.strip_suffix("/**") {
        (
            if prefix.is_empty() {
                "/"
            } else {
                &input[..prefix.len() + 1]
            },
            true,
        )
    } else {
        (input, false)
    };
    if path.contains('*') {
        return Err("may use ** only as the final recursive path segment");
    }

    let canonical = canonicalize_path(path)?;

    Ok(PathRule {
        path: canonical,
        recursive,
    })
}

fn canonicalize_path(path: &str) -> Result<String, &'static str> {
    if !path.starts_with('/') || path.contains(['?', '#', '\\']) {
        return Err("must be an absolute URL path without query, fragment, or backslash");
    }

    let mut canonical = String::with_capacity(path.len());
    let bytes = path.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len() {
                return Err("contains malformed percent encoding");
            }
            let high = hex_value(bytes[index + 1]).ok_or("contains malformed percent encoding")?;
            let low = hex_value(bytes[index + 2]).ok_or("contains malformed percent encoding")?;
            let decoded = high * 16 + low;
            if matches!(decoded, b'/' | b'\\' | b'%') {
                return Err("contains an encoded path separator or ambiguous double encoding");
            }
            if is_unreserved(decoded) {
                canonical.push(char::from(decoded));
            } else {
                canonical.push('%');
                canonical.push(char::from(bytes[index + 1].to_ascii_uppercase()));
                canonical.push(char::from(bytes[index + 2].to_ascii_uppercase()));
            }
            index += 3;
            continue;
        }

        if !is_path_character(byte) {
            return Err("contains a character that is not valid in a URL path");
        }
        canonical.push(char::from(byte));
        index += 1;
    }

    if canonical.contains("//") {
        return Err("contains an ambiguous repeated path separator");
    }
    if canonical
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return Err("contains an unsafe dot segment");
    }

    Ok(canonical)
}

pub(crate) fn canonicalize_request_path(path: &str) -> Result<String, &'static str> {
    canonicalize_path(if path.is_empty() { "/" } else { path })
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn is_path_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'/' | b'-'
                | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
        )
}

fn validate_header(input: &str) -> Result<String, &'static str> {
    let prohibited = [
        "connection",
        "content-length",
        "forwarded",
        "host",
        "http2-settings",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-port",
        "x-forwarded-proto",
        "x-original-host",
        "x-original-url",
        "x-real-ip",
        "x-rewrite-url",
    ];
    if input.is_empty()
        || !input
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
    {
        return Err("must be a valid HTTP header name");
    }
    if prohibited.contains(&input.to_ascii_lowercase().as_str()) {
        return Err("is a hop-by-hop or routing-critical header");
    }
    Ok(input.to_string())
}

fn validate_secret_id(input: &str) -> Result<SecretRef, &'static str> {
    if input.is_empty()
        || input.len() > 64
        || !input
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || !input.as_bytes()[0].is_ascii_alphanumeric()
        || input
            .chars()
            .last()
            .is_some_and(|character| matches!(character, '.' | '-' | '_'))
        || input.contains("..")
    {
        return Err("must be a valid symbolic secret identifier");
    }
    Ok(SecretRef(input.to_string()))
}

fn validate_allowed_secrets(raw: Vec<RawSecretRef>) -> Result<HashSet<String>, ConfigError> {
    let mut allowed = HashSet::with_capacity(raw.len());
    for secret in raw {
        let secret = validate_secret_id(&secret.0).map_err(|_| {
            ConfigError::new("secrets.allowed must contain valid secret identifiers")
        })?;
        if !allowed.insert(secret.as_str().to_owned()) {
            return Err(ConfigError::new(
                "secrets.allowed must not contain duplicate secret identifiers",
            ));
        }
    }
    Ok(allowed)
}

fn validate_basic_username(input: &str) -> Result<(), &'static str> {
    if input.is_empty()
        || input.contains(':')
        || !input.bytes().all(|byte| (b' '..=b'~').contains(&byte))
    {
        return Err("must be printable ASCII and must not contain a colon");
    }
    Ok(())
}

fn deserialize<T: DeserializeOwned>(input: &str) -> Result<T, ConfigError> {
    toml::from_str(input).map_err(|_| {
        ConfigError::new("invalid TOML syntax, field type, or unsupported field (values omitted)")
    })
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
    #[serde(default = "default_connection_timeout_ms")]
    connection_timeout_ms: u64,
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
    allowed: Vec<RawSecretRef>,
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

fn default_connection_timeout_ms() -> u64 {
    DEFAULT_CONNECTION_TIMEOUT_MS
}

fn default_io_timeout_ms() -> u64 {
    DEFAULT_IO_TIMEOUT_MS
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum RawControlRequest {
    Create {
        version: u16,
        session: RawSessionSettings,
        #[serde(default)]
        rules: Vec<RawHostRule>,
    },
    Stop {
        version: u16,
        session_id: String,
    },
    CreateFromFile {
        version: u16,
        name: String,
    },
    List {
        version: u16,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSessionSettings {
    #[serde(default)]
    persistent: bool,
    #[serde(default)]
    socket_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHostRule {
    host: String,
    mode: RuleMode,
    #[serde(default = "default_ports")]
    ports: Vec<u16>,
    #[serde(default)]
    paths: Vec<RawPathRule>,
    #[serde(default)]
    inject: Vec<RawHeaderInjection>,
}

#[derive(Deserialize)]
#[serde(transparent)]
struct RawPathRule(String);

fn default_ports() -> Vec<u16> {
    vec![443]
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHeaderInjection {
    header: String,
    secret: RawSecretRef,
    format: InjectionFormat,
    username: Option<String>,
}

#[derive(Deserialize)]
#[serde(transparent)]
struct RawSecretRef(String);

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        CaConfig, ControlRequest, DaemonConfig, InjectionFormat, PROTOCOL_VERSION, RuleMode,
        SessionConfig, SessionCreateMode,
    };

    const DAEMON_EXAMPLE: &str = r#"
[daemon]
control_socket = "/run/baffle/control.sock"
socket_dir = "/run/baffle/proxies"
trusted_operator_uid = 1000
max_sessions = 64
max_connections_per_session = 128
shutdown_grace_seconds = 5

[ca]
certificate = "/var/lib/baffle/ca.pem"
private_key = "/var/lib/baffle/ca-key.pem"

[secrets]
directory = "/var/lib/baffle/secrets"
"#;

    const SESSION_EXAMPLE: &str = r#"
version = 1
operation = "create"

[session]
persistent = false

[[rules]]
host = "crates.io"
mode = "tunnel"
ports = [443]

[[rules]]
host = "api.github.com"
mode = "intercept"
ports = [443]
paths = ["/repos/dstoc/cladding", "/repos/dstoc/cladding/**"]

  [[rules.inject]]
  header = "Authorization"
  secret = "github-api"
  format = "bearer"

[[rules]]
host = "github.com"
mode = "intercept"
ports = [443]
paths = ["/dstoc/cladding.git/**"]

  [[rules.inject]]
  header = "Authorization"
  secret = "github-git"
  format = "basic_password"
  username = "x-access-token"
"#;

    const MINIMAL_CREATE: &str = r#"
version = 1
operation = "create"

[session]

[[rules]]
host = "Example.COM."
mode = "intercept"
"#;

    fn config_with(rule: &str) -> String {
        format!("version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\n{rule}\n")
    }

    #[test]
    fn parses_the_proposal_daemon_example_and_defaults_daemon_limits() {
        let config = DaemonConfig::from_toml(DAEMON_EXAMPLE)
            .expect("proposal daemon configuration should parse");
        assert_eq!(config.daemon.max_sessions, 64);
        assert_eq!(
            config.ca.certificate,
            PathBuf::from("/var/lib/baffle/ca.pem")
        );
        assert!(config.secrets.allowed.is_empty());

        let config = DaemonConfig::from_toml(
            r#"
[daemon]
control_socket = "/run/baffle/control.sock"
socket_dir = "/run/baffle/proxies"
trusted_operator_uid = 1000

[ca]
certificate = "/var/lib/baffle/ca.pem"
private_key = "/var/lib/baffle/ca-key.pem"

[secrets]
directory = "/var/lib/baffle/secrets"
"#,
        )
        .expect("omitted daemon limits should use defaults");
        assert_eq!(config.daemon.max_sessions, 64);
        assert_eq!(config.daemon.max_connections_per_session, 128);
        assert_eq!(config.daemon.shutdown_grace_seconds, 5);
        assert_eq!(config.daemon.trusted_operator_uid, 1000);
        assert_eq!(config.daemon.control_read_timeout_ms, 5_000);
        assert_eq!(config.daemon.max_provisioning_requests, 8);
        assert_eq!(config.daemon.connection_timeout_ms, 5_000);
        assert_eq!(config.daemon.io_timeout_ms, 30_000);
        assert_eq!(config.daemon.create_mode, SessionCreateMode::Inline);
        assert_eq!(config.daemon.session_config_dir, None);
    }

    #[test]
    fn requires_a_valid_directory_for_file_only_mode() {
        let base = r#"
[daemon]
control_socket = "/run/baffle/control.sock"
socket_dir = "/run/baffle/proxies"
trusted_operator_uid = 1000

[ca]
certificate = "/var/lib/baffle/ca.pem"
private_key = "/var/lib/baffle/ca-key.pem"

[secrets]
directory = "/var/lib/baffle/secrets"
"#;
        assert!(
            DaemonConfig::from_toml(
                &base.replace("\n[ca]", "\ncreate_mode = \"file_only\"\n\n[ca]")
            )
            .is_err(),
            "file-only mode must require a session configuration directory"
        );
        assert!(
            DaemonConfig::from_toml(&base.replace(
                "\n[ca]",
                "\nsession_config_dir = \"/var/lib/baffle/sessions\"\n\n[ca]",
            ))
            .is_err(),
            "inline mode must reject an unused session configuration directory"
        );
        let config = DaemonConfig::from_toml(&base.replace(
            "\n[ca]",
            "\ncreate_mode = \"file_only\"\nsession_config_dir = \"/var/lib/baffle/sessions\"\n\n[ca]",
        ))
        .expect("file-only mode with an absolute directory should parse");
        assert_eq!(config.daemon.create_mode, SessionCreateMode::FileOnly);
        assert_eq!(
            config.daemon.session_config_dir,
            Some(PathBuf::from("/var/lib/baffle/sessions"))
        );
        for invalid_path in [
            "relative/sessions",
            "/var/../sessions",
            "/var/./sessions",
            "/",
        ] {
            let input = base.replace(
                "\n[ca]",
                &format!(
                    "\ncreate_mode = \"file_only\"\nsession_config_dir = \"{invalid_path}\"\n\n[ca]"
                ),
            );
            assert!(
                DaemonConfig::from_toml(&input).is_err(),
                "invalid session configuration directory {invalid_path:?} must fail"
            );
        }
    }

    #[test]
    fn parses_the_proposal_session_example_into_a_validated_policy() {
        let request = ControlRequest::from_toml(SESSION_EXAMPLE)
            .expect("proposal session configuration should parse");
        let ControlRequest::Create { version, session } = request else {
            panic!("expected create request");
        };
        assert_eq!(version, PROTOCOL_VERSION);
        assert!(!session.persistent);
        assert_eq!(session.rules.len(), 3);
        assert_eq!(session.rules[0].mode, RuleMode::Tunnel);
        assert_eq!(session.rules[1].paths[0].as_str(), "/repos/dstoc/cladding");
        assert_eq!(session.rules[1].inject[0].format, InjectionFormat::Bearer);
        assert_eq!(
            session.rules[2].inject[0].username.as_deref(),
            Some("x-access-token")
        );
    }

    #[test]
    fn validates_optional_nested_session_socket_names() {
        let request = ControlRequest::from_toml(
            "version = 1\noperation = \"create\"\n\n[session]\nsocket_name = \"cladding/github.sock\"\n\n[[rules]]\nhost = \"example.com\"\nmode = \"tunnel\"\n",
        )
        .expect("a nested socket name should parse");
        let ControlRequest::Create { session, .. } = request else {
            panic!("expected create request");
        };
        assert_eq!(session.socket_name.as_deref(), Some("cladding/github.sock"));

        for name in [
            "",
            "/absolute.sock",
            "./socket.sock",
            "directory/../socket.sock",
            "../socket.sock",
            "directory//socket.sock",
            "directory/",
            "directory\\socket.sock",
            &"x".repeat(108),
        ] {
            let input = format!(
                "version = 1\noperation = \"create\"\n\n[session]\nsocket_name = {name:?}\n\n[[rules]]\nhost = \"example.com\"\nmode = \"tunnel\"\n"
            );
            assert!(
                ControlRequest::from_toml(&input).is_err(),
                "unsafe socket name should fail: {name:?}"
            );
        }
    }

    #[test]
    fn accepts_interception_paths_and_injection_on_configured_port_80() {
        let request = ControlRequest::from_toml(
            "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\nports = [80]\npaths = [\"/public\"]\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"api-token\"\nformat = \"bearer\"\n",
        )
        .expect("configured TLS on port 80 should parse");
        let ControlRequest::Create { session, .. } = request else {
            panic!("expected create request");
        };
        assert_eq!(session.rules[0].mode, RuleMode::Intercept);
        assert_eq!(session.rules[0].ports, [80]);
        assert_eq!(session.rules[0].paths[0].as_str(), "/public");
        assert_eq!(session.rules[0].inject[0].secret.as_str(), "api-token");
    }

    #[test]
    fn defaults_create_persistence_and_destination_port() {
        let request =
            ControlRequest::from_toml(MINIMAL_CREATE).expect("minimal create request should parse");
        let ControlRequest::Create { session, version } = request else {
            panic!("expected create request");
        };
        assert_eq!(version, PROTOCOL_VERSION);
        assert!(!session.persistent);
        assert_eq!(session.rules[0].host, "example.com");
        assert_eq!(session.rules[0].ports, [443]);
    }

    #[test]
    fn rejects_removed_private_addresses_field_for_migration() {
        assert!(
            ControlRequest::from_toml(
                "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"internal.example\"\nmode = \"tunnel\"\nports = [8443]\nprivate_addresses = [\"10.20.30.40\"]\n",
            )
            .is_err(),
            "removed address exceptions must fail strict schema validation"
        );
    }

    #[test]
    fn parses_stop_and_list_requests_with_an_explicit_protocol_version() {
        assert_eq!(
            ControlRequest::from_toml(
                "version = 1\noperation = \"stop\"\nsession_id = \"s_123\"\n"
            )
            .expect("stop should parse"),
            ControlRequest::Stop {
                version: PROTOCOL_VERSION,
                session_id: "s_123".into(),
            }
        );
        assert_eq!(
            ControlRequest::from_toml("version = 1\noperation = \"list\"\n")
                .expect("list should parse"),
            ControlRequest::List {
                version: PROTOCOL_VERSION,
            }
        );
    }

    #[test]
    fn validates_nested_session_config_names_and_rejects_path_forms() {
        assert_eq!(
            ControlRequest::from_toml(
                "version = 1\noperation = \"create_from_file\"\nname = \"cladding/github.toml\"\n"
            )
            .expect("nested session config path should parse"),
            ControlRequest::CreateFromFile {
                version: PROTOCOL_VERSION,
                name: "cladding/github.toml".into(),
            }
        );
        for name in [
            "",
            "/etc/passwd.toml",
            "../outside.toml",
            "cladding/../outside.toml",
            "cladding//github.toml",
            "cladding/github.toml/",
            "cladding\\github.toml",
            "C:/outside.toml",
            "cladding/config.txt",
        ] {
            let input = format!("version = 1\noperation = \"create_from_file\"\nname = {name:?}\n");
            assert!(
                ControlRequest::from_toml(&input).is_err(),
                "invalid session config name {name:?} must fail"
            );
        }
        let too_long = "a".repeat(super::MAX_SESSION_CONFIG_NAME_BYTES + 1);
        let input =
            format!("version = 1\noperation = \"create_from_file\"\nname = \"{too_long}.toml\"\n");
        assert!(ControlRequest::from_toml(&input).is_err());
    }

    #[test]
    fn rejects_invalid_or_ambiguous_policies_in_a_table() {
        let cases = [
            (
                "invalid hostname",
                config_with("host = \"*.example.com\"\nmode = \"tunnel\""),
            ),
            (
                "IP literal",
                config_with("host = \"127.0.0.1\"\nmode = \"tunnel\""),
            ),
            (
                "abbreviated IPv4 address",
                config_with("host = \"127.1\"\nmode = \"tunnel\""),
            ),
            (
                "three-part IPv4 address",
                config_with("host = \"127.0.1\"\nmode = \"tunnel\""),
            ),
            (
                "octal IPv4 address",
                config_with("host = \"0177.0.0.1\"\nmode = \"tunnel\""),
            ),
            (
                "hexadecimal IPv4 address",
                config_with("host = \"0x7f.1\"\nmode = \"tunnel\""),
            ),
            (
                "single-integer IPv4 address",
                config_with("host = \"2130706433\"\nmode = \"tunnel\""),
            ),
            (
                "zero port",
                config_with("host = \"example.com\"\nmode = \"tunnel\"\nports = [0]"),
            ),
            (
                "duplicate port",
                config_with("host = \"example.com\"\nmode = \"tunnel\"\nports = [443, 443]"),
            ),
            (
                "empty port list",
                config_with("host = \"example.com\"\nmode = \"tunnel\"\nports = []"),
            ),
            (
                "injection on tunnel",
                "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"tunnel\"\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"token\"\nformat = \"bearer\"\n".to_string(),
            ),
            (
                "duplicate canonical host",
                "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"EXAMPLE.com\"\nmode = \"tunnel\"\n\n[[rules]]\nhost = \"example.com.\"\nmode = \"tunnel\"\n".into(),
            ),
            (
                "overlapping paths",
                config_with(
                    "host = \"example.com\"\nmode = \"intercept\"\npaths = [\"/x/**\", \"/x/y\"]",
                ),
            ),
            (
                "encoded separator",
                config_with(
                    "host = \"example.com\"\nmode = \"intercept\"\npaths = [\"/x%2fy\"]",
                ),
            ),
            (
                "encoded dot segment",
                config_with(
                    "host = \"example.com\"\nmode = \"intercept\"\npaths = [\"/%2e%2e/private\"]",
                ),
            ),
            (
                "malformed percent escape",
                config_with(
                    "host = \"example.com\"\nmode = \"intercept\"\npaths = [\"/x%2\"]",
                ),
            ),
            (
                "routing-critical header",
                "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\n\n[[rules.inject]]\nheader = \"Host\"\nsecret = \"token\"\nformat = \"raw\"\n".to_string(),
            ),
            (
                "invalid secret identifier",
                "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"../credential\"\nformat = \"bearer\"\n".to_string(),
            ),
            (
                "absolute secret path",
                "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"/var/lib/token\"\nformat = \"bearer\"\n".to_string(),
            ),
            (
                "relative secret path",
                "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"credentials/token\"\nformat = \"bearer\"\n".to_string(),
            ),
            (
                "embedded credentials",
                "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"operator:credential\"\nformat = \"bearer\"\n".to_string(),
            ),
            (
                "basic password without username",
                "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"token\"\nformat = \"basic_password\"\n".to_string(),
            ),
            (
                "literal credential field",
                "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"token\"\nformat = \"bearer\"\nvalue = \"do-not-leak-this\"\n".to_string(),
            ),
        ];

        for (name, input) in cases {
            let error =
                ControlRequest::from_toml(&input).expect_err("invalid policy should be rejected");
            assert!(!error.to_string().contains("do-not-leak-this"), "{name}");
            assert!(!error.to_string().contains("credential"), "{name}");
        }
    }

    #[test]
    fn rejects_duplicate_injection_headers_without_echoing_secret_values() {
        let input = r#"
version = 1
operation = "create"

[session]

[[rules]]
host = "example.com"
mode = "intercept"

[[rules.inject]]
header = "Authorization"
secret = "secret-value-one"
format = "bearer"

[[rules.inject]]
header = "authorization"
secret = "secret-value-two"
format = "raw"
"#;
        let error = ControlRequest::from_toml(input).expect_err("duplicate header should fail");
        assert!(error.to_string().contains("duplicates"));
        assert!(!error.to_string().contains("secret-value"));
    }

    #[test]
    fn rejects_hop_by_hop_and_routing_sensitive_injection_headers() {
        for header in [
            "Connection",
            "Content-Length",
            "Forwarded",
            "Host",
            "HTTP2-Settings",
            "Proxy-Connection",
            "Transfer-Encoding",
            "Upgrade",
            "X-Forwarded-Host",
            "X-Original-URL",
        ] {
            let input = format!(
                "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\n\n[[rules.inject]]\nheader = \"{header}\"\nsecret = \"token\"\nformat = \"raw\"\n"
            );
            let error = ControlRequest::from_toml(&input)
                .expect_err("unsafe header names should be rejected");
            assert!(error.to_string().contains("hop-by-hop or routing-critical"));
        }
    }

    #[test]
    fn rejects_unknown_daemon_fields_without_echoing_values() {
        let input = DAEMON_EXAMPLE.replace(
            "max_sessions = 64",
            "max_sessions = 64\nprivate_key_password = \"do-not-leak-this\"",
        );
        let error = DaemonConfig::from_toml(&input).expect_err("unknown field should fail");
        assert!(error.to_string().contains("unsupported field"));
        assert!(!error.to_string().contains("do-not-leak-this"));
    }

    #[test]
    fn parses_daemon_secret_entitlements_and_rejects_unsafe_names() {
        let configured = DAEMON_EXAMPLE.replace(
            "directory = \"/var/lib/baffle/secrets\"",
            "directory = \"/var/lib/baffle/secrets\"\nallowed = [\"github-api\", \"github-git\"]",
        );
        let config =
            DaemonConfig::from_toml(&configured).expect("daemon secret entitlements should parse");
        assert!(config.secrets.allowed.contains("github-api"));
        assert!(config.secrets.allowed.contains("github-git"));

        for allowed in [
            "allowed = [\"../credential\"]",
            "allowed = [\"/tmp/credential\"]",
            "allowed = [\"same\", \"same\"]",
        ] {
            let input = DAEMON_EXAMPLE.replace(
                "directory = \"/var/lib/baffle/secrets\"",
                &format!("directory = \"/var/lib/baffle/secrets\"\n{allowed}"),
            );
            let error = DaemonConfig::from_toml(&input)
                .expect_err("unsafe or duplicate entitlements should fail");
            assert!(!error.to_string().contains("credential"));
        }
    }

    #[test]
    fn requires_a_trusted_operator_and_rejects_zero_control_limits() {
        let missing_operator = DAEMON_EXAMPLE.replace("trusted_operator_uid = 1000\n", "");
        assert!(DaemonConfig::from_toml(&missing_operator).is_err());

        for field in [
            "control_read_timeout_ms",
            "max_provisioning_requests",
            "io_timeout_ms",
        ] {
            let input = DAEMON_EXAMPLE.replace(
                "shutdown_grace_seconds = 5",
                &format!("shutdown_grace_seconds = 5\n{field} = 0"),
            );
            assert!(DaemonConfig::from_toml(&input).is_err(), "{field}");
        }
    }

    #[test]
    fn validates_protocol_versions_and_session_ids() {
        assert!(ControlRequest::from_toml("operation = \"list\"\n").is_err());
        assert!(ControlRequest::from_toml("version = 2\noperation = \"list\"\n").is_err());
        assert!(
            ControlRequest::from_toml(
                "version = 1\noperation = \"stop\"\nsession_id = \"../bad\"\n"
            )
            .is_err()
        );
    }

    #[test]
    fn validates_all_three_injection_formats() {
        for format in ["raw", "bearer"] {
            let request = ControlRequest::from_toml(&format!(
                "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\n\n[[rules.inject]]\nheader = \"X-Token\"\nsecret = \"api-token\"\nformat = \"{format}\"\n"
            ))
            .expect("raw and bearer formats should parse");
            let ControlRequest::Create {
                session: SessionConfig { rules, .. },
                ..
            } = request
            else {
                panic!("expected create request");
            };
            assert_eq!(rules[0].inject[0].username, None);
        }

        let basic = ControlRequest::from_toml(
            "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"git-token\"\nformat = \"basic_password\"\nusername = \"git\"\n",
        )
        .expect("basic_password should parse");
        let ControlRequest::Create { session, .. } = basic else {
            panic!("expected create request");
        };
        assert_eq!(
            session.rules[0].inject[0].format,
            InjectionFormat::BasicPassword
        );
    }

    #[test]
    fn rejects_invalid_daemon_limits() {
        let input = DAEMON_EXAMPLE.replace("max_sessions = 64", "max_sessions = 0");
        assert!(
            DaemonConfig::from_toml(&input)
                .expect_err("zero session limit should fail")
                .to_string()
                .contains("max_sessions")
        );
    }

    #[test]
    fn ca_example_values_remain_path_data() {
        let config = DaemonConfig::from_toml(DAEMON_EXAMPLE).expect("valid daemon config");
        assert_eq!(
            config.ca,
            CaConfig {
                certificate: "/var/lib/baffle/ca.pem".into(),
                private_key: "/var/lib/baffle/ca-key.pem".into(),
            }
        );
    }
}
