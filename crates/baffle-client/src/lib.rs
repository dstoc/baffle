//! Typed client for Baffle's versioned Unix control protocol.
//!
//! This module depends only on the public wire format. It does not expose or
//! use daemon runtime types.

use std::{
    collections::BTreeMap,
    error::Error,
    fmt, io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

mod policy;

pub use policy::{
    MAX_SESSION_CONFIG_COMPONENT_BYTES, MAX_SESSION_CONFIG_NAME_BYTES,
    SESSION_CONFIG_INVALID_MESSAGE, SESSION_CONFIG_VERSION, SessionConfigError,
    canonicalize_request_path, normalize_dns_name, validate_secret_name,
    validate_session_config_name,
};

/// The protocol version implemented by this client.
pub const PROTOCOL_VERSION: u16 = 2;

const MAX_REQUEST_BYTES: usize = 256 * 1024;
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Return the default control socket path for the current platform.
///
/// macOS uses `HOME/Library/Caches/Baffle/control.sock`, falling back to
/// `/tmp/baffle-<euid>/Library/Caches/Baffle/control.sock` when `HOME` is unset.
/// Other platforms use `/run/baffle/control.sock`.
pub fn default_control_socket() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: geteuid has no preconditions and does not access memory.
        let uid = unsafe { libc::geteuid() };
        macos_default_control_socket(std::env::var_os("HOME"), uid)
    }
    #[cfg(not(target_os = "macos"))]
    {
        linux_default_control_socket()
    }
}

#[cfg(any(target_os = "macos", test))]
fn macos_default_control_socket(home: Option<std::ffi::OsString>, uid: u32) -> PathBuf {
    let base = home
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/tmp/baffle-{uid}")));
    base.join("Library/Caches/Baffle/control.sock")
}

#[cfg(any(not(target_os = "macos"), test))]
fn linux_default_control_socket() -> PathBuf {
    PathBuf::from("/run/baffle/control.sock")
}

/// A client that opens one control connection for each operation.
#[derive(Debug, Clone)]
pub struct Client {
    control_socket: PathBuf,
}

impl Client {
    /// Create a client for the daemon's control socket.
    pub fn new(control_socket: impl Into<PathBuf>) -> Self {
        Self {
            control_socket: control_socket.into(),
        }
    }

    /// Return the configured control socket path.
    pub fn control_socket(&self) -> &Path {
        &self.control_socket
    }

    /// Create a proxy session.
    ///
    /// The returned handle owns the control connection while the session is
    /// ephemeral. Dropping or closing that handle releases the lease. A
    /// persistent session returns without retaining the control connection.
    pub async fn create(&self, config: SessionConfig) -> Result<Session, ClientError> {
        let request = CreateRequest::new(config)?;
        let mut stream = self.open_control().await?;
        let response = exchange(&mut stream, &request).await?;
        let created: CreateResult = success_result(response)?;

        Ok(Session {
            id: created.id,
            socket_path: PathBuf::from(created.socket),
            persistent: created.persistent,
            ca_certificate_pem: created.ca_certificate_pem,
            lease: (!created.persistent).then_some(stream),
        })
    }

    /// Create a proxy session from a TOML file provisioned by the daemon administrator.
    ///
    /// `name` is a relative path beneath the daemon's configured session
    /// configuration directory. The returned handle owns the control
    /// connection while the session is ephemeral.
    pub async fn create_from_file(&self, name: impl AsRef<str>) -> Result<Session, ClientError> {
        self.create_from_file_with_requirement(name.as_ref(), false)
            .await
    }

    /// Create an ephemeral proxy session from a TOML file provisioned by the daemon administrator.
    ///
    /// This asks the daemon to reject a persistent configuration before it
    /// creates any session resources. The returned handle owns the lease until
    /// it is dropped or closed. Older daemons may reject the request because
    /// they do not support the `require_ephemeral` field.
    pub async fn create_ephemeral_from_file(
        &self,
        name: impl AsRef<str>,
    ) -> Result<Session, ClientError> {
        self.create_from_file_with_requirement(name.as_ref(), true)
            .await
    }

    async fn create_from_file_with_requirement(
        &self,
        name: &str,
        require_ephemeral: bool,
    ) -> Result<Session, ClientError> {
        validate_session_config_name(name)
            .map_err(|error| ClientError::InvalidPolicy(error.to_string()))?;
        let request = CreateFromFileRequest {
            version: PROTOCOL_VERSION,
            operation: "create_from_file",
            name,
            require_ephemeral,
        };
        let mut stream = self.open_control().await?;
        let response = exchange(&mut stream, &request).await?;
        let created: CreateResult = success_result(response)?;

        if require_ephemeral && created.persistent {
            drop(stream);
            let cleanup = self.stop(&created.id).await;
            let message = match cleanup {
                Ok(()) => "daemon returned a persistent session despite require_ephemeral; the session was stopped".into(),
                Err(error) => format!(
                    "daemon returned a persistent session despite require_ephemeral; stopping the session failed: {error}"
                ),
            };
            return Err(ClientError::Protocol(message));
        }

        Ok(Session {
            id: created.id,
            socket_path: PathBuf::from(created.socket),
            persistent: created.persistent,
            ca_certificate_pem: created.ca_certificate_pem,
            lease: (!created.persistent).then_some(stream),
        })
    }

    /// Stop a session by its opaque ID.
    pub async fn stop(&self, session_id: impl AsRef<str>) -> Result<(), ClientError> {
        let request = StopRequest {
            version: PROTOCOL_VERSION,
            operation: "stop",
            session_id: session_id.as_ref(),
        };
        let mut stream = self.open_control().await?;
        let response = exchange(&mut stream, &request).await?;
        let result: StopResult = success_result(response)?;
        if !result.stopped {
            return Err(ClientError::Protocol(
                "daemon did not confirm that the session stopped".into(),
            ));
        }
        Ok(())
    }

    /// Reload one file-backed session by ID.
    ///
    /// This operation uses a short-lived control connection and does not
    /// acquire, release, or replace the session's creator lease.
    pub async fn reload(&self, session_id: impl AsRef<str>) -> Result<ReloadResult, ClientError> {
        let request = ReloadRequest {
            version: PROTOCOL_VERSION,
            operation: "reload",
            session_id: session_id.as_ref(),
        };
        let mut stream = self.open_control().await?;
        let response = exchange(&mut stream, &request).await?;
        success_result(response)
    }

    /// Reload every active file-backed session owned by the caller.
    ///
    /// Results are returned in stable session-ID order. Each result is
    /// independent and may report `failed` while other sessions succeed.
    pub async fn reload_all(&self) -> Result<Vec<ReloadResult>, ClientError> {
        let request = ReloadAllRequest {
            version: PROTOCOL_VERSION,
            operation: "reload_all",
        };
        let mut stream = self.open_control().await?;
        let response = exchange(&mut stream, &request).await?;
        let result: ReloadAllResult = success_result(response)?;
        Ok(result.results)
    }

    /// List sessions owned by the authenticated control-socket user.
    pub async fn list(&self) -> Result<Vec<SessionInfo>, ClientError> {
        let request = ListRequest {
            version: PROTOCOL_VERSION,
            operation: "list",
        };
        let mut stream = self.open_control().await?;
        let response = exchange(&mut stream, &request).await?;
        let result: ListResult = success_result(response)?;
        Ok(result.sessions)
    }

    async fn open_control(&self) -> Result<UnixStream, ClientError> {
        UnixStream::connect(&self.control_socket)
            .await
            .map_err(ClientError::Transport)
    }
}

/// A session policy sent to the daemon when creating a proxy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionConfig {
    /// Keep the proxy after the create control connection closes.
    pub persistent: bool,
    /// Optional Unix socket path relative to the daemon's session socket directory.
    pub socket_name: Option<String>,
    /// Action for CONNECT destinations that have no explicit host rule.
    pub unmatched: UnmatchedHostPolicy,
    /// Host allowlist rules for this proxy.
    pub rules: Vec<HostRule>,
}

impl SessionConfig {
    /// Create an ephemeral policy with no rules.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set whether the session survives a control-client disconnect.
    pub fn persistent(mut self, persistent: bool) -> Self {
        self.persistent = persistent;
        self
    }

    /// Request a named data socket below the daemon's session socket directory.
    pub fn socket_name(mut self, socket_name: impl Into<String>) -> Self {
        self.socket_name = Some(socket_name.into());
        self
    }

    /// Set the policy for CONNECT destinations without an explicit host rule.
    pub fn unmatched_host_policy(mut self, policy: UnmatchedHostPolicy) -> Self {
        self.unmatched = policy;
        self
    }

    /// Add one host rule.
    pub fn with_rule(mut self, rule: HostRule) -> Self {
        self.rules.push(rule);
        self
    }
}

/// Policy for CONNECT destinations that have no explicit host rule.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnmatchedHostPolicy {
    /// Deny destinations without an explicit host rule.
    #[default]
    Deny,
    /// Permit opaque HTTPS tunnels to unmatched DNS hostnames on port 443.
    Tunnel,
}

impl UnmatchedHostPolicy {
    fn is_deny(&self) -> bool {
        *self == Self::Deny
    }
}

/// The action for one exact destination hostname.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleMode {
    /// Permit HTTPS CONNECT without TLS decryption. Path-restricted rules do
    /// not permit an opaque connection because Baffle cannot inspect its paths.
    Tunnel,
    /// Intercept HTTPS so path and header rules can be applied to inner HTTP
    /// requests after successful TLS negotiation.
    Intercept,
}

/// A policy rule for one exact DNS hostname.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRule {
    /// Exact DNS hostname, for example `api.example.com`.
    pub host: String,
    /// How the daemon handles HTTPS for this host.
    pub mode: RuleMode,
    /// Permitted destination ports. Defaults to HTTPS port 443 in `tunnel` and
    /// `intercept` constructors.
    pub ports: Vec<u16>,
    /// Optional exact paths or recursive patterns such as `/v1/**`. Paths
    /// match case-sensitively, ignore query strings, and are canonicalized
    /// before forwarding. Unsafe or ambiguous encodings are denied.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    /// Optional daemon-managed header injections.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inject: Vec<HeaderInjection>,
}

impl HostRule {
    /// Allow HTTPS tunneling to this host on port 443.
    pub fn tunnel(host: impl Into<String>) -> Self {
        Self::new(host, RuleMode::Tunnel)
    }

    /// Intercept HTTPS to this host on port 443.
    pub fn intercept(host: impl Into<String>) -> Self {
        Self::new(host, RuleMode::Intercept)
    }

    /// Create a rule with the default HTTPS port.
    pub fn new(host: impl Into<String>, mode: RuleMode) -> Self {
        Self {
            host: host.into(),
            mode,
            ports: vec![443],
            paths: Vec::new(),
            inject: Vec::new(),
        }
    }
}

/// A declaration to inject a daemon-managed secret into an HTTP header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderInjection {
    /// HTTP header name, for example `Authorization`.
    pub header: String,
    /// Symbolic secret name configured by the daemon operator.
    pub secret: String,
    /// How Baffle formats the secret value.
    pub format: InjectionFormat,
    /// Required for `basic_password`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

impl HeaderInjection {
    /// Inject the secret as a raw header value.
    pub fn raw(header: impl Into<String>, secret: impl Into<String>) -> Self {
        Self::new(header, secret, InjectionFormat::Raw, None)
    }

    /// Inject the secret with the `Bearer` authorization scheme.
    pub fn bearer(header: impl Into<String>, secret: impl Into<String>) -> Self {
        Self::new(header, secret, InjectionFormat::Bearer, None)
    }

    /// Inject the secret as the password in an HTTP Basic authorization value.
    pub fn basic_password(
        header: impl Into<String>,
        secret: impl Into<String>,
        username: impl Into<String>,
    ) -> Self {
        Self::new(
            header,
            secret,
            InjectionFormat::BasicPassword,
            Some(username.into()),
        )
    }

    fn new(
        header: impl Into<String>,
        secret: impl Into<String>,
        format: InjectionFormat,
        username: Option<String>,
    ) -> Self {
        Self {
            header: header.into(),
            secret: secret.into(),
            format,
            username,
        }
    }
}

/// Supported formats for daemon-managed header injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectionFormat {
    Raw,
    Bearer,
    BasicPassword,
}

/// A session returned by Baffle.
///
/// Ephemeral sessions retain their create control connection in this handle.
/// The connection closes when the handle is dropped.
pub struct Session {
    id: String,
    socket_path: PathBuf,
    persistent: bool,
    ca_certificate_pem: Option<String>,
    lease: Option<UnixStream>,
}

impl Session {
    /// Return the opaque proxy ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Return the proxy's Unix data-socket path.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Return whether the session survives control-client disconnects.
    pub fn is_persistent(&self) -> bool {
        self.persistent
    }

    /// Return the public CA certificate PEM used by this session's daemon.
    ///
    /// Older protocol-v2 daemons do not include this response field, so this
    /// returns `None` when the daemon did not provide certificate data. Do not
    /// use a missing certificate as trust material.
    pub fn ca_certificate_pem(&self) -> Option<&str> {
        self.ca_certificate_pem.as_deref()
    }

    /// Explicitly release an ephemeral session lease.
    ///
    /// For a persistent session this only discards the local handle; use
    /// [`Client::stop`] to remove the daemon-owned session.
    pub fn close(mut self) {
        self.lease.take();
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Session")
            .field("id", &self.id)
            .field("socket_path", &self.socket_path)
            .field("persistent", &self.persistent)
            .field("has_lease", &self.lease.is_some())
            .finish()
    }
}

/// A session returned by the `list` operation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SessionInfo {
    /// Opaque proxy ID.
    pub id: String,
    /// Unix data-socket path.
    #[serde(rename = "socket")]
    pub socket_path: PathBuf,
    /// Whether control-client disconnects leave this session running.
    pub persistent: bool,
    /// Current daemon lifecycle state.
    pub state: SessionState,
    /// Number of the current immutable policy generation.
    #[serde(default)]
    pub generation: u64,
    /// Number of superseded listeners still draining accepted connections.
    #[serde(default)]
    pub draining_generations: usize,
}

/// Outcome for one session in a reload operation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ReloadResult {
    /// Opaque session ID.
    pub id: String,
    /// Outcome for this session.
    pub status: ReloadStatus,
    /// Current data-socket path, including on a failed reload.
    #[serde(rename = "socket")]
    pub socket_path: PathBuf,
    /// Safe, non-secret failure category when `status` is `Failed`.
    pub reason: Option<String>,
}

/// Reload status for one file-backed session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReloadStatus {
    Reloaded,
    Unchanged,
    Failed,
}

/// Current lifecycle state of a proxy session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Running,
    Stopping,
}

/// A safe error returned by the client or the daemon.
#[derive(Debug)]
pub enum ClientError {
    /// The peer UID is not authorized, or requested secrets are unavailable.
    Authorization(String),
    /// The daemon rejected the supplied policy or request fields.
    InvalidPolicy(String),
    /// The session or provisioning capacity limit has been reached.
    CapacityLimit(String),
    /// The daemon and client use incompatible protocol versions.
    ProtocolMismatch(String),
    /// The daemon could not provision or stop the requested session.
    Provisioning(String),
    /// The requested session does not exist or is not owned by this user.
    SessionNotFound(String),
    /// The daemon could not find the named session configuration file.
    SessionConfigNotFound(String),
    /// The named session configuration file could not be safely read.
    SessionConfigUnavailable(String),
    /// The named session configuration file is not a valid session policy.
    SessionConfigInvalid(String),
    /// The requested create operation is disabled by daemon configuration.
    OperationNotAllowed(String),
    /// The control transport failed.
    Transport(io::Error),
    /// The request could not be encoded as TOML.
    Serialization(toml::ser::Error),
    /// The daemon returned a malformed or unexpected response.
    Protocol(String),
    /// An unrecognized stable daemon error code.
    Server { code: String, message: String },
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorization(message) => write!(formatter, "authorization failed: {message}"),
            Self::InvalidPolicy(message) => write!(formatter, "invalid policy: {message}"),
            Self::CapacityLimit(message) => write!(formatter, "capacity limit: {message}"),
            Self::ProtocolMismatch(message) => write!(formatter, "protocol mismatch: {message}"),
            Self::Provisioning(message) => write!(formatter, "provisioning failed: {message}"),
            Self::SessionNotFound(message) => write!(formatter, "session not found: {message}"),
            Self::SessionConfigNotFound(message) => {
                write!(formatter, "session configuration not found: {message}")
            }
            Self::SessionConfigUnavailable(message) => {
                write!(formatter, "session configuration unavailable: {message}")
            }
            Self::SessionConfigInvalid(message) => {
                write!(formatter, "invalid session configuration: {message}")
            }
            Self::OperationNotAllowed(message) => {
                write!(formatter, "operation not allowed: {message}")
            }
            Self::Transport(error) => write!(formatter, "control transport failed: {error}"),
            Self::Serialization(error) => write!(formatter, "could not encode request: {error}"),
            Self::Protocol(message) => write!(formatter, "control protocol error: {message}"),
            Self::Server { code, message } => write!(formatter, "daemon error {code}: {message}"),
        }
    }
}

impl Error for ClientError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Serialization(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Serialize)]
struct CreateRequest {
    version: u16,
    operation: &'static str,
    session: SessionConfigWire,
}

impl CreateRequest {
    fn new(config: SessionConfig) -> Result<Self, ClientError> {
        let mut rules = BTreeMap::new();
        for rule in config.rules {
            let host = rule.host.clone();
            let value = NamedHostRule {
                mode: rule.mode,
                ports: rule.ports,
                paths: rule.paths,
                inject: rule.inject,
            };
            if rules.insert(host, value).is_some() {
                return Err(ClientError::Protocol(
                    "session configuration contains duplicate host rules".into(),
                ));
            }
        }

        Ok(Self {
            version: PROTOCOL_VERSION,
            operation: "create",
            session: SessionConfigWire {
                version: SESSION_CONFIG_VERSION,
                persistent: config.persistent,
                socket_name: config.socket_name,
                unmatched: config.unmatched,
                rules,
            },
        })
    }
}

#[derive(Serialize)]
struct CreateFromFileRequest<'a> {
    version: u16,
    operation: &'static str,
    name: &'a str,
    #[serde(skip_serializing_if = "is_false")]
    require_ephemeral: bool,
}

fn is_false(value: &bool) -> bool {
    !value
}

#[derive(Serialize)]
struct SessionConfigWire {
    version: u16,
    persistent: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    socket_name: Option<String>,
    #[serde(skip_serializing_if = "UnmatchedHostPolicy::is_deny")]
    unmatched: UnmatchedHostPolicy,
    rules: BTreeMap<String, NamedHostRule>,
}

#[derive(Serialize)]
struct NamedHostRule {
    mode: RuleMode,
    ports: Vec<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    paths: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    inject: Vec<HeaderInjection>,
}

#[derive(Serialize)]
struct StopRequest<'a> {
    version: u16,
    operation: &'static str,
    session_id: &'a str,
}

#[derive(Serialize)]
struct ListRequest {
    version: u16,
    operation: &'static str,
}

#[derive(Serialize)]
struct ReloadRequest<'a> {
    version: u16,
    operation: &'static str,
    session_id: &'a str,
}

#[derive(Serialize)]
struct ReloadAllRequest {
    version: u16,
    operation: &'static str,
}

#[derive(Deserialize)]
struct ReloadAllResult {
    results: Vec<ReloadResult>,
}

#[derive(Deserialize)]
struct Envelope {
    version: u16,
    ok: bool,
    result: Option<Value>,
    error: Option<RemoteError>,
}

#[derive(Deserialize)]
struct RemoteError {
    code: String,
    message: String,
}

#[derive(Deserialize)]
struct CreateResult {
    id: String,
    socket: String,
    persistent: bool,
    #[serde(default)]
    ca_certificate_pem: Option<String>,
}

#[derive(Deserialize)]
struct StopResult {
    stopped: bool,
}

#[derive(Deserialize)]
struct ListResult {
    sessions: Vec<SessionInfo>,
}

async fn exchange<T: Serialize>(
    stream: &mut UnixStream,
    request: &T,
) -> Result<Value, ClientError> {
    let body = toml::to_string(request).map_err(ClientError::Serialization)?;
    if body.is_empty() || body.len() > MAX_REQUEST_BYTES {
        return Err(ClientError::Protocol(
            "request exceeds the supported frame size".into(),
        ));
    }
    let length = u32::try_from(body.len())
        .map_err(|_| ClientError::Protocol("request exceeds the supported frame size".into()))?;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .map_err(ClientError::Transport)?;
    stream
        .write_all(body.as_bytes())
        .await
        .map_err(ClientError::Transport)?;
    stream.flush().await.map_err(ClientError::Transport)?;

    let mut header = [0; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(ClientError::Transport)?;
    let response_length = u32::from_be_bytes(header) as usize;
    if response_length == 0 || response_length > MAX_RESPONSE_BYTES {
        return Err(ClientError::Protocol(
            "response frame has an unsupported size".into(),
        ));
    }
    let mut response_body = vec![0; response_length];
    stream
        .read_exact(&mut response_body)
        .await
        .map_err(ClientError::Transport)?;
    let envelope: Envelope = serde_json::from_slice(&response_body)
        .map_err(|_| ClientError::Protocol("response is not valid JSON".into()))?;
    if envelope.version != PROTOCOL_VERSION {
        return Err(ClientError::ProtocolMismatch(format!(
            "client supports version {PROTOCOL_VERSION}, daemon returned version {}",
            envelope.version
        )));
    }
    if envelope.ok {
        return envelope
            .result
            .ok_or_else(|| ClientError::Protocol("successful response has no result".into()));
    }
    let error = envelope
        .error
        .ok_or_else(|| ClientError::Protocol("failed response has no error".into()))?;
    Err(map_remote_error(error))
}

fn success_result<T: for<'de> Deserialize<'de>>(value: Value) -> Result<T, ClientError> {
    serde_json::from_value(value)
        .map_err(|_| ClientError::Protocol("result does not match the operation response".into()))
}

fn map_remote_error(error: RemoteError) -> ClientError {
    let RemoteError { code, message } = error;
    match code.as_str() {
        "unauthorized" | "secret_unavailable" => ClientError::Authorization(message),
        "invalid_request" => ClientError::InvalidPolicy(message),
        "unsupported_version" => ClientError::ProtocolMismatch(message),
        "busy" | "session_limit" => ClientError::CapacityLimit(message),
        "session_not_found" => ClientError::SessionNotFound(message),
        "config_file_not_found" => ClientError::SessionConfigNotFound(message),
        "config_file_unavailable" => ClientError::SessionConfigUnavailable(message),
        "config_file_invalid" => ClientError::SessionConfigInvalid(message),
        "ephemeral_required" => ClientError::InvalidPolicy(message),
        "operation_not_allowed" => ClientError::OperationNotAllowed(message),
        "internal_error" | "shutting_down" => ClientError::Provisioning(message),
        _ => ClientError::Server { code, message },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClientError, CreateFromFileRequest, CreateRequest, CreateResult, HostRule, InjectionFormat,
        SessionConfig, UnmatchedHostPolicy, linux_default_control_socket,
        macos_default_control_socket, map_remote_error, success_result,
        validate_session_config_name,
    };

    #[test]
    fn uses_the_linux_control_socket_path() {
        assert_eq!(
            linux_default_control_socket(),
            std::path::PathBuf::from("/run/baffle/control.sock")
        );
    }

    #[test]
    fn uses_home_for_the_macos_control_socket_path() {
        assert_eq!(
            macos_default_control_socket(Some("/Users/alice".into()), 501),
            std::path::PathBuf::from("/Users/alice/Library/Caches/Baffle/control.sock")
        );
    }

    #[test]
    fn falls_back_to_uid_scoped_tmp_when_macos_home_is_unset() {
        assert_eq!(
            macos_default_control_socket(None, 501),
            std::path::PathBuf::from("/tmp/baffle-501/Library/Caches/Baffle/control.sock")
        );
    }

    #[test]
    fn serializes_create_requests_with_the_current_session_schema() {
        let policy = SessionConfig::new()
            .persistent(true)
            .socket_name("cladding/github.sock")
            .with_rule(HostRule::intercept("api.example.com"));
        let encoded = toml::to_string(&CreateRequest::new(policy).expect("request should build"))
            .expect("request should serialize");
        assert!(encoded.contains("operation = \"create\""));
        assert!(encoded.contains("version = 2"));
        assert!(encoded.contains("[session]\nversion = 2\npersistent = true"));
        assert!(encoded.contains("socket_name = \"cladding/github.sock\""));
        assert!(encoded.contains("[session.rules.\"api.example.com\"]"));
        assert!(encoded.contains("mode = \"intercept\""));
        assert!(encoded.contains("ports = [443]"));
        assert!(!encoded.contains("[[rules]]"));
        assert!(!encoded.contains("host = \"api.example.com\""));
        assert!(!encoded.contains("private_addresses"));
    }

    #[test]
    fn omits_socket_name_when_not_requested() {
        let policy = SessionConfig::new().with_rule(HostRule::tunnel("api.example.com"));
        let encoded = toml::to_string(&CreateRequest::new(policy).expect("request should build"))
            .expect("request should serialize");

        assert!(!encoded.contains("socket_name"));
        assert!(!encoded.contains("unmatched"));
    }

    #[test]
    fn serializes_opt_in_unmatched_tunneling_in_session_settings() {
        let policy = SessionConfig::new().unmatched_host_policy(UnmatchedHostPolicy::Tunnel);
        let encoded = toml::to_string(&CreateRequest::new(policy).expect("request should build"))
            .expect("request should serialize");

        assert!(encoded.contains("unmatched = \"tunnel\""));
    }

    #[test]
    fn rejects_duplicate_hosts_that_cannot_be_encoded_as_named_rules() {
        let policy = SessionConfig::new()
            .with_rule(HostRule::tunnel("api.example.com"))
            .with_rule(HostRule::intercept("api.example.com"));
        let error = CreateRequest::new(policy)
            .err()
            .expect("duplicate hosts must be rejected");
        assert!(error.to_string().contains("duplicate host rules"));
    }

    #[test]
    fn serializes_secret_injection_format_names() {
        assert_eq!(
            serde_json::to_string(&InjectionFormat::BasicPassword).expect("enum should serialize"),
            "\"basic_password\""
        );
    }

    #[test]
    fn maps_stable_daemon_errors_to_safe_categories() {
        assert!(matches!(
            map_remote_error(super::RemoteError {
                code: "secret_unavailable".into(),
                message: "one or more requested secrets are unavailable".into(),
            }),
            ClientError::Authorization(_)
        ));
        assert!(matches!(
            map_remote_error(super::RemoteError {
                code: "session_limit".into(),
                message: "session limit has been reached".into(),
            }),
            ClientError::CapacityLimit(_)
        ));
        assert!(matches!(
            map_remote_error(super::RemoteError {
                code: "internal_error".into(),
                message: "request could not be completed".into(),
            }),
            ClientError::Provisioning(_)
        ));
        assert!(matches!(
            map_remote_error(super::RemoteError {
                code: "config_file_invalid".into(),
                message: "session configuration file is invalid".into(),
            }),
            ClientError::SessionConfigInvalid(_)
        ));
    }

    #[test]
    fn serializes_file_create_and_validates_relative_toml_names() {
        let request = CreateFromFileRequest {
            version: super::PROTOCOL_VERSION,
            operation: "create_from_file",
            name: "cladding/github.toml",
            require_ephemeral: false,
        };
        let encoded = toml::to_string(&request).expect("file request should serialize");
        assert!(encoded.contains("operation = \"create_from_file\""));
        assert!(encoded.contains("name = \"cladding/github.toml\""));
        assert!(!encoded.contains("require_ephemeral"));
        assert!(validate_session_config_name("cladding/github.toml").is_ok());
        for invalid in [
            "",
            "/etc/passwd.toml",
            "../outside.toml",
            "cladding/../outside.toml",
            "cladding//github.toml",
            "cladding\\github.toml",
            "cladding/name.txt",
        ] {
            assert!(
                validate_session_config_name(invalid).is_err(),
                "{invalid:?} must be rejected"
            );
        }
    }

    #[test]
    fn serializes_the_ephemeral_file_create_constraint() {
        let request = CreateFromFileRequest {
            version: super::PROTOCOL_VERSION,
            operation: "create_from_file",
            name: "cladding/github.toml",
            require_ephemeral: true,
        };
        let encoded = toml::to_string(&request).expect("file request should serialize");
        assert!(encoded.contains("require_ephemeral = true"));
    }

    #[test]
    fn create_response_accepts_a_public_ca_and_older_daemons_without_one() {
        let with_ca: CreateResult = success_result(serde_json::json!({
            "id": "session_example_01",
            "socket": "/run/baffle/proxies/session_example_01.sock",
            "persistent": false,
            "ca_certificate_pem": "-----BEGIN CERTIFICATE-----\\npublic-certificate\\n-----END CERTIFICATE-----\\n",
            "future_field": true
        }))
        .expect("the additive certificate field should deserialize");
        assert_eq!(
            with_ca.ca_certificate_pem.as_deref(),
            Some("-----BEGIN CERTIFICATE-----\\npublic-certificate\\n-----END CERTIFICATE-----\\n")
        );

        let older_daemon: CreateResult = success_result(serde_json::json!({
            "id": "session_example_02",
            "socket": "/run/baffle/proxies/session_example_02.sock",
            "persistent": true
        }))
        .expect("protocol-v2 create responses without the additive field remain valid");
        assert_eq!(older_daemon.ca_certificate_pem, None);
    }

    #[test]
    fn create_response_rejects_a_malformed_certificate_field_type() {
        let error = success_result::<CreateResult>(serde_json::json!({
            "id": "session_example_01",
            "socket": "/run/baffle/proxies/session_example_01.sock",
            "persistent": false,
            "ca_certificate_pem": 7
        }))
        .err()
        .expect("a non-string certificate field is an invalid response");
        assert!(matches!(error, ClientError::Protocol(_)));
    }
}
