//! Typed client for Baffle's versioned Unix control protocol.
//!
//! This module depends only on the public wire format. It does not expose or
//! use daemon runtime types.

use std::{
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

/// The protocol version implemented by this client.
pub const PROTOCOL_VERSION: u16 = 1;

const MAX_REQUEST_BYTES: usize = 256 * 1024;
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

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
        let request = CreateRequest {
            version: PROTOCOL_VERSION,
            operation: "create",
            session: SessionSettings {
                persistent: config.persistent,
            },
            rules: config.rules,
        };
        let mut stream = self.open_control().await?;
        let response = exchange(&mut stream, &request).await?;
        let created: CreateResult = success_result(response)?;

        Ok(Session {
            id: created.id,
            socket_path: PathBuf::from(created.socket),
            persistent: created.persistent,
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

    /// Add one host rule.
    pub fn with_rule(mut self, rule: HostRule) -> Self {
        self.rules.push(rule);
        self
    }
}

/// The action for one exact destination hostname.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleMode {
    /// Permit HTTPS CONNECT without TLS decryption.
    Tunnel,
    /// Intercept HTTPS so path and header rules can be applied.
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
    /// Optional exact paths or recursive patterns such as `/v1/**`.
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
    session: SessionSettings,
    rules: Vec<HostRule>,
}

#[derive(Serialize)]
struct SessionSettings {
    persistent: bool,
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
        "internal_error" | "shutting_down" => ClientError::Provisioning(message),
        _ => ClientError::Server { code, message },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClientError, CreateRequest, HostRule, InjectionFormat, SessionConfig, SessionSettings,
        map_remote_error,
    };

    #[test]
    fn serializes_create_requests_with_the_v1_wire_shape() {
        let policy = SessionConfig::new()
            .persistent(true)
            .with_rule(HostRule::intercept("api.example.com"));
        let encoded = toml::to_string(&CreateRequest {
            version: 1,
            operation: "create",
            session: SessionSettings { persistent: true },
            rules: policy.rules,
        })
        .expect("request should serialize");
        assert!(encoded.contains("operation = \"create\""));
        assert!(encoded.contains("version = 1"));
        assert!(encoded.contains("[session]\npersistent = true"));
        assert!(encoded.contains("[[rules]]"));
        assert!(encoded.contains("mode = \"intercept\""));
        assert!(encoded.contains("ports = [443]"));
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
    }
}
