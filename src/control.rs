//! Private Unix control socket and framed request/response transport.

use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, Read},
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
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

use crate::config::{ControlRequest, DaemonConfig, PROTOCOL_VERSION};
use crate::secrets::{ResolvedSecrets, SecretStore, SecretStoreError};
use crate::{
    ca::ManagedCa,
    config::SessionConfig,
    proxy_runtime::{ProxyRuntime, ProxyRuntimeError, ProxyRuntimeEvent, RuntimeId},
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

pub struct ControlServer {
    listener: UnixListener,
    _socket_guard: SocketGuard,
    state: Arc<ControlState>,
    connections: JoinSet<()>,
    runtime_events: tokio::sync::mpsc::UnboundedReceiver<ProxyRuntimeEvent>,
}

struct ControlState {
    trusted_operator_uid: u32,
    read_timeout: Duration,
    secret_store: SecretStore,
    sessions: SessionManager,
    provisioning_slots: Arc<Semaphore>,
}

struct SocketGuard {
    path: PathBuf,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_file(&self.path)
            && error.kind() != io::ErrorKind::NotFound
        {
            warn!(path = %self.path.display(), %error, "failed to remove control socket");
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

        match fs::symlink_metadata(control_socket) {
            Ok(_) => bail!("control socket path already exists"),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("could not inspect control socket path"),
        }

        let listener = UnixListener::bind(control_socket).with_context(|| {
            format!("could not bind control socket {}", control_socket.display())
        })?;
        let socket_guard = SocketGuard {
            path: control_socket.clone(),
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

        Ok(Self {
            listener,
            _socket_guard: socket_guard,
            state: Arc::new(ControlState {
                trusted_operator_uid: trusted_uid,
                read_timeout: Duration::from_millis(config.daemon.control_read_timeout_ms),
                secret_store: SecretStore::new(
                    config.secrets.directory.clone(),
                    trusted_uid,
                    config.secrets.allowed.clone(),
                ),
                sessions: SessionManager::new(
                    socket_dir.clone(),
                    config.daemon.max_sessions,
                    Duration::from_secs(config.daemon.shutdown_grace_seconds),
                    ca,
                    runtime_event_sender,
                ),
                provisioning_slots: Arc::new(Semaphore::new(
                    config.daemon.max_provisioning_requests,
                )),
            }),
            connections: JoinSet::new(),
            runtime_events,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
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
                Some(event) = self.runtime_events.recv() => {
                    let ProxyRuntimeEvent { runtime_id, result } = event;
                    match result {
                        Ok(()) => info!(runtime_id = %runtime_id.as_str(), "proxy runtime stopped"),
                        Err(error) => warn!(runtime_id = %runtime_id.as_str(), %error, "proxy runtime failed"),
                    }
                    self.state.sessions.remove(runtime_id.as_str()).await;
                }
            }
        }
    }

    /// Stop all owned proxy instances, allowing each Hudsucker task to drain.
    pub async fn shutdown(&self) {
        self.state.sessions.shutdown_all().await;
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
            let permit = match state.provisioning_slots.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    let _ = write_error(&mut stream, ERR_BUSY).await;
                    return;
                }
            };
            let secrets = match state.secret_store.resolve(client_uid, &session) {
                Ok(secrets) => secrets,
                Err(
                    SecretStoreError::UnauthorizedClient
                    | SecretStoreError::NotEntitled
                    | SecretStoreError::Unavailable,
                ) => {
                    let _ = write_error(&mut stream, ERR_SECRET_UNAVAILABLE).await;
                    return;
                }
            };
            let result = {
                let result = state.sessions.create(session, secrets).await;
                drop(permit);
                result
            };
            match result {
                Ok(created) => {
                    if !created.persistent {
                        lease_id = Some(created.id.clone());
                    }
                    success(json!({
                        "id": created.id,
                        "socket": created.socket,
                        "persistent": created.persistent,
                    }))
                }
                Err(SessionError::AtCapacity) => error_value(ERR_SESSION_LIMIT),
                Err(SessionError::Runtime(error)) => {
                    warn!(%error, "failed to start proxy runtime");
                    error_value(ERR_INTERNAL)
                }
                Err(SessionError::Internal) => error_value(ERR_INTERNAL),
            }
        }
        ControlRequest::Stop { session_id, .. } => {
            if state.sessions.stop(&session_id).await {
                success(json!({ "stopped": true }))
            } else {
                error_value(ERR_SESSION_NOT_FOUND)
            }
        }
        ControlRequest::List { .. } => success(json!({
            "sessions": state.sessions.list().await,
        })),
    };

    if write_value(&mut stream, response).await.is_err() {
        if let Some(id) = lease_id {
            state.sessions.remove(&id).await;
        }
        return;
    }

    // An ephemeral create connection is also its lease. Any bytes after the
    // request violate the one-request rule and revoke the placeholder session.
    if let Some(id) = lease_id {
        let mut extra = [0; 1];
        let _ = stream.read(&mut extra).await;
        state.sessions.remove(&id).await;
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
    shutdown_grace: Duration,
    ca: Arc<ManagedCa>,
    runtime_events: tokio::sync::mpsc::UnboundedSender<ProxyRuntimeEvent>,
    sessions: Arc<Mutex<HashMap<String, ManagedSession>>>,
}

impl SessionManager {
    fn new(
        socket_dir: PathBuf,
        max_sessions: usize,
        shutdown_grace: Duration,
        ca: Arc<ManagedCa>,
        runtime_events: tokio::sync::mpsc::UnboundedSender<ProxyRuntimeEvent>,
    ) -> Self {
        Self {
            socket_dir,
            max_sessions,
            shutdown_grace,
            ca,
            runtime_events,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn create(
        &self,
        session: SessionConfig,
        secrets: ResolvedSecrets,
    ) -> std::result::Result<SessionInfo, SessionError> {
        let id = new_session_id().map_err(|_| SessionError::Internal)?;
        let persistent = session.persistent;
        let mut sessions = self.sessions.lock().await;
        if sessions.len() >= self.max_sessions {
            return Err(SessionError::AtCapacity);
        }
        if sessions.contains_key(&id) {
            return Err(SessionError::Internal);
        }

        let runtime = ProxyRuntime::start(
            RuntimeId::new(id.clone()),
            session,
            Arc::clone(&self.ca),
            self.runtime_events.clone(),
        )
        .await
        .map_err(SessionError::Runtime)?;
        let info = SessionInfo {
            socket: self
                .socket_dir
                .join(format!("{id}.sock"))
                .to_string_lossy()
                .into_owned(),
            id: id.clone(),
            persistent,
        };
        sessions.insert(
            id,
            ManagedSession {
                info: info.clone(),
                _secrets: secrets,
                runtime,
            },
        );
        Ok(info)
    }

    async fn stop(&self, id: &str) -> bool {
        let session = self.sessions.lock().await.remove(id);
        if let Some(session) = session {
            session.runtime.shutdown(self.shutdown_grace).await;
            true
        } else {
            false
        }
    }

    async fn remove(&self, id: &str) {
        let session = self.sessions.lock().await.remove(id);
        if let Some(session) = session {
            session.runtime.shutdown(self.shutdown_grace).await;
        }
    }

    async fn shutdown_all(&self) {
        let sessions = std::mem::take(&mut *self.sessions.lock().await);
        let mut shutdowns = JoinSet::new();
        for session in sessions.into_values() {
            let grace = self.shutdown_grace;
            shutdowns.spawn(async move {
                session.runtime.shutdown(grace).await;
            });
        }
        while shutdowns.join_next().await.is_some() {}
    }

    async fn list(&self) -> Vec<SessionInfo> {
        let mut sessions = self
            .sessions
            .lock()
            .await
            .values()
            .map(|session| session.info.clone())
            .collect::<Vec<_>>();
        sessions.sort_by(|left, right| left.id.cmp(&right.id));
        sessions
    }
}

struct ManagedSession {
    info: SessionInfo,
    // Secret values remain scoped to this session and are never serialized.
    _secrets: ResolvedSecrets,
    runtime: ProxyRuntime,
}

#[derive(Debug)]
enum SessionError {
    AtCapacity,
    Runtime(ProxyRuntimeError),
    Internal,
}

#[derive(Debug, Clone, Serialize)]
struct SessionInfo {
    id: String,
    socket: String,
    persistent: bool,
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

    use hudsucker::rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};

    use crate::{ca::ManagedCa, config::CaConfig, secrets::SecretStore};

    use super::{ControlState, SessionManager, handle_connection};

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
        SessionManager::new(
            directory.to_path_buf(),
            max_sessions,
            Duration::from_secs(1),
            ca,
            runtime_events,
        )
    }

    fn state(directory: &std::path::Path, uid: u32, allowed: &[&str]) -> ControlState {
        ControlState {
            trusted_operator_uid: uid,
            read_timeout: Duration::from_secs(1),
            secret_store: SecretStore::new(
                directory.to_path_buf(),
                uid,
                allowed.iter().map(|name| (*name).to_owned()).collect(),
            ),
            sessions: session_manager(directory, 1),
            provisioning_slots: Arc::new(Semaphore::new(1)),
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
            read_timeout: Duration::from_secs(1),
            secret_store: SecretStore::new(
                directory.path().to_path_buf(),
                peer_uid.wrapping_add(1),
                Default::default(),
            ),
            sessions: session_manager(directory.path(), 1),
            provisioning_slots: Arc::new(Semaphore::new(1)),
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
            control_state.sessions.list().await.is_empty(),
            "unauthorized references must fail before session creation"
        );
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
        let sessions = state.sessions.sessions.lock().await;
        let created = sessions.get(id).expect("session should be retained");
        assert_eq!(
            created
                ._secrets
                .get("api-token")
                .expect("session should own its resolved secret")
                .as_str(),
            "credential-must-not-leak"
        );
    }
}
