use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicU64},
    time::Duration,
};

use serde::Serialize;
use tokio::{sync::Mutex, task::JoinSet};

use crate::{
    ca::ManagedCa,
    config::{DaemonSettings, SessionConfig},
    proxy_runtime::{ProxyRuntime, ProxyRuntimeError, ProxyRuntimeEvent, RuntimeId},
    secrets::ResolvedSecrets,
    telemetry::Metrics,
};

#[derive(Clone)]
pub(super) struct SessionManager {
    pub(super) socket_dir: PathBuf,
    pub(super) max_sessions: usize,
    pub(super) max_connections_per_session: usize,
    pub(super) io_timeout: Duration,
    pub(super) shutdown_grace: Duration,
    pub(super) ca: Arc<ManagedCa>,
    pub(super) runtime_events: tokio::sync::mpsc::UnboundedSender<ProxyRuntimeEvent>,
    pub(super) registry: Arc<Mutex<SessionRegistry>>,
    pub(super) metrics: Arc<Metrics>,
}

pub(super) struct SessionRegistry {
    pub(super) accepting_sessions: bool,
    pub(super) sessions: HashMap<String, ManagedSession>,
    pub(super) provisioning: HashSet<String>,
}

impl SessionManager {
    pub(super) fn new(
        settings: &DaemonSettings,
        ca: Arc<ManagedCa>,
        runtime_events: tokio::sync::mpsc::UnboundedSender<ProxyRuntimeEvent>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            socket_dir: settings.socket_dir.clone(),
            max_sessions: settings.max_sessions,
            max_connections_per_session: settings.max_connections_per_session,
            io_timeout: Duration::from_millis(settings.io_timeout_ms),
            shutdown_grace: Duration::from_secs(settings.shutdown_grace_seconds),
            ca,
            runtime_events,
            registry: Arc::new(Mutex::new(SessionRegistry {
                accepting_sessions: true,
                sessions: HashMap::new(),
                provisioning: HashSet::new(),
            })),
            metrics,
        }
    }

    pub(super) async fn create(
        &self,
        owner_uid: u32,
        session: SessionConfig,
        secrets: ResolvedSecrets,
        config_source: Option<String>,
    ) -> std::result::Result<SessionInfo, SessionError> {
        let secrets = Arc::new(secrets);
        let id = new_session_id().map_err(|_| SessionError::Internal)?;
        let persistent = session.persistent;
        {
            let mut registry = self.registry.lock().await;
            if !registry.accepting_sessions {
                return Err(SessionError::ShuttingDown);
            }
            if registry.sessions.len() + registry.provisioning.len() >= self.max_sessions {
                return Err(SessionError::AtCapacity);
            }
            if registry.sessions.contains_key(&id) || !registry.provisioning.insert(id.clone()) {
                return Err(SessionError::Internal);
            }
        }

        let socket_name = session
            .socket_name
            .clone()
            .unwrap_or_else(|| format!("{id}.sock"));
        let socket_path = match absolute_socket_path(&self.socket_dir.join(socket_name)) {
            Ok(path) => path,
            Err(_) => {
                self.registry.lock().await.provisioning.remove(&id);
                return Err(SessionError::Internal);
            }
        };
        let listener_gate = Arc::new(AtomicU64::new(1));
        let runtime = match ProxyRuntime::start_session_with_metrics(
            RuntimeId::new(id.clone()),
            session.clone(),
            Arc::clone(&secrets),
            Arc::clone(&self.ca),
            socket_path,
            self.max_connections_per_session,
            self.io_timeout,
            Arc::clone(&self.metrics),
            self.runtime_events.clone(),
            Arc::clone(&listener_gate),
            1,
        )
        .await
        {
            Ok(runtime) => runtime,
            Err(error) => {
                self.registry.lock().await.provisioning.remove(&id);
                return Err(SessionError::Runtime(error));
            }
        };
        let info = SessionInfo {
            socket: runtime.socket_path().to_string_lossy().into_owned(),
            id: id.clone(),
            persistent,
            state: SessionLifecycle::Running,
            generation: 1,
            draining_generations: 0,
        };
        let mut registry = self.registry.lock().await;
        registry.provisioning.remove(&id);
        if !registry.accepting_sessions {
            drop(registry);
            drop(runtime);
            return Err(SessionError::ShuttingDown);
        }
        registry.sessions.insert(
            id,
            ManagedSession {
                info: info.clone(),
                owner_uid,
                configuration: session,
                secrets,
                config_source,
                runtime: Some(runtime),
                retired_runtimes: Vec::new(),
                reload_lock: Arc::new(Mutex::new(())),
                listener_gate,
                listener_generation: 1,
            },
        );
        let active_sessions = self.metrics.session_started();
        tracing::info!(
            event = "session_lifecycle",
            session_id = %info.id,
            state = "running",
            active_sessions,
            "proxy session started"
        );
        Ok(info)
    }

    pub(super) async fn reject_new_sessions(&self) {
        self.registry.lock().await.accepting_sessions = false;
    }

    pub(super) async fn stop(&self, id: &str, owner_uid: u32) -> bool {
        let reload_lock = {
            let registry = self.registry.lock().await;
            let Some(session) = registry.sessions.get(id) else {
                return false;
            };
            if session.owner_uid != owner_uid {
                return false;
            }
            Arc::clone(&session.reload_lock)
        };
        let _serial = reload_lock.lock().await;
        let runtimes = {
            let mut registry = self.registry.lock().await;
            let Some(session) = registry.sessions.get_mut(id) else {
                return false;
            };
            if session.owner_uid != owner_uid {
                return false;
            }
            if session.info.state == SessionLifecycle::Stopping {
                return true;
            }
            session.info.state = SessionLifecycle::Stopping;
            let mut runtimes = std::mem::take(&mut session.retired_runtimes);
            runtimes.extend(session.runtime.take());
            runtimes
        };
        self.shutdown_runtimes(runtimes).await;
        if self.registry.lock().await.sessions.remove(id).is_some() {
            let active_sessions = self.metrics.session_stopped();
            tracing::info!(
                event = "session_lifecycle",
                session_id = id,
                state = "stopped",
                reason = "explicit_stop",
                active_sessions,
                "proxy session removed"
            );
        }
        true
    }

    pub(super) async fn remove(&self, id: &str, reason: &'static str) {
        let reload_lock = {
            let registry = self.registry.lock().await;
            let Some(session) = registry.sessions.get(id) else {
                return;
            };
            Arc::clone(&session.reload_lock)
        };
        let _serial = reload_lock.lock().await;
        let runtimes = {
            let mut registry = self.registry.lock().await;
            let Some(session) = registry.sessions.get_mut(id) else {
                return;
            };
            if session.info.state == SessionLifecycle::Stopping && session.runtime.is_none() {
                return;
            }
            session.info.state = SessionLifecycle::Stopping;
            let mut runtimes = std::mem::take(&mut session.retired_runtimes);
            runtimes.extend(session.runtime.take());
            runtimes
        };
        self.shutdown_runtimes(runtimes).await;
        if self.registry.lock().await.sessions.remove(id).is_some() {
            let active_sessions = self.metrics.session_stopped();
            tracing::info!(
                event = "session_lifecycle",
                session_id = id,
                state = "stopped",
                reason,
                active_sessions,
                "proxy session removed"
            );
        }
    }

    pub(super) async fn runtime_exit(&self, id: &str, listener_generation: u64) {
        let reload_lock = {
            let registry = self.registry.lock().await;
            let Some(session) = registry.sessions.get(id) else {
                return;
            };
            Arc::clone(&session.reload_lock)
        };
        let _serial = reload_lock.lock().await;
        let runtimes = {
            let mut registry = self.registry.lock().await;
            let Some(session) = registry.sessions.get_mut(id) else {
                return;
            };
            if session.listener_generation != listener_generation {
                session
                    .retired_runtimes
                    .retain(|runtime| runtime.listener_generation() != listener_generation);
                session.info.draining_generations = session.retired_runtimes.len();
                return;
            }
            if session.info.state == SessionLifecycle::Stopping && session.runtime.is_none() {
                return;
            }
            session.info.state = SessionLifecycle::Stopping;
            let mut runtimes = std::mem::take(&mut session.retired_runtimes);
            runtimes.extend(session.runtime.take());
            runtimes
        };
        self.shutdown_runtimes(runtimes).await;
        if self.registry.lock().await.sessions.remove(id).is_some() {
            let active_sessions = self.metrics.session_stopped();
            tracing::info!(
                event = "session_lifecycle",
                session_id = id,
                state = "stopped",
                reason = "runtime_exit",
                active_sessions,
                "proxy session removed"
            );
        }
    }

    pub(super) async fn shutdown_all(&self) {
        let session_ids = {
            let mut registry = self.registry.lock().await;
            registry.accepting_sessions = false;
            registry.provisioning.clear();
            registry.sessions.keys().cloned().collect::<Vec<_>>()
        };
        let mut runtimes = Vec::new();
        let mut session_count = 0;
        for id in session_ids {
            let reload_lock = {
                let registry = self.registry.lock().await;
                registry
                    .sessions
                    .get(&id)
                    .map(|session| Arc::clone(&session.reload_lock))
            };
            let Some(reload_lock) = reload_lock else {
                continue;
            };
            let _serial = reload_lock.lock().await;
            if let Some(session) = self.registry.lock().await.sessions.get_mut(&id) {
                session.info.state = SessionLifecycle::Stopping;
                runtimes.append(&mut session.retired_runtimes);
                runtimes.extend(session.runtime.take());
                session_count += 1;
            }
        }
        self.shutdown_runtimes(runtimes).await;
        self.registry.lock().await.sessions.clear();
        for _ in 0..session_count {
            self.metrics.session_stopped();
        }
    }

    pub(super) async fn shutdown_runtimes(&self, runtimes: Vec<ProxyRuntime>) {
        let mut shutdowns = JoinSet::new();
        for runtime in runtimes {
            let grace = self.shutdown_grace;
            shutdowns.spawn(async move { runtime.shutdown(grace).await });
        }
        while shutdowns.join_next().await.is_some() {}
    }

    pub(super) async fn list(&self, owner_uid: u32) -> Vec<SessionInfo> {
        let mut registry = self.registry.lock().await;
        for session in registry.sessions.values_mut() {
            session
                .retired_runtimes
                .retain(|runtime| !runtime.is_finished());
            session.info.draining_generations = session.retired_runtimes.len();
        }
        let mut sessions = registry
            .sessions
            .values()
            .filter(|session| session.owner_uid == owner_uid)
            .map(|session| session.info.clone())
            .collect::<Vec<_>>();
        sessions.sort_by(|left, right| left.id.cmp(&right.id));
        sessions
    }
}

pub(super) fn absolute_socket_path(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

pub(super) struct ManagedSession {
    pub(super) info: SessionInfo,
    pub(super) owner_uid: u32,
    // Keep the validated configuration with its runtime. Secret values are
    // held separately and neither value is included in list responses.
    pub(super) configuration: SessionConfig,
    // Secret values remain scoped to this session and are never serialized.
    pub(super) secrets: Arc<ResolvedSecrets>,
    pub(super) config_source: Option<String>,
    pub(super) runtime: Option<ProxyRuntime>,
    pub(super) retired_runtimes: Vec<ProxyRuntime>,
    pub(super) reload_lock: Arc<Mutex<()>>,
    pub(super) listener_gate: Arc<AtomicU64>,
    pub(super) listener_generation: u64,
}

#[derive(Debug)]
pub(super) enum SessionError {
    AtCapacity,
    Runtime(ProxyRuntimeError),
    ShuttingDown,
    Internal,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct SessionInfo {
    pub(super) id: String,
    pub(super) socket: String,
    pub(super) persistent: bool,
    pub(super) state: SessionLifecycle,
    pub(super) generation: u64,
    pub(super) draining_generations: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SessionLifecycle {
    Running,
    Stopping,
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
#[path = "tests/session.rs"]
mod tests;
