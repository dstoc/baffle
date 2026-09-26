use std::{
    path::PathBuf,
    sync::{Arc, atomic::Ordering},
};

use serde::Serialize;

use crate::{
    config::ControlRequest,
    proxy_runtime::{ProxyRuntime, RuntimeId},
    secrets::SecretStore,
};

use super::{
    file_config::{SessionConfigFileError, SessionConfigStore},
    session::{SessionLifecycle, SessionManager, absolute_socket_path},
};

const MAX_RETIRED_LISTENERS: usize = 8;

impl SessionManager {
    pub(super) async fn reload(
        &self,
        id: &str,
        owner_uid: u32,
        configs: Option<&SessionConfigStore>,
        secret_store: &SecretStore,
    ) -> std::result::Result<SessionReloadResult, ()> {
        let reload_lock = {
            let registry = self.registry.lock().await;
            let Some(session) = registry.sessions.get(id) else {
                return Err(());
            };
            if session.owner_uid != owner_uid {
                return Err(());
            }
            Arc::clone(&session.reload_lock)
        };
        let _serial = reload_lock.lock().await;
        Ok(self
            .reload_locked(id, owner_uid, configs, secret_store)
            .await)
    }

    pub(super) async fn reload_all(
        &self,
        owner_uid: u32,
        configs: Option<&SessionConfigStore>,
        secret_store: &SecretStore,
    ) -> Vec<SessionReloadResult> {
        let sessions = {
            let registry = self.registry.lock().await;
            let mut sessions = registry
                .sessions
                .values()
                .filter(|session| {
                    session.owner_uid == owner_uid
                        && session.config_source.is_some()
                        && session.info.state == SessionLifecycle::Running
                })
                .map(|session| (session.info.id.clone(), session.info.socket.clone()))
                .collect::<Vec<_>>();
            sessions.sort_by(|left, right| left.0.cmp(&right.0));
            sessions
        };
        let mut results = Vec::with_capacity(sessions.len());
        for (id, socket) in sessions {
            match self.reload(&id, owner_uid, configs, secret_store).await {
                Ok(result) => results.push(result),
                Err(()) => results.push(SessionReloadResult::failed(
                    &id,
                    socket,
                    "session_unavailable",
                )),
            }
        }
        results
    }

    pub(super) async fn reload_locked(
        &self,
        id: &str,
        owner_uid: u32,
        configs: Option<&SessionConfigStore>,
        secret_store: &SecretStore,
    ) -> SessionReloadResult {
        let (config_source, current_secrets, current_socket, persistent) = {
            let mut registry = self.registry.lock().await;
            let accepting = registry.accepting_sessions;
            let Some(session) = registry.sessions.get_mut(id) else {
                return SessionReloadResult::failed(id, "".to_owned(), "session_unavailable");
            };
            if session.owner_uid != owner_uid {
                return SessionReloadResult::failed(id, "".to_owned(), "session_unavailable");
            }
            session
                .retired_runtimes
                .retain(|runtime| !runtime.is_finished());
            session.info.draining_generations = session.retired_runtimes.len();
            if session.info.state != SessionLifecycle::Running || !accepting {
                return SessionReloadResult::failed(
                    id,
                    session.info.socket.clone(),
                    "session_stopping",
                );
            }
            let Some(source) = session.config_source.clone() else {
                return SessionReloadResult::failed(
                    id,
                    session.info.socket.clone(),
                    "inline_session",
                );
            };
            (
                source,
                Arc::clone(&session.secrets),
                session.info.socket.clone(),
                session.configuration.persistent,
            )
        };

        let Some(configs) = configs else {
            return SessionReloadResult::failed(id, current_socket, "configuration_unavailable");
        };
        let text = match configs.read_snapshot(&config_source) {
            Ok(text) => text,
            Err(SessionConfigFileError::NotFound) => {
                return SessionReloadResult::failed(id, current_socket, "configuration_not_found");
            }
            Err(SessionConfigFileError::Unavailable) => {
                return SessionReloadResult::failed(
                    id,
                    current_socket,
                    "configuration_unavailable",
                );
            }
            Err(SessionConfigFileError::Invalid) => {
                return SessionReloadResult::failed(id, current_socket, "configuration_invalid");
            }
        };
        let mut candidate = match ControlRequest::from_toml(&text) {
            Ok(ControlRequest::Create { session, .. }) => session,
            _ => {
                return SessionReloadResult::failed(id, current_socket, "configuration_invalid");
            }
        };
        // Persistence is the lifetime chosen at creation. A file edit cannot
        // turn a leased session into a persistent one or end its lease.
        candidate.persistent = persistent;
        let candidate_secrets = match secret_store.resolve(owner_uid, &candidate) {
            Ok(secrets) => Arc::new(secrets),
            Err(_) => {
                return SessionReloadResult::failed(id, current_socket, "credentials_unavailable");
            }
        };
        let target_path = self.socket_dir.join(
            candidate
                .socket_name
                .as_deref()
                .map(str::to_owned)
                .unwrap_or_else(|| format!("{id}.sock")),
        );
        let target_path = match absolute_socket_path(&target_path) {
            Ok(path) => path,
            Err(_) => {
                return SessionReloadResult::failed(id, current_socket, "listener_unavailable");
            }
        };
        let current_path = PathBuf::from(&current_socket);
        let same_path = target_path == current_path;
        let configuration_unchanged = same_effective_rules(&candidate.rules, &{
            let registry = self.registry.lock().await;
            let Some(session) = registry.sessions.get(id) else {
                return SessionReloadResult::failed(id, current_socket, "session_unavailable");
            };
            session.configuration.rules.clone()
        });
        if configuration_unchanged
            && same_path
            && current_secrets.has_same_values(&candidate_secrets)
        {
            return SessionReloadResult::unchanged(id, current_socket);
        }

        if same_path {
            let mut registry = self.registry.lock().await;
            if !registry.accepting_sessions {
                return SessionReloadResult::failed(id, current_socket, "session_stopping");
            }
            let Some(session) = registry.sessions.get_mut(id) else {
                return SessionReloadResult::failed(id, current_socket, "session_unavailable");
            };
            let Some(runtime) = session.runtime.as_ref() else {
                return SessionReloadResult::failed(id, current_socket, "session_stopping");
            };
            if runtime
                .replace_generation(&candidate, Arc::clone(&candidate_secrets))
                .is_err()
            {
                return SessionReloadResult::failed(id, current_socket, "generation_limit");
            }
            session.configuration = candidate;
            session.secrets = candidate_secrets;
            session.info.generation = session.info.generation.saturating_add(1);
            session.info.draining_generations = session.retired_runtimes.len();
            return SessionReloadResult::reloaded(id, current_socket);
        }

        let (permits, listener_gate, next_listener_generation, can_retire) = {
            let mut registry = self.registry.lock().await;
            if !registry.accepting_sessions {
                return SessionReloadResult::failed(id, current_socket, "session_stopping");
            }
            let Some(session) = registry.sessions.get_mut(id) else {
                return SessionReloadResult::failed(id, current_socket, "session_unavailable");
            };
            session
                .retired_runtimes
                .retain(|runtime| !runtime.is_finished());
            let Some(runtime) = session.runtime.as_ref() else {
                return SessionReloadResult::failed(id, current_socket, "session_stopping");
            };
            let Some(next_listener_generation) = session.listener_generation.checked_add(1) else {
                return SessionReloadResult::failed(id, current_socket, "generation_limit");
            };
            (
                runtime.connection_permits(),
                Arc::clone(&session.listener_gate),
                next_listener_generation,
                session.retired_runtimes.len() < MAX_RETIRED_LISTENERS,
            )
        };
        if !can_retire {
            return SessionReloadResult::failed(id, current_socket, "generation_limit");
        }
        let replacement = match ProxyRuntime::start_replacement_with_metrics(
            RuntimeId::new(id.to_owned()),
            candidate.clone(),
            Arc::clone(&candidate_secrets),
            Arc::clone(&self.ca),
            target_path.clone(),
            permits,
            self.io_timeout,
            Arc::clone(&self.metrics),
            self.runtime_events.clone(),
            Arc::clone(&listener_gate),
            next_listener_generation,
        )
        .await
        {
            Ok(runtime) => runtime,
            Err(_) => {
                return SessionReloadResult::failed(id, current_socket, "listener_unavailable");
            }
        };

        let mut registry = self.registry.lock().await;
        if !registry.accepting_sessions {
            drop(registry);
            replacement.shutdown(self.shutdown_grace).await;
            return SessionReloadResult::failed(id, current_socket, "session_stopping");
        }
        let Some(session) = registry.sessions.get_mut(id) else {
            drop(registry);
            replacement.shutdown(self.shutdown_grace).await;
            return SessionReloadResult::failed(id, current_socket, "session_unavailable");
        };
        if session.info.state != SessionLifecycle::Running {
            drop(registry);
            replacement.shutdown(self.shutdown_grace).await;
            return SessionReloadResult::failed(id, current_socket, "session_stopping");
        }
        let Some(old_runtime) = session.runtime.replace(replacement) else {
            session.runtime = None;
            drop(registry);
            return SessionReloadResult::failed(id, current_socket, "session_stopping");
        };
        session.configuration = candidate;
        session.secrets = candidate_secrets;
        session.info.socket = target_path.to_string_lossy().into_owned();
        session.info.generation = session.info.generation.saturating_add(1);
        session.listener_generation = next_listener_generation;
        old_runtime.mark_retiring();
        session
            .listener_gate
            .store(next_listener_generation, Ordering::Release);
        old_runtime.retire();
        session.retired_runtimes.push(old_runtime);
        session.info.draining_generations = session.retired_runtimes.len();
        SessionReloadResult::reloaded(id, session.info.socket.clone())
    }
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct SessionReloadResult {
    id: String,
    status: ReloadStatus,
    socket: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

impl SessionReloadResult {
    pub(super) fn reloaded(id: &str, socket: String) -> Self {
        Self {
            id: id.to_owned(),
            status: ReloadStatus::Reloaded,
            socket,
            reason: None,
        }
    }

    pub(super) fn unchanged(id: &str, socket: String) -> Self {
        Self {
            id: id.to_owned(),
            status: ReloadStatus::Unchanged,
            socket,
            reason: None,
        }
    }

    pub(super) fn failed(id: &str, socket: String, reason: &'static str) -> Self {
        Self {
            id: id.to_owned(),
            status: ReloadStatus::Failed,
            socket,
            reason: Some(reason),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReloadStatus {
    Reloaded,
    Unchanged,
    Failed,
}

fn same_effective_rules(
    left: &[crate::config::HostRule],
    right: &[crate::config::HostRule],
) -> bool {
    fn canonical(rules: &[crate::config::HostRule]) -> Vec<crate::config::HostRule> {
        let mut rules = rules.to_vec();
        for rule in &mut rules {
            rule.ports.sort_unstable();
            rule.paths.sort_by_key(|path| path.as_str());
            for injection in &mut rule.inject {
                injection.header.make_ascii_lowercase();
            }
            rule.inject
                .sort_by(|left, right| left.header.cmp(&right.header));
        }
        rules.sort_by(|left, right| left.host.cmp(&right.host));
        rules
    }

    canonical(left) == canonical(right)
}
