use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use super::{ProxyRuntimeError, ProxyRuntimeEvent, RuntimeId};
use tokio::{
    sync::{Semaphore, watch},
    task::{AbortHandle, JoinHandle},
};
use tokio_util::sync::CancellationToken;

use crate::{
    ca::ManagedCa, config::SessionConfig, policy::SessionPolicy, proxy_runtime::TestUpstreamTrust,
    secrets::ResolvedSecrets, telemetry::Metrics,
};

pub(crate) const MAX_POLICY_GENERATIONS: usize = 8;

#[derive(Debug, Clone, Copy)]
pub(crate) struct RuntimeGenerationLimit;

/// An opaque proxy session served directly on its private Unix socket.
pub struct ProxyRuntime {
    runtime_id: RuntimeId,
    listener_generation: u64,
    socket_path: PathBuf,
    cancellation: CancellationToken,
    retirement: CancellationToken,
    retired: Arc<AtomicBool>,
    task_abort: AbortHandle,
    task: JoinHandle<()>,
    metrics: Arc<Metrics>,
    generation: watch::Sender<Arc<ProxyGeneration>>,
    generations: Arc<Mutex<Vec<Weak<ProxyGeneration>>>>,
    permits: Arc<Semaphore>,
    socket_guard: Arc<Mutex<Option<ingress::UnixSocketGuard>>>,
}

struct ProxyGeneration {
    policy: Arc<SessionPolicy>,
    secrets: Arc<ResolvedSecrets>,
}

/// Named inputs for a runtime that shares session-owned lifecycle state.
pub(crate) struct ProxyRuntimeOptions {
    pub(crate) runtime_id: RuntimeId,
    pub(crate) session: SessionConfig,
    pub(crate) secrets: Arc<ResolvedSecrets>,
    pub(crate) ca: Arc<ManagedCa>,
    pub(crate) socket_path: PathBuf,
    pub(crate) connection_permits: Arc<Semaphore>,
    pub(crate) io_timeout: Duration,
    pub(crate) metrics: Arc<Metrics>,
    pub(crate) test_upstream_trust: TestUpstreamTrust,
    pub(crate) events: tokio::sync::mpsc::UnboundedSender<ProxyRuntimeEvent>,
    pub(crate) socket_directories: Arc<ingress::SocketDirectoryRegistry>,
    pub(crate) listener_gate: Arc<AtomicU64>,
    pub(crate) listener_generation: u64,
}

impl ProxyRuntime {
    /// Bind and start one runtime from a validated session configuration.
    ///
    /// Success means the private Unix socket is bound. The returned handle owns
    /// all runtime tasks until bounded shutdown or cancellation on drop.
    pub async fn start(
        runtime_id: RuntimeId,
        session: SessionConfig,
        ca: Arc<ManagedCa>,
        socket_path: PathBuf,
        max_connections: usize,
        events: tokio::sync::mpsc::UnboundedSender<ProxyRuntimeEvent>,
    ) -> Result<Self, ProxyRuntimeError> {
        Self::start_with_options(ProxyRuntimeOptions {
            runtime_id,
            session,
            secrets: Arc::new(ResolvedSecrets::default()),
            ca,
            socket_path,
            connection_permits: Arc::new(Semaphore::new(max_connections)),
            io_timeout: Duration::from_secs(30),
            metrics: Arc::new(Metrics::default()),
            test_upstream_trust: TestUpstreamTrust::default(),
            events,
            socket_directories: Arc::new(ingress::SocketDirectoryRegistry::default()),
            listener_gate: Arc::new(AtomicU64::new(1)),
            listener_generation: 1,
        })
        .await
    }

    pub(crate) async fn start_with_options(
        options: ProxyRuntimeOptions,
    ) -> Result<Self, ProxyRuntimeError> {
        let ProxyRuntimeOptions {
            runtime_id,
            session,
            secrets,
            ca,
            socket_path,
            connection_permits: permits,
            io_timeout,
            metrics,
            test_upstream_trust,
            events,
            socket_directories,
            listener_gate,
            listener_generation,
        } = options;
        let (unix_listener, socket_guard) =
            ingress::bind_unix_listener(&socket_path, socket_directories)
                .map_err(ProxyRuntimeError::BindSocket)?;
        let socket_guard = Arc::new(Mutex::new(Some(socket_guard)));

        let generation = Arc::new(ProxyGeneration {
            policy: Arc::new(SessionPolicy::compile(&session)),
            secrets,
        });
        let (generation_sender, generation_receiver) = watch::channel(Arc::clone(&generation));
        let generations = Arc::new(Mutex::new(vec![Arc::downgrade(&generation)]));
        let tls_relay = tls::new_cached_relay(&ca);
        let cancellation = CancellationToken::new();
        let retirement = CancellationToken::new();
        let retired = Arc::new(AtomicBool::new(false));
        let mut proxy_task = tokio::spawn(ingress::run_proxy(
            unix_listener,
            Arc::clone(&socket_guard),
            ingress::ProxySettings {
                generations: generation_receiver,
                tls_relay,
                test_upstream_trust,
                permits: Arc::clone(&permits),
                cancellation: cancellation.clone(),
                retirement: retirement.clone(),
                listener_gate: Arc::clone(&listener_gate),
                listener_generation,
                metrics: Arc::clone(&metrics),
                io_timeout,
            },
        ));
        let task_abort = proxy_task.abort_handle();
        let event_id = runtime_id.clone();
        let event_retired = Arc::clone(&retired);
        let event_gate = Arc::clone(&listener_gate);
        let task = tokio::spawn(async move {
            let result = map_proxy_join((&mut proxy_task).await);
            if result.is_err() {
                tracing::error!(
                    event = "session_lifecycle",
                    session_id = %event_id.as_str(),
                    state = "failed",
                    "Rama proxy session task failed"
                );
            }
            let retired = event_retired.load(Ordering::Acquire);
            if retired || event_gate.load(Ordering::Acquire) == listener_generation {
                let _ = events.send(ProxyRuntimeEvent {
                    runtime_id: event_id,
                    listener_generation,
                    retired,
                    result,
                });
            }
        });

        Ok(Self {
            runtime_id,
            listener_generation,
            socket_path,
            cancellation,
            retirement,
            retired,
            task_abort,
            task,
            metrics,
            generation: generation_sender,
            generations,
            permits,
            socket_guard,
        })
    }

    pub fn runtime_id(&self) -> &RuntimeId {
        &self.runtime_id
    }

    pub(crate) fn listener_generation(&self) -> u64 {
        self.listener_generation
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Atomically select a new immutable policy for connections accepted next.
    pub(crate) fn replace_generation(
        &self,
        session: &SessionConfig,
        secrets: Arc<ResolvedSecrets>,
    ) -> Result<(), RuntimeGenerationLimit> {
        let generation = Arc::new(ProxyGeneration {
            policy: Arc::new(SessionPolicy::compile(session)),
            secrets,
        });
        let mut generations = self.generations.lock().expect("generation lock poisoned");
        generations.retain(|generation| generation.strong_count() > 0);
        if generations.len() >= MAX_POLICY_GENERATIONS {
            return Err(RuntimeGenerationLimit);
        }
        self.generation.send_replace(Arc::clone(&generation));
        generations.push(Arc::downgrade(&generation));
        Ok(())
    }

    /// Stop accepting and drain connections already accepted by this listener.
    pub(crate) fn mark_retiring(&self) {
        self.retired.store(true, Ordering::Release);
    }

    pub(crate) fn retire(&self) {
        self.mark_retiring();
        self.retirement.cancel();
        if let Ok(guard) = self.socket_guard.lock()
            && let Some(guard) = guard.as_ref()
        {
            guard.unlink_owned();
        }
    }

    pub(crate) fn connection_permits(&self) -> Arc<Semaphore> {
        Arc::clone(&self.permits)
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    /// Cancel ingress, drain active work, then abort after the grace period.
    pub async fn shutdown(mut self, grace: Duration) {
        tracing::info!(
            event = "session_lifecycle",
            session_id = %self.runtime_id.as_str(),
            state = "stopping",
            "Rama proxy session shutdown started"
        );
        if let Ok(mut guard) = self.socket_guard.lock() {
            guard.take();
        }
        self.cancellation.cancel();
        if tokio::time::timeout(grace, &mut self.task).await.is_err() {
            self.metrics.forced_shutdown();
            self.task_abort.abort();
            let _ = (&mut self.task).await;
        }
    }
}

impl Drop for ProxyRuntime {
    fn drop(&mut self) {
        self.cancellation.cancel();
        // If the session owner is cancelled while awaiting graceful shutdown,
        // do not detach the proxy connection tasks.
        self.task_abort.abort();
        if let Ok(mut guard) = self.socket_guard.lock() {
            guard.take();
        }
    }
}

fn map_proxy_join(
    result: Result<Result<(), ProxyRuntimeError>, tokio::task::JoinError>,
) -> Result<(), ProxyRuntimeError> {
    result.map_err(|error| ProxyRuntimeError::Task(error.to_string()))?
}

mod connect;
mod http;
mod ingress;
mod tls;

pub(crate) use ingress::SocketDirectoryRegistry;

#[cfg(test)]
mod tests;
