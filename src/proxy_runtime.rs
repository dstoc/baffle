//! One Hudsucker proxy instance hosted by the daemon's shared Tokio runtime.

use std::{fmt, future::Future, io, net::SocketAddr, sync::Arc, time::Duration};

use hudsucker::{
    Body, HttpContext, HttpHandler, Proxy, RequestOrResponse, WebSocketContext, WebSocketHandler,
    hyper::{Request, Response, StatusCode},
    rustls::crypto::aws_lc_rs,
    tokio_tungstenite::tungstenite::Message,
};
use tokio::{
    net::TcpListener,
    task::{AbortHandle, JoinHandle},
};
use tokio_util::sync::CancellationToken;

use crate::{ca::ManagedCa, config::SessionConfig};

/// A stable identifier for one running Hudsucker instance.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RuntimeId(String);

impl RuntimeId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A startup or fatal error from one proxy instance.
#[derive(Debug)]
pub enum ProxyRuntimeError {
    Bind(io::Error),
    Build(hudsucker::Error),
    Run(hudsucker::Error),
    Task(String),
}

impl fmt::Display for ProxyRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind(error) => write!(formatter, "could not bind proxy listener: {error}"),
            Self::Build(error) => write!(formatter, "could not build proxy: {error}"),
            Self::Run(error) => write!(formatter, "proxy runtime failed: {error}"),
            Self::Task(error) => write!(formatter, "proxy runtime task failed: {error}"),
        }
    }
}

/// A typed notification that a proxy runtime exited.
#[derive(Debug)]
pub struct ProxyRuntimeEvent {
    pub runtime_id: RuntimeId,
    pub result: Result<(), ProxyRuntimeError>,
}

/// A running proxy with its dedicated listener, cancellation token, and task.
pub struct ProxyRuntime {
    runtime_id: RuntimeId,
    local_addr: SocketAddr,
    cancellation: CancellationToken,
    runtime_abort: AbortHandle,
    task: JoinHandle<()>,
}

impl ProxyRuntime {
    /// Bind and start one proxy from a validated session configuration.
    ///
    /// Hudsucker builds its outbound client inside each `start` call. This
    /// method creates a separate builder and handler for every runtime while
    /// sharing only the daemon-owned CA material.
    pub async fn start(
        runtime_id: RuntimeId,
        session: SessionConfig,
        ca: Arc<ManagedCa>,
        events: tokio::sync::mpsc::UnboundedSender<ProxyRuntimeEvent>,
    ) -> Result<Self, ProxyRuntimeError> {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .map_err(ProxyRuntimeError::Bind)?;
        let local_addr = listener.local_addr().map_err(ProxyRuntimeError::Bind)?;
        let cancellation = CancellationToken::new();
        let shutdown = cancellation.clone();

        let proxy = Proxy::builder()
            .with_listener(listener)
            .with_ca(ca.for_proxy())
            .with_rustls_connector(aws_lc_rs::default_provider())
            .with_http_handler(DenyAllHandler {
                runtime_id: runtime_id.clone(),
                _session: session.clone(),
            })
            .with_websocket_handler(DenyAllHandler {
                runtime_id: runtime_id.clone(),
                _session: session,
            })
            .with_graceful_shutdown(async move {
                shutdown.cancelled().await;
            })
            .build()
            .map_err(ProxyRuntimeError::Build)?;

        // Keep the Hudsucker task's result observable even if the task panics.
        let runtime_task = tokio::spawn(proxy.start());
        let runtime_abort = runtime_task.abort_handle();
        let event_id = runtime_id.clone();
        let task = tokio::spawn(async move {
            let result = match runtime_task.await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(ProxyRuntimeError::Run(error)),
                Err(error) => Err(ProxyRuntimeError::Task(error.to_string())),
            };
            let _ = events.send(ProxyRuntimeEvent {
                runtime_id: event_id,
                result,
            });
        });

        Ok(Self {
            runtime_id,
            local_addr,
            cancellation,
            runtime_abort,
            task,
        })
    }

    pub fn runtime_id(&self) -> &RuntimeId {
        &self.runtime_id
    }

    /// Return the pre-bound loopback listener address used by Hudsucker.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Ask Hudsucker to drain active connections, then bound the wait.
    pub async fn shutdown(mut self, grace: Duration) {
        self.cancellation.cancel();
        if tokio::time::timeout(grace, &mut self.task).await.is_err() {
            self.runtime_abort.abort();
            let _ = (&mut self.task).await;
        }
    }
}

impl Drop for ProxyRuntime {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

#[derive(Clone)]
struct DenyAllHandler {
    runtime_id: RuntimeId,
    // Retain the validated, immutable policy with its own handler state. Policy
    // decisions are added in the filtering milestone; this runtime denies all.
    _session: SessionConfig,
}

impl HttpHandler for DenyAllHandler {
    fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        _request: Request<Body>,
    ) -> impl Future<Output = RequestOrResponse> + Send {
        tracing::debug!(runtime_id = %self.runtime_id.as_str(), "denying outbound proxy request");
        async {
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::empty())
                .expect("static deny response is valid")
                .into()
        }
    }
}

impl WebSocketHandler for DenyAllHandler {
    async fn handle_message(
        &mut self,
        _ctx: &WebSocketContext,
        _message: Message,
    ) -> Option<Message> {
        None
    }
}
