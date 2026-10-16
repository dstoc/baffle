//! Backend-independent proxy session boundary.
//!
//! The daemon provisions an opaque runtime, reads its bound listener details,
//! receives fatal runtime events, and cancels it with bounded shutdown. The
//! private Rama module owns the Unix listener, tasks, and cleanup.

mod rama;
mod test_trust;

pub use rama::ProxyRuntime;
pub(crate) use test_trust::TestUpstreamTrust;

#[cfg(any(test, feature = "benchmark-tcp-nodelay"))]
pub(crate) fn benchmark_tcp_nodelay_mode() -> String {
    #[cfg(feature = "benchmark-tcp-nodelay")]
    {
        std::env::var("BAFFLE_BENCH_TCP_NODELAY").unwrap_or_else(|_| "production".to_owned())
    }
    #[cfg(not(feature = "benchmark-tcp-nodelay"))]
    {
        "production".to_owned()
    }
}

#[cfg(any(test, feature = "benchmark-tcp-nodelay"))]
pub(crate) fn benchmark_tcp_nodelay_enabled(socket_leg: &str) -> bool {
    let mode = benchmark_tcp_nodelay_mode();
    mode == socket_leg || mode == "all"
}

#[cfg(test)]
mod benchmark;

use std::{fmt, io};

/// A stable identifier for one running proxy session.
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

/// A backend-neutral startup or fatal runtime error.
#[derive(Debug)]
pub enum ProxyRuntimeError {
    BindSocket(io::Error),
    Build(String),
    Run(String),
    Task(String),
}

impl ProxyRuntimeError {
    pub fn class(&self) -> &'static str {
        match self {
            Self::BindSocket(_) => "socket_bind",
            Self::Build(_) => "proxy_build",
            Self::Run(_) => "proxy_run",
            Self::Task(_) => "task",
        }
    }
}

impl fmt::Display for ProxyRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BindSocket(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                formatter.write_str("proxy Unix socket path already exists")
            }
            Self::BindSocket(_) => formatter.write_str("could not bind proxy Unix socket"),
            Self::Build(_) => formatter.write_str("could not build proxy"),
            Self::Run(_) => formatter.write_str("proxy runtime failed"),
            Self::Task(_) => formatter.write_str("proxy runtime task failed"),
        }
    }
}

impl std::error::Error for ProxyRuntimeError {}

/// A typed notification that a proxy runtime exited.
#[derive(Debug)]
pub struct ProxyRuntimeEvent {
    pub runtime_id: RuntimeId,
    pub listener_generation: u64,
    pub retired: bool,
    pub result: Result<(), ProxyRuntimeError>,
}
