//! Backend-neutral proxy session entry points.
//!
//! The daemon and control protocol use this module without importing either
//! backend's networking types. Cargo selects exactly one implementation.

#[cfg(all(feature = "backend-hudsucker", not(feature = "backend-rama")))]
#[path = "proxy_runtime/hudsucker.rs"]
mod backend;

#[cfg(all(feature = "backend-rama", not(feature = "backend-hudsucker")))]
#[path = "proxy_runtime/rama.rs"]
mod backend;

#[cfg(any(feature = "backend-hudsucker", feature = "backend-rama"))]
pub use backend::ProxyRuntime;

#[cfg(all(feature = "backend-hudsucker", test))]
pub(crate) use backend::PolicyHandler;

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
    Bind(io::Error),
    BindSocket(io::Error),
    Bridge(io::Error),
    Build(String),
    Run(String),
    Task(String),
    BackendUnavailable,
}

impl ProxyRuntimeError {
    pub fn class(&self) -> &'static str {
        match self {
            Self::Bind(_) => "bind",
            Self::BindSocket(_) => "socket_bind",
            Self::Bridge(_) => "bridge",
            Self::Build(_) => "proxy_build",
            Self::Run(_) => "proxy_run",
            Self::Task(_) => "task",
            Self::BackendUnavailable => "backend_unavailable",
        }
    }
}

impl fmt::Display for ProxyRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind(_) => formatter.write_str("could not bind proxy listener"),
            Self::BindSocket(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                formatter.write_str("proxy Unix socket path already exists")
            }
            Self::BindSocket(_) => formatter.write_str("could not bind proxy Unix socket"),
            Self::Bridge(_) => formatter.write_str("proxy Unix socket bridge failed"),
            Self::Build(_) => formatter.write_str("could not build proxy"),
            Self::Run(_) => formatter.write_str("proxy runtime failed"),
            Self::Task(_) => formatter.write_str("proxy runtime task failed"),
            Self::BackendUnavailable => formatter.write_str(
                "Rama backend is disabled until Baffle's upstream TLS and authority checks are integrated",
            ),
        }
    }
}

impl std::error::Error for ProxyRuntimeError {}

/// A typed notification that a proxy runtime exited.
#[derive(Debug)]
pub struct ProxyRuntimeEvent {
    pub runtime_id: RuntimeId,
    pub result: Result<(), ProxyRuntimeError>,
}
