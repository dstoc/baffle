//! Backend-independent proxy session boundary.
//!
//! The daemon provisions an opaque runtime, reads its bound listener details,
//! receives fatal runtime events, and cancels it with bounded shutdown. The
//! private Rama module owns the Unix listener, tasks, and cleanup.

mod rama;

pub use rama::ProxyRuntime;

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
pub(crate) use rama::set_test_upstream_trust_anchor;

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
    pub result: Result<(), ProxyRuntimeError>,
}

#[cfg(baffle_integration_test)]
pub(super) fn integration_test_upstream_root() -> Result<Option<Vec<u8>>, String> {
    #[cfg(baffle_integration_test)]
    {
        let Some(path) = std::env::var_os("BAFFLE_TEST_UPSTREAM_CA") else {
            return Ok(None);
        };
        let pem = std::fs::read(path)
            .map_err(|error| format!("could not read integration upstream CA: {error}"))?;
        let (remainder, certificate) = x509_parser::pem::parse_x509_pem(&pem)
            .map_err(|_| "could not parse integration upstream CA PEM".to_owned())?;
        if certificate.label != "CERTIFICATE" || !remainder.iter().all(u8::is_ascii_whitespace) {
            return Err("integration upstream CA must contain one certificate".to_owned());
        }
        return Ok(Some(certificate.contents));
    }
    #[cfg(not(baffle_integration_test))]
    Ok(None)
}
