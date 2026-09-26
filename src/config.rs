//! TOML configuration parsing and validation.
//!
//! This module is the stable public facade for daemon settings, session policy,
//! and control-protocol parsing. Parsing validates configuration before runtime
//! operations begin.

use std::{error::Error, fmt};

use serde::de::DeserializeOwned;

mod daemon;
mod policy;
mod protocol;
mod session;
#[cfg(test)]
mod tests;

pub use daemon::{CaConfig, DaemonConfig, DaemonSettings, SecretStoreConfig, SessionCreateMode};
pub(crate) use policy::canonicalize_request_path;
pub use policy::{HeaderInjection, HostRule, InjectionFormat, PathRule, RuleMode, SecretRef};
pub use protocol::ControlRequest;
pub use session::SessionConfig;
pub(crate) const MAX_SESSION_CONFIG_NAME_BYTES: usize = 1_024;
pub const PROTOCOL_VERSION: u16 = 1;

/// A safe configuration error. Error text never contains input values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    message: String,
    kind: ConfigErrorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigErrorKind {
    Invalid,
    UnsupportedProtocolVersion,
}

impl ConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: ConfigErrorKind::Invalid,
        }
    }

    fn unsupported_protocol_version() -> Self {
        Self {
            message: "unsupported control protocol version".into(),
            kind: ConfigErrorKind::UnsupportedProtocolVersion,
        }
    }

    pub(crate) fn is_unsupported_protocol_version(&self) -> bool {
        self.kind == ConfigErrorKind::UnsupportedProtocolVersion
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for ConfigError {}

fn deserialize<T: DeserializeOwned>(input: &str) -> Result<T, ConfigError> {
    toml::from_str(input).map_err(|_| {
        ConfigError::new("invalid TOML syntax, field type, or unsupported field (values omitted)")
    })
}
