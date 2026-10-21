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
mod session_file;
#[cfg(test)]
mod tests;

pub use baffle_client::PROTOCOL_VERSION;
pub use baffle_client::{
    CredentialMode, HeaderInjection, HostRule, InjectionFormat, RuleMode, SessionConfig,
    UnmatchedHostPolicy,
};
pub use baffle_client::{MAX_SESSION_CONFIG_COMPONENT_BYTES, MAX_SESSION_CONFIG_NAME_BYTES};
pub use daemon::{CaConfig, DaemonConfig, DaemonSettings, SecretStoreConfig, SessionCreateMode};
pub(crate) use policy::canonicalize_request_path;
pub use protocol::ControlRequest;
pub use session_file::SessionFile;

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
            message: format!(
                "unsupported control protocol version; expected version = {}",
                baffle_client::PROTOCOL_VERSION
            ),
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
