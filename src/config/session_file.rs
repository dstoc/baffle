use std::collections::BTreeMap;

use serde::Deserialize;

use super::{
    ConfigError,
    policy::{RawNamedRule, validate_named_rules},
    session::{SessionConfig, UnmatchedHostPolicy, validate_socket_name},
};

const SESSION_FILE_VERSION: i64 = 2;

/// Parser for the user-facing session-file format.
///
/// Session files describe policy only. Control operations remain part of the
/// Unix-socket protocol and are not fields in this document.
pub struct SessionFile;

impl SessionFile {
    /// Parse and validate a version 2 session file.
    pub fn from_toml(input: &str) -> Result<SessionConfig, ConfigError> {
        let raw: RawSessionConfig = toml::from_str(input).map_err(|_| {
            ConfigError::new("invalid session configuration TOML syntax or value (values omitted)")
        })?;

        match raw.version {
            Some(SESSION_FILE_VERSION) => {}
            Some(_) => {
                return Err(ConfigError::new(
                    "unsupported session configuration version; expected version = 2",
                ));
            }
            None => {
                return Err(ConfigError::new(
                    "session configuration must declare version = 2",
                ));
            }
        }

        if !raw.unsupported_fields.is_empty() {
            return Err(invalid_session_file());
        }

        let unmatched = match raw.unmatched.as_deref().unwrap_or("deny") {
            "deny" => UnmatchedHostPolicy::Deny,
            "tunnel" => UnmatchedHostPolicy::Tunnel,
            _ => return Err(ConfigError::new("unmatched must be \"deny\" or \"tunnel\"")),
        };
        let rules: BTreeMap<String, RawNamedRule> = match raw.rules {
            Some(RawRules::Named(rules)) => rules,
            Some(RawRules::Other(value)) => {
                let _ = value;
                return Err(invalid_session_file());
            }
            None => BTreeMap::new(),
        };

        let rules = validate_named_rules(rules)?;
        Ok(SessionConfig {
            persistent: raw.persistent,
            socket_name: raw
                .socket_name
                .map(|name| validate_socket_name(&name))
                .transpose()?,
            unmatched,
            rules,
        })
    }
}

fn invalid_session_file() -> ConfigError {
    ConfigError::new("invalid version 2 session configuration field or value (values omitted)")
}

#[derive(Deserialize)]
struct RawSessionConfig {
    #[serde(default)]
    version: Option<i64>,
    #[serde(default)]
    persistent: bool,
    #[serde(default)]
    socket_name: Option<String>,
    #[serde(default)]
    unmatched: Option<String>,
    #[serde(default)]
    rules: Option<RawRules>,
    #[serde(default, flatten)]
    unsupported_fields: BTreeMap<String, toml::Value>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawRules {
    Named(BTreeMap<String, RawNamedRule>),
    Other(toml::Value),
}
