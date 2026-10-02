use std::collections::BTreeMap;

use serde::Deserialize;

use super::{
    ConfigError,
    policy::{RawNamedRule, validate_named_rules},
    session::{SessionConfig, validate_socket_name},
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
        let value = toml::from_str::<toml::Value>(input).map_err(|_| {
            ConfigError::new("invalid session configuration TOML syntax or value (values omitted)")
        })?;
        let Some(root) = value.as_table() else {
            return Err(ConfigError::new(
                "session configuration must be a TOML document with version = 2",
            ));
        };

        match root.get("version").and_then(toml::Value::as_integer) {
            Some(1) => {
                return Err(ConfigError::new(
                    "session configuration version 1 is unsupported; migrate to version 2 by removing operation, moving session settings to the root, and changing [[rules]] host entries to [rules.\"hostname\"]",
                ));
            }
            Some(SESSION_FILE_VERSION) => {}
            Some(_) => {
                return Err(ConfigError::new(
                    "unsupported session configuration version; expected version = 2",
                ));
            }
            None if root.contains_key("version") => {
                return Err(ConfigError::new(
                    "session configuration version must be the integer 2",
                ));
            }
            None => {
                return Err(ConfigError::new(
                    "session configuration must declare version = 2; version 1 session files must be migrated",
                ));
            }
        }

        if root.contains_key("operation") {
            return Err(ConfigError::new(
                "operation is a control-protocol field and is not valid in a session file; remove it from the version 2 document",
            ));
        }
        if root.contains_key("session") {
            return Err(ConfigError::new(
                "the [session] table is not valid in a version 2 session file; move persistent and socket_name to the document root",
            ));
        }
        if root.get("rules").is_some_and(toml::Value::is_array) {
            return Err(ConfigError::new(
                "[[rules]] entries are not valid in a version 2 session file; use quoted hostname tables such as [rules.\"example.com\"]",
            ));
        }

        let raw: RawSessionConfig = toml::from_str(input).map_err(|_| {
            ConfigError::new(
                "invalid version 2 session configuration field or value (values omitted)",
            )
        })?;
        if raw.version != SESSION_FILE_VERSION as u16 {
            return Err(ConfigError::new(
                "unsupported session configuration version; expected version = 2",
            ));
        }
        let rules = validate_named_rules(raw.rules)?;
        Ok(SessionConfig {
            persistent: raw.persistent,
            socket_name: raw
                .socket_name
                .map(|name| validate_socket_name(&name))
                .transpose()?,
            rules,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSessionConfig {
    version: u16,
    #[serde(default)]
    persistent: bool,
    #[serde(default)]
    socket_name: Option<String>,
    #[serde(default)]
    rules: BTreeMap<String, RawNamedRule>,
}
