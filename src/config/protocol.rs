use serde::Deserialize;

pub(crate) const MAX_SESSION_CONFIG_COMPONENT_BYTES: usize = 255;

use super::{
    ConfigError, MAX_SESSION_CONFIG_NAME_BYTES, PROTOCOL_VERSION, deserialize,
    session::SessionConfig,
    session_file::{RawSessionConfig, validate_session_config},
};

/// A validated control request. `Create` carries a validated policy, not raw TOML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlRequest {
    Create {
        version: u16,
        session: SessionConfig,
    },
    CreateFromFile {
        version: u16,
        name: String,
    },
    Stop {
        version: u16,
        session_id: String,
    },
    Reload {
        version: u16,
        session_id: String,
    },
    ReloadAll {
        version: u16,
    },
    List {
        version: u16,
    },
}

impl ControlRequest {
    /// Parse and validate one TOML control request.
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let envelope: RawProtocolVersion = deserialize(input)?;
        validate_protocol_version(envelope.version)?;
        let raw: RawControlRequest = deserialize(input)?;
        match raw {
            RawControlRequest::Create { version, session } => Ok(Self::Create {
                version,
                session: validate_session_config(session)?,
            }),
            RawControlRequest::Stop {
                version,
                session_id,
            } => {
                validate_session_id(&session_id)?;
                Ok(Self::Stop {
                    version,
                    session_id,
                })
            }
            RawControlRequest::Reload {
                version,
                session_id,
            } => {
                validate_session_id(&session_id)?;
                Ok(Self::Reload {
                    version,
                    session_id,
                })
            }
            RawControlRequest::ReloadAll { version } => Ok(Self::ReloadAll { version }),
            RawControlRequest::CreateFromFile { version, name } => {
                let name = validate_session_config_name(&name)?;
                Ok(Self::CreateFromFile { version, name })
            }
            RawControlRequest::List { version } => Ok(Self::List { version }),
        }
    }
}

#[derive(Deserialize)]
struct RawProtocolVersion {
    version: u16,
}

fn validate_session_config_name(name: &str) -> Result<String, ConfigError> {
    if name.is_empty()
        || name.len() > MAX_SESSION_CONFIG_NAME_BYTES
        || !name.ends_with(".toml")
        || name.contains('\\')
        || name.contains(':')
        || name.chars().any(char::is_control)
    {
        return Err(ConfigError::new("session configuration name is invalid"));
    }

    for component in name.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.len() > MAX_SESSION_CONFIG_COMPONENT_BYTES
        {
            return Err(ConfigError::new("session configuration name is invalid"));
        }
    }
    Ok(name.to_owned())
}
fn validate_protocol_version(version: u16) -> Result<(), ConfigError> {
    if version != PROTOCOL_VERSION {
        return Err(ConfigError::unsupported_protocol_version());
    }
    Ok(())
}

fn validate_session_id(id: &str) -> Result<(), ConfigError> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ConfigError::new(
            "session_id must be a non-empty opaque identifier",
        ));
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum RawControlRequest {
    Create {
        version: u16,
        session: RawSessionConfig,
    },
    Stop {
        version: u16,
        session_id: String,
    },
    Reload {
        version: u16,
        session_id: String,
    },
    ReloadAll {
        version: u16,
    },
    CreateFromFile {
        version: u16,
        name: String,
    },
    List {
        version: u16,
    },
}
