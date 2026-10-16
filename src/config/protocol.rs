use serde::Deserialize;

use super::{ConfigError, PROTOCOL_VERSION, SessionConfig, deserialize};

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
            RawControlRequest::Create { version, session } => {
                let session = toml::to_string(&session).map_err(|_| {
                    ConfigError::new(
                        "invalid session configuration TOML syntax or value (values omitted)",
                    )
                })?;
                let session = SessionConfig::from_toml(&session)
                    .map_err(|error| ConfigError::new(error.to_string()))?;
                Ok(Self::Create { version, session })
            }
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
                baffle_client::validate_session_config_name(&name)
                    .map_err(|error| ConfigError::new(error.to_string()))?;
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
    Create { version: u16, session: toml::Value },
    Stop { version: u16, session_id: String },
    Reload { version: u16, session_id: String },
    ReloadAll { version: u16 },
    CreateFromFile { version: u16, name: String },
    List { version: u16 },
}
