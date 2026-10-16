use super::{ConfigError, SessionConfig};

/// Parser for the user-facing session-file format.
///
/// Session files describe policy only. Control operations remain part of the
/// Unix-socket protocol and are not fields in this document.
pub struct SessionFile;

impl SessionFile {
    /// Parse and validate a version 2 session file.
    pub fn from_toml(input: &str) -> Result<SessionConfig, ConfigError> {
        SessionConfig::from_toml(input).map_err(|error| ConfigError::new(error.to_string()))
    }
}
