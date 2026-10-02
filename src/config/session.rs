use super::{ConfigError, policy::HostRule};

/// Policy for CONNECT destinations that have no explicit host rule.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnmatchedHostPolicy {
    /// Deny destinations without an explicit host rule.
    #[default]
    Deny,
    /// Permit opaque HTTPS tunnels to unmatched DNS hostnames on port 443.
    Tunnel,
}

/// A validated policy for one proxy session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfig {
    pub persistent: bool,
    /// Optional path relative to the daemon's session socket directory.
    pub socket_name: Option<String>,
    /// Action for CONNECT destinations that have no explicit host rule.
    pub unmatched: UnmatchedHostPolicy,
    pub rules: Vec<HostRule>,
}

pub(super) fn validate_socket_name(input: &str) -> Result<String, ConfigError> {
    if input.is_empty() || input.starts_with('/') || input.contains(['\\', '\0']) {
        return Err(ConfigError::new(
            "socket_name must be a relative Unix socket path",
        ));
    }
    let components = input.split('/').collect::<Vec<_>>();
    if components
        .iter()
        .any(|component| component.is_empty() || *component == "." || *component == "..")
    {
        return Err(ConfigError::new(
            "socket_name must not contain empty, dot, or parent components",
        ));
    }
    if input.len() > 107 {
        return Err(ConfigError::new("socket_name is too long"));
    }
    Ok(input.to_owned())
}
