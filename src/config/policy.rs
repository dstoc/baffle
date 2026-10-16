use std::collections::HashSet;

use super::ConfigError;

pub(crate) use baffle_client::canonicalize_request_path;

pub(super) fn validate_allowed_secrets(raw: Vec<String>) -> Result<HashSet<String>, ConfigError> {
    let mut allowed = HashSet::with_capacity(raw.len());
    for secret in raw {
        baffle_client::validate_secret_name(&secret).map_err(|_| {
            ConfigError::new("secrets.allowed must contain valid secret identifiers")
        })?;
        if !allowed.insert(secret) {
            return Err(ConfigError::new(
                "secrets.allowed must not contain duplicate secret identifiers",
            ));
        }
    }
    Ok(allowed)
}
