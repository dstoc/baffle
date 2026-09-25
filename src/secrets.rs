//! Daemon-owned secret resolution for authenticated control clients.

use std::{
    collections::{HashMap, HashSet},
    fmt, fs,
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use crate::config::SessionConfig;

const MAX_SECRET_BYTES: u64 = 64 * 1024;

/// Secret material intentionally has a redacted debug representation.
pub(crate) struct SecretValue(String);

impl SecretValue {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

/// Resolved values belong to one session and are not serializable.
#[derive(Default)]
pub(crate) struct ResolvedSecrets(HashMap<String, SecretValue>);

impl ResolvedSecrets {
    pub(crate) fn get(&self, name: &str) -> Option<&SecretValue> {
        self.0.get(name)
    }

    #[cfg(test)]
    pub(crate) fn from_values(values: impl IntoIterator<Item = (String, String)>) -> Self {
        Self(
            values
                .into_iter()
                .map(|(name, value)| (name, SecretValue(value)))
                .collect(),
        )
    }
}

pub(crate) struct SecretStore {
    directory: PathBuf,
    trusted_operator_uid: u32,
    allowed: HashSet<String>,
}

impl SecretStore {
    pub(crate) fn new(
        directory: PathBuf,
        trusted_operator_uid: u32,
        allowed: HashSet<String>,
    ) -> Self {
        Self {
            directory,
            trusted_operator_uid,
            allowed,
        }
    }

    /// Authorize every reference before opening any secret file.
    pub(crate) fn resolve(
        &self,
        client_uid: u32,
        session: &SessionConfig,
    ) -> Result<ResolvedSecrets, SecretStoreError> {
        if client_uid != self.trusted_operator_uid {
            return Err(SecretStoreError::UnauthorizedClient);
        }

        let requested = session
            .rules
            .iter()
            .flat_map(|rule| rule.inject.iter())
            .map(|injection| injection.secret.as_str())
            .collect::<HashSet<_>>();

        if requested.iter().any(|name| !self.allowed.contains(*name)) {
            return Err(SecretStoreError::NotEntitled);
        }
        if requested.is_empty() {
            return Ok(ResolvedSecrets(HashMap::new()));
        }

        validate_private_directory(&self.directory, self.trusted_operator_uid)?;

        let mut resolved = HashMap::with_capacity(requested.len());
        for name in requested {
            let value = read_secret(&self.directory, name, self.trusted_operator_uid)?;
            resolved.insert(name.to_owned(), value);
        }
        Ok(ResolvedSecrets(resolved))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretStoreError {
    UnauthorizedClient,
    NotEntitled,
    Unavailable,
}

fn validate_private_directory(directory: &Path, trusted_uid: u32) -> Result<(), SecretStoreError> {
    let metadata = fs::symlink_metadata(directory).map_err(|_| SecretStoreError::Unavailable)?;
    let mode = metadata.permissions().mode();
    if !metadata.is_dir()
        || metadata.uid() != trusted_uid
        || mode & 0o077 != 0
        || mode & 0o500 != 0o500
        || mode & 0o7000 != 0
    {
        return Err(SecretStoreError::Unavailable);
    }
    Ok(())
}

fn read_secret(
    directory: &Path,
    name: &str,
    trusted_uid: u32,
) -> Result<SecretValue, SecretStoreError> {
    // Names have already passed the symbolic identifier validator, so this
    // join cannot select a path outside the configured directory.
    let path = directory.join(name);
    let metadata = fs::symlink_metadata(&path).map_err(|_| SecretStoreError::Unavailable)?;
    validate_secret_file(&metadata, trusted_uid)?;

    let file = fs::File::open(&path).map_err(|_| SecretStoreError::Unavailable)?;
    let opened = file.metadata().map_err(|_| SecretStoreError::Unavailable)?;
    validate_secret_file(&opened, trusted_uid)?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err(SecretStoreError::Unavailable);
    }

    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take(MAX_SECRET_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SecretStoreError::Unavailable)?;
    if bytes.len() as u64 > MAX_SECRET_BYTES {
        return Err(SecretStoreError::Unavailable);
    }

    // Secret files are often written with one final line ending. Remove only
    // that terminator; embedded control characters remain invalid.
    if bytes.ends_with(b"\r\n") {
        bytes.truncate(bytes.len() - 2);
    } else if bytes.ends_with(b"\n") {
        bytes.truncate(bytes.len() - 1);
    }
    let value = String::from_utf8(bytes).map_err(|_| SecretStoreError::Unavailable)?;
    if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(SecretStoreError::Unavailable);
    }
    Ok(SecretValue(value))
}

fn validate_secret_file(metadata: &fs::Metadata, trusted_uid: u32) -> Result<(), SecretStoreError> {
    let mode = metadata.permissions().mode();
    if !metadata.is_file()
        || metadata.uid() != trusted_uid
        || metadata.len() > MAX_SECRET_BYTES
        || mode & 0o077 != 0
        || mode & 0o400 == 0
        || mode & 0o111 != 0
        || mode & 0o7000 != 0
    {
        return Err(SecretStoreError::Unavailable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::Path,
    };

    use crate::config::ControlRequest;

    use super::{SecretStore, SecretStoreError};

    fn create_request(secret: &str) -> crate::config::SessionConfig {
        let request = ControlRequest::from_toml(&format!(
            "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"{secret}\"\nformat = \"bearer\"\n"
        ))
        .expect("test create request should parse");
        let ControlRequest::Create { session, .. } = request else {
            panic!("expected create request");
        };
        session
    }

    fn store(directory: &Path, allowed: &[&str]) -> SecretStore {
        let uid = fs::metadata(directory)
            .expect("secret directory should have metadata")
            .uid();
        SecretStore::new(
            directory.to_path_buf(),
            uid,
            allowed.iter().map(|name| (*name).to_owned()).collect(),
        )
    }

    fn write_secret(directory: &Path, name: &str, value: &str, mode: u32) {
        let path = directory.join(name);
        fs::write(&path, value).expect("secret should be written");
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .expect("secret permissions should be set");
    }

    #[test]
    fn resolves_only_entitled_secret_files_and_redacts_debug_output() {
        let directory = tempfile::tempdir().expect("secret directory should be created");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("secret directory should be private");
        write_secret(
            directory.path(),
            "api-token",
            "credential-that-must-not-leak\n",
            0o600,
        );
        let store = store(directory.path(), &["api-token"]);

        let secrets = store
            .resolve(store_uid(&store), &create_request("api-token"))
            .expect("entitled secret should resolve");
        let value = secrets
            .get("api-token")
            .expect("resolved value should be retained");
        assert_eq!(value.as_str(), "credential-that-must-not-leak");
        assert_eq!(format!("{value:?}"), "SecretValue([REDACTED])");
        assert!(!format!("{value:?}").contains("credential-that-must-not-leak"));
    }

    #[test]
    fn rejects_missing_inaccessible_and_unentitled_secrets() {
        let directory = tempfile::tempdir().expect("secret directory should be created");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("secret directory should be private");
        let store = store(directory.path(), &["missing", "inaccessible", "private"]);
        let uid = store_uid(&store);

        assert!(matches!(
            store.resolve(uid, &create_request("missing")),
            Err(SecretStoreError::Unavailable)
        ));

        write_secret(directory.path(), "inaccessible", "credential", 0o644);
        assert!(matches!(
            store.resolve(uid, &create_request("inaccessible")),
            Err(SecretStoreError::Unavailable)
        ));

        assert!(matches!(
            store.resolve(uid, &create_request("not-allowed")),
            Err(SecretStoreError::NotEntitled)
        ));
    }

    #[test]
    fn rejects_symlinked_secret_files_and_untrusted_client_uids() {
        let directory = tempfile::tempdir().expect("secret directory should be created");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("secret directory should be private");
        write_secret(directory.path(), "outside", "credential", 0o600);
        std::os::unix::fs::symlink(
            directory.path().join("outside"),
            directory.path().join("token"),
        )
        .expect("secret symlink should be created");
        let store = store(directory.path(), &["token"]);
        let uid = store_uid(&store);

        assert!(matches!(
            store.resolve(uid, &create_request("token")),
            Err(SecretStoreError::Unavailable)
        ));
        assert!(matches!(
            store.resolve(uid.wrapping_add(1), &create_request("token")),
            Err(SecretStoreError::UnauthorizedClient)
        ));
    }

    fn store_uid(store: &SecretStore) -> u32 {
        fs::metadata(&store.directory)
            .expect("secret directory should have metadata")
            .uid()
    }
}
