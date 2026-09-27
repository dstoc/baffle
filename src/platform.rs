use std::path::{Path, PathBuf};

/// Resolve only macOS's standard system-directory aliases before secure
/// no-follow walks. Other symlink components remain visible and are rejected.
pub(crate) fn normalize_system_path(path: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        for alias in ["/var", "/tmp", "/etc"] {
            let alias_path = Path::new(alias);
            let Ok(suffix) = path.strip_prefix(alias_path) else {
                continue;
            };
            if let Ok(real_path) = std::fs::canonicalize(alias_path) {
                return real_path.join(suffix);
            }
        }
    }
    path.to_path_buf()
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::normalize_system_path;
    use std::path::Path;

    #[test]
    fn resolves_the_system_var_alias_without_following_nested_symlinks() {
        let expected_root = Path::new("/var")
            .canonicalize()
            .expect("macOS /var alias should resolve");
        assert_eq!(
            normalize_system_path(Path::new("/var/folders/test/socket.sock")),
            expected_root.join("folders/test/socket.sock")
        );
        assert_eq!(
            normalize_system_path(Path::new("/var/folders/test/link/socket.sock")),
            expected_root.join("folders/test/link/socket.sock")
        );
    }
}
