use std::path::{Path, PathBuf};

/// Resolve only supported system-directory aliases before secure no-follow
/// walks. Other symlink components remain visible and are rejected.
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
    #[cfg(target_os = "linux")]
    {
        let alias = Path::new("/var/run");
        if let Ok(suffix) = path.strip_prefix(alias)
            && std::fs::symlink_metadata(alias)
                .is_ok_and(|metadata| metadata.file_type().is_symlink())
            && std::fs::read_link(alias).is_ok_and(|target| target == Path::new("/run"))
        {
            return Path::new("/run").join(suffix);
        }
    }
    path.to_path_buf()
}

/// Open a directory for traversal and metadata access without requiring read
/// permission on its entries.
pub(crate) const fn directory_open_flags() -> libc::c_int {
    #[cfg(target_os = "linux")]
    {
        libc::O_PATH
    }
    #[cfg(target_os = "macos")]
    {
        libc::O_SEARCH
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        libc::O_RDONLY
    }
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

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::normalize_system_path;
    use std::path::Path;

    #[test]
    fn resolves_only_the_conventional_var_run_alias() {
        let path = Path::new("/var/run/baffle/proxies/socket.sock");
        let is_conventional_alias = std::fs::symlink_metadata("/var/run")
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
            && std::fs::read_link("/var/run").is_ok_and(|target| target == Path::new("/run"));

        if is_conventional_alias {
            assert_eq!(
                normalize_system_path(path),
                Path::new("/run/baffle/proxies/socket.sock")
            );
        } else {
            assert_eq!(normalize_system_path(path), path);
        }
        assert_eq!(
            normalize_system_path(Path::new("/var/runtime/baffle")),
            Path::new("/var/runtime/baffle")
        );
    }
}
