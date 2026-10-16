use crate::control::file_config::SessionConfigStore;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
};

#[test]
fn opens_session_config_directory_through_search_only_ancestor() {
    let directory = tempfile::tempdir().expect("temporary root should be created");
    let ancestor = directory.path().join("search-only");
    let config_directory = ancestor.join("sessions");
    fs::create_dir(&ancestor).expect("search-only ancestor should be created");
    fs::create_dir(&config_directory).expect("session directory should be created");
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o111))
        .expect("ancestor should be searchable but not readable");
    fs::set_permissions(&config_directory, fs::Permissions::from_mode(0o700))
        .expect("session directory should be private");
    let trusted_uid = fs::metadata(directory.path())
        .expect("temporary root should have metadata")
        .uid();

    SessionConfigStore::open(&config_directory, trusted_uid)
        .expect("search-only ancestor should not require read permission");
}

#[cfg(target_os = "linux")]
#[test]
fn opens_session_config_directory_through_var_run_alias() {
    let is_conventional_alias = fs::symlink_metadata("/var/run")
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
        && fs::read_link("/var/run").is_ok_and(|target| target == std::path::Path::new("/run"));
    if !is_conventional_alias {
        return;
    }

    let run_metadata = fs::metadata("/run").expect("run directory should have metadata");
    if run_metadata.permissions().mode() & 0o022 != 0 {
        // A writable /run does not satisfy the existing config-root policy.
        return;
    }
    let trusted_uid = run_metadata.uid();
    SessionConfigStore::open(std::path::Path::new("/var/run"), trusted_uid)
        .expect("session config should open through the supported Linux alias");
}

#[cfg(target_os = "macos")]
#[test]
fn opens_session_config_directory_through_var_alias() {
    use std::path::Path;

    let directory = tempfile::tempdir_in("/private/var/tmp")
        .expect("temporary session directory should be created");
    let canonical =
        fs::canonicalize(directory.path()).expect("temporary session directory should resolve");
    let suffix = canonical
        .strip_prefix(Path::new("/private/var"))
        .expect("temporary session directory should be under /private/var");
    let alias = Path::new("/var").join(suffix);
    let trusted_uid = fs::metadata(&alias)
        .expect("session directory should have metadata")
        .uid();

    SessionConfigStore::open(&alias, trusted_uid)
        .expect("session directory under the /var alias should open securely");
}
