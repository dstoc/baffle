use crate::{
    config::{CredentialMode, SessionFile, UnmatchedHostPolicy},
    control::file_config::{SessionConfigFileErrorKind, SessionConfigStore},
};
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

#[test]
fn composes_nested_imports_relative_to_each_declaring_file() {
    let (directory, store) = session_store();
    write_session_file(
        &directory,
        "shared/common.toml",
        "version = 2\nunmatched = \"tunnel\"\n\n[rules.\"common.example\"]\n",
    );
    write_session_file(
        &directory,
        "nested/deep/policy.toml",
        "version = 2\nimports = [\"../../shared/common.toml\"]\n\n[rules.\"nested.example\"]\n",
    );
    write_session_file(
        &directory,
        "app.toml",
        "version = 2\npersistent = true\nsocket_name = \"apps/imported.sock\"\nunmatched = \"tunnel\"\nimports = [\"nested/deep/policy.toml\", \"shared/common.toml\"]\n\n[rules.\"root.example\"]\n",
    );

    let session = store
        .read_session("app.toml")
        .expect("nested imports should compose");
    assert!(session.persistent);
    assert_eq!(session.socket_name.as_deref(), Some("apps/imported.sock"));
    assert_eq!(session.unmatched, UnmatchedHostPolicy::Tunnel);
    assert_eq!(
        session
            .rules
            .iter()
            .map(|rule| rule.host.as_str())
            .collect::<Vec<_>>(),
        ["common.example", "nested.example", "root.example"]
    );
}

#[test]
fn composes_credential_modes_and_rejects_imported_default_broadening() {
    let (directory, store) = session_store();
    write_session_file(
        &directory,
        "shared/credentials.toml",
        "version = 2\n\n[credentials.overrides.github-api]\nmode = \"disabled\"\n",
    );
    write_session_file(
        &directory,
        "root.toml",
        "version = 2\nimports = [\"shared/credentials.toml\"]\n\n[credentials]\ndefault_mode = \"substitute\"\n",
    );
    let session = store
        .read_session("root.toml")
        .expect("credential defaults and unique imported overrides should compose");
    assert_eq!(
        session.default_credential_mode,
        Some(CredentialMode::Substitute)
    );
    assert_eq!(
        session.effective_credential_mode("github-api"),
        CredentialMode::Disabled
    );

    write_session_file(
        &directory,
        "broadening.toml",
        "version = 2\nimports = [\"shared/default.toml\"]\n",
    );
    write_session_file(
        &directory,
        "shared/default.toml",
        "version = 2\n\n[credentials]\ndefault_mode = \"substitute\"\n",
    );
    let error = store
        .read_session("broadening.toml")
        .expect_err("an imported default must not change the root's inject fallback");
    assert!(error.detail.contains("effective value `inject`"));
}

#[test]
fn counts_root_and_imported_files_toward_the_unique_file_limit() {
    let (directory, store) = session_store();

    let imports = (0..127)
        .map(|index| format!("\"accepted-{index}.toml\""))
        .collect::<Vec<_>>()
        .join(", ");
    write_session_file(
        &directory,
        "accepted.toml",
        &format!("version = 2\nimports = [{imports}]\n"),
    );
    for index in 0..127 {
        write_session_file(
            &directory,
            &format!("accepted-{index}.toml"),
            "version = 2\n",
        );
    }
    store
        .read_session("accepted.toml")
        .expect("the root and 127 imports should fit the 128-file limit");

    let imports = (0..128)
        .map(|index| format!("\"rejected-{index}.toml\""))
        .collect::<Vec<_>>()
        .join(", ");
    write_session_file(
        &directory,
        "rejected.toml",
        &format!("version = 2\nimports = [{imports}]\n"),
    );
    for index in 0..128 {
        write_session_file(
            &directory,
            &format!("rejected-{index}.toml"),
            "version = 2\n",
        );
    }
    let too_many = store
        .read_session("rejected.toml")
        .expect_err("the root and 128 imports must exceed the 128-file limit");
    assert!(too_many.detail.contains("exceed 128 unique files"));
}

#[test]
fn counts_active_ancestors_toward_the_unique_file_limit() {
    let (directory, store) = session_store();
    let imports = (0..127)
        .map(|index| format!("\"leaf-{index}.toml\""))
        .collect::<Vec<_>>()
        .join(", ");
    write_session_file(
        &directory,
        "root.toml",
        "version = 2\nimports = [\"nested/branch.toml\"]\n",
    );
    write_session_file(
        &directory,
        "nested/branch.toml",
        &format!("version = 2\nimports = [{imports}]\n"),
    );
    for index in 0..127 {
        write_session_file(
            &directory,
            &format!("nested/leaf-{index}.toml"),
            "version = 2\n",
        );
    }

    let too_many = store
        .read_session("root.toml")
        .expect_err("the nested graph has 129 unique files");
    assert!(too_many.detail.contains("exceed 128 unique files"));
}

#[test]
fn rejects_conflicting_rules_unmatched_settings_and_imported_lifecycle_fields() {
    let (directory, store) = session_store();
    write_session_file(
        &directory,
        "common.toml",
        "version = 2\nunmatched = \"deny\"\n\n[rules.\"HOST.example.\"]\n",
    );
    write_session_file(
        &directory,
        "duplicate.toml",
        "version = 2\nimports = [\"common.toml\"]\n\n[rules.\"host.example\"]\n",
    );
    let duplicate = store
        .read_session("duplicate.toml")
        .expect_err("normalized duplicate rules must fail");
    assert_eq!(duplicate.kind, SessionConfigFileErrorKind::Invalid);
    assert!(duplicate.detail.contains("defined more than once"));

    write_session_file(
        &directory,
        "conflict.toml",
        "version = 2\nunmatched = \"tunnel\"\nimports = [\"common.toml\"]\n",
    );
    let conflict = store
        .read_session("conflict.toml")
        .expect_err("conflicting explicit scalar settings must fail");
    assert!(
        conflict
            .detail
            .contains("conflict with the root file's effective value")
    );

    write_session_file(
        &directory,
        "tunnel.toml",
        "version = 2\nunmatched = \"tunnel\"\n",
    );
    write_session_file(
        &directory,
        "implicit-broadening.toml",
        "version = 2\nimports = [\"tunnel.toml\"]\n",
    );
    let implicit_broadening = store
        .read_session("implicit-broadening.toml")
        .expect_err("the root default deny must constrain imported settings");
    assert!(
        implicit_broadening
            .detail
            .contains("root file's effective value `deny`")
    );

    write_session_file(
        &directory,
        "lifecycle.toml",
        "version = 2\npersistent = false\n",
    );
    write_session_file(
        &directory,
        "imports-lifecycle.toml",
        "version = 2\nimports = [\"lifecycle.toml\"]\n",
    );
    let lifecycle = store
        .read_session("imports-lifecycle.toml")
        .expect_err("imported lifecycle settings must fail");
    assert!(lifecycle.detail.contains("cannot set `persistent`"));
}

#[test]
fn rejects_import_cycles_missing_files_and_paths_outside_the_config_root() {
    let (directory, store) = session_store();
    write_session_file(
        &directory,
        "cycle-a.toml",
        "version = 2\nimports = [\"cycle-b.toml\"]\n",
    );
    write_session_file(
        &directory,
        "cycle-b.toml",
        "version = 2\nimports = [\"cycle-a.toml\"]\n",
    );
    let cycle = store
        .read_session("cycle-a.toml")
        .expect_err("import cycles must fail");
    assert!(cycle.detail.contains("import cycle"));

    write_session_file(
        &directory,
        "missing.toml",
        "version = 2\nimports = [\"absent.toml\"]\n",
    );
    let missing = store
        .read_session("missing.toml")
        .expect_err("missing imports must fail");
    assert_eq!(missing.kind, SessionConfigFileErrorKind::NotFound);
    assert!(missing.detail.contains("absent.toml"));

    write_session_file(
        &directory,
        "bad-policy.toml",
        "version = 2\n\n[rules.\"invalid.example\"]\nmode = \"unsupported\"\n",
    );
    write_session_file(
        &directory,
        "invalid-import.toml",
        "version = 2\nimports = [\"bad-policy.toml\"]\n",
    );
    let invalid = store
        .read_session("invalid-import.toml")
        .expect_err("invalid imported policy must fail");
    assert_eq!(invalid.kind, SessionConfigFileErrorKind::Invalid);
    assert!(invalid.detail.contains("bad-policy.toml"));

    write_session_file(
        &directory,
        "nested/escape.toml",
        "version = 2\nimports = [\"../../outside.toml\"]\n",
    );
    let escape = store
        .read_session("nested/escape.toml")
        .expect_err("imports must not escape the configured root");
    assert_eq!(escape.kind, SessionConfigFileErrorKind::Invalid);
    assert!(
        escape
            .detail
            .contains("within the session configuration directory")
    );

    write_session_file(
        &directory,
        "absolute.toml",
        "version = 2\nimports = [\"/etc/passwd\"]\n",
    );
    let absolute = store
        .read_session("absolute.toml")
        .expect_err("absolute import paths must fail");
    assert_eq!(absolute.kind, SessionConfigFileErrorKind::Invalid);
    assert!(absolute.detail.contains("relative TOML file paths"));
}

#[test]
fn imports_keep_file_only_permission_and_symlink_checks_and_are_not_inline_config() {
    use std::os::unix::fs::symlink;

    let (directory, store) = session_store();
    let outside = directory.path().join("outside.toml");
    fs::write(&outside, "version = 2\n").expect("outside file should be written");
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o600))
        .expect("outside file should be private");
    let root = directory.path().join("sessions");
    symlink(&outside, root.join("linked.toml")).expect("import symlink should be created");
    write_session_file(
        &directory,
        "linked-import.toml",
        "version = 2\nimports = [\"linked.toml\"]\n",
    );
    let linked = store
        .read_session("linked-import.toml")
        .expect_err("import symlinks must be rejected");
    assert_eq!(linked.kind, SessionConfigFileErrorKind::Unavailable);

    write_session_file(&directory, "unreadable.toml", "version = 2\n");
    fs::set_permissions(
        root.join("unreadable.toml"),
        fs::Permissions::from_mode(0o000),
    )
    .expect("import should be unreadable to the daemon identity");
    write_session_file(
        &directory,
        "unreadable-import.toml",
        "version = 2\nimports = [\"unreadable.toml\"]\n",
    );
    let unreadable = store
        .read_session("unreadable-import.toml")
        .expect_err("unreadable imports must be rejected");
    assert_eq!(unreadable.kind, SessionConfigFileErrorKind::Unavailable);

    write_session_file(
        &directory,
        "inline.toml",
        "version = 2\nimports = [\"linked.toml\"]\n",
    );
    let inline = SessionFile::from_toml(
        &fs::read_to_string(root.join("inline.toml")).expect("inline fixture should be read"),
    );
    assert!(inline.is_err(), "local inline parsing must reject imports");
}

#[test]
fn loads_the_documented_nested_import_example() {
    let (directory, store) = session_store();
    write_session_file(
        &directory,
        "cladding.toml",
        include_str!("../../../examples/session-imports/cladding.toml"),
    );
    write_session_file(
        &directory,
        "shared/github.toml",
        include_str!("../../../examples/session-imports/shared/github.toml"),
    );
    write_session_file(
        &directory,
        "shared/nested/api.toml",
        include_str!("../../../examples/session-imports/shared/nested/api.toml"),
    );

    let session = store
        .read_session("cladding.toml")
        .expect("documented nested import example should compose");
    assert_eq!(
        session
            .rules
            .iter()
            .map(|rule| rule.host.as_str())
            .collect::<Vec<_>>(),
        ["github.com", "api.github.com", "cladding.example.com"]
    );
}

fn session_store() -> (tempfile::TempDir, SessionConfigStore) {
    let directory = tempfile::tempdir().expect("temporary root should be created");
    let config_directory = directory.path().join("sessions");
    fs::create_dir(&config_directory).expect("session configuration root should be created");
    fs::set_permissions(&config_directory, fs::Permissions::from_mode(0o700))
        .expect("session configuration root should be private");
    let trusted_uid = fs::metadata(directory.path())
        .expect("temporary root should have metadata")
        .uid();
    let store = SessionConfigStore::open(&config_directory, trusted_uid)
        .expect("session configuration store should open");
    (directory, store)
}

fn write_session_file(directory: &tempfile::TempDir, name: &str, contents: &str) {
    let path = directory.path().join("sessions").join(name);
    fs::create_dir_all(path.parent().expect("session file should have a parent"))
        .expect("session file parent should be created");
    fs::write(&path, contents).expect("session file should be written");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("session file should be private");
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
