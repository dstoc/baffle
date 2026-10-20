use super::DAEMON_EXAMPLE;
use crate::config::{CaConfig, DaemonConfig, SessionCreateMode};
use std::path::PathBuf;

#[test]
fn parses_the_proposal_daemon_example_and_defaults_daemon_limits() {
    let config = DaemonConfig::from_toml(DAEMON_EXAMPLE)
        .expect("proposal daemon configuration should parse");
    assert_eq!(config.daemon.max_sessions, 64);
    assert_eq!(
        config.ca.certificate,
        PathBuf::from("/var/lib/baffle/ca.pem")
    );
    assert!(config.secrets.allowed.is_empty());

    let config = DaemonConfig::from_toml(
        r#"
[daemon]
control_socket = "/run/baffle/control.sock"
socket_dir = "/run/baffle/proxies"
trusted_operator_uid = 1000

[ca]
certificate = "/var/lib/baffle/ca.pem"
private_key = "/var/lib/baffle/ca-key.pem"

[secrets]
directory = "/var/lib/baffle/secrets"
"#,
    )
    .expect("omitted daemon limits should use defaults");
    assert_eq!(config.daemon.max_sessions, 64);
    assert_eq!(config.daemon.max_connections_per_session, 128);
    assert_eq!(config.daemon.shutdown_grace_seconds, 5);
    assert_eq!(config.daemon.trusted_operator_uid, 1000);
    assert_eq!(config.daemon.control_read_timeout_ms, 5_000);
    assert_eq!(config.daemon.max_provisioning_requests, 8);
    assert_eq!(config.daemon.io_timeout_ms, 30_000);
    assert_eq!(config.daemon.create_mode, SessionCreateMode::Inline);
    assert_eq!(config.daemon.session_config_dir, None);
}

#[test]
fn requires_a_valid_directory_for_file_only_mode() {
    let base = r#"
[daemon]
control_socket = "/run/baffle/control.sock"
socket_dir = "/run/baffle/proxies"
trusted_operator_uid = 1000

[ca]
certificate = "/var/lib/baffle/ca.pem"
private_key = "/var/lib/baffle/ca-key.pem"

[secrets]
directory = "/var/lib/baffle/secrets"
"#;
    assert!(
        DaemonConfig::from_toml(&base.replace("\n[ca]", "\ncreate_mode = \"file_only\"\n\n[ca]"))
            .is_err(),
        "file-only mode must require a session configuration directory"
    );
    assert!(
        DaemonConfig::from_toml(&base.replace(
            "\n[ca]",
            "\nsession_config_dir = \"/var/lib/baffle/sessions\"\n\n[ca]",
        ))
        .is_err(),
        "inline mode must reject an unused session configuration directory"
    );
    let config = DaemonConfig::from_toml(&base.replace(
        "\n[ca]",
        "\ncreate_mode = \"file_only\"\nsession_config_dir = \"/var/lib/baffle/sessions\"\n\n[ca]",
    ))
    .expect("file-only mode with an absolute directory should parse");
    assert_eq!(config.daemon.create_mode, SessionCreateMode::FileOnly);
    assert_eq!(
        config.daemon.session_config_dir,
        Some(PathBuf::from("/var/lib/baffle/sessions"))
    );
    for invalid_path in [
        "relative/sessions",
        "/var/../sessions",
        "/var/./sessions",
        "/",
    ] {
        let input = base.replace(
            "\n[ca]",
            &format!(
                "\ncreate_mode = \"file_only\"\nsession_config_dir = \"{invalid_path}\"\n\n[ca]"
            ),
        );
        assert!(
            DaemonConfig::from_toml(&input).is_err(),
            "invalid session configuration directory {invalid_path:?} must fail"
        );
    }
}

#[test]
fn rejects_unknown_daemon_fields_without_echoing_values() {
    let input = DAEMON_EXAMPLE.replace(
        "max_sessions = 64",
        "max_sessions = 64\nprivate_key_password = \"do-not-leak-this\"",
    );
    let error = DaemonConfig::from_toml(&input).expect_err("unknown field should fail");
    assert!(error.to_string().contains("unsupported field"));
    assert!(!error.to_string().contains("do-not-leak-this"));
}

#[test]
fn rejects_retired_connection_timeout_ms_field() {
    let input = DAEMON_EXAMPLE.replace(
        "max_sessions = 64",
        "max_sessions = 64\nconnection_timeout_ms = 5000",
    );
    let error = DaemonConfig::from_toml(&input)
        .expect_err("retired connection_timeout_ms field should be rejected");
    assert!(error.to_string().contains("unsupported field"));
}

#[test]
fn parses_daemon_secret_entitlements_and_rejects_unsafe_names() {
    let configured = DAEMON_EXAMPLE.replace(
        "directory = \"/var/lib/baffle/secrets\"",
        "directory = \"/var/lib/baffle/secrets\"\nallowed = [\"github-api\", \"github-git\"]",
    );
    let config =
        DaemonConfig::from_toml(&configured).expect("daemon secret entitlements should parse");
    assert!(config.secrets.allowed.contains("github-api"));
    assert!(config.secrets.allowed.contains("github-git"));

    for allowed in [
        "allowed = [\"../credential\"]",
        "allowed = [\"/tmp/credential\"]",
        "allowed = [\"same\", \"same\"]",
    ] {
        let input = DAEMON_EXAMPLE.replace(
            "directory = \"/var/lib/baffle/secrets\"",
            &format!("directory = \"/var/lib/baffle/secrets\"\n{allowed}"),
        );
        let error = DaemonConfig::from_toml(&input)
            .expect_err("unsafe or duplicate entitlements should fail");
        assert!(!error.to_string().contains("credential"));
    }
}

#[test]
fn requires_a_trusted_operator_and_rejects_zero_control_limits() {
    let missing_operator = DAEMON_EXAMPLE.replace("trusted_operator_uid = 1000\n", "");
    assert!(DaemonConfig::from_toml(&missing_operator).is_err());

    for field in [
        "control_read_timeout_ms",
        "max_provisioning_requests",
        "io_timeout_ms",
    ] {
        let input = DAEMON_EXAMPLE.replace(
            "shutdown_grace_seconds = 5",
            &format!("shutdown_grace_seconds = 5\n{field} = 0"),
        );
        assert!(DaemonConfig::from_toml(&input).is_err(), "{field}");
    }
}

#[test]
fn rejects_invalid_daemon_limits() {
    let input = DAEMON_EXAMPLE.replace("max_sessions = 64", "max_sessions = 0");
    assert!(
        DaemonConfig::from_toml(&input)
            .expect_err("zero session limit should fail")
            .to_string()
            .contains("max_sessions")
    );
}

#[test]
fn ca_example_values_remain_path_data() {
    let config = DaemonConfig::from_toml(DAEMON_EXAMPLE).expect("valid daemon config");
    assert_eq!(
        config.ca,
        CaConfig {
            certificate: "/var/lib/baffle/ca.pem".into(),
            private_key: "/var/lib/baffle/ca-key.pem".into(),
        }
    );
}

#[test]
fn daemon_file_paths_resolve_from_the_declaring_directory() {
    let workspace = tempfile::tempdir().expect("temporary directory should be created");
    let config_directory = workspace.path().join("config");
    std::fs::create_dir(&config_directory).expect("config directory should be created");
    let absolute_certificate = workspace.path().join("absolute-ca.pem");
    let config_path = config_directory.join(".").join("daemon.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
[daemon]
control_socket = "run/control.sock"
socket_dir = "run/proxies"
trusted_operator_uid = 1000
create_mode = "file_only"
session_config_dir = "sessions"

[ca]
certificate = {:?}
private_key = "keys/ca-key.pem"

[secrets]
directory = "secrets"
"#,
            absolute_certificate.display().to_string()
        ),
    )
    .expect("daemon config should be written");

    let config = DaemonConfig::load(&config_path).expect("daemon config should load");
    assert_eq!(
        config.daemon.control_socket,
        config_directory.join("run/control.sock")
    );
    assert_eq!(
        config.daemon.socket_dir,
        config_directory.join("run/proxies")
    );
    assert_eq!(
        config.daemon.session_config_dir,
        Some(config_directory.join("sessions"))
    );
    assert_eq!(config.ca.certificate, absolute_certificate);
    assert_eq!(
        config.ca.private_key,
        config_directory.join("keys/ca-key.pem")
    );
    assert_eq!(config.secrets.directory, config_directory.join("secrets"));
}

#[test]
fn relative_file_only_directory_keeps_dot_component_validation() {
    let workspace = tempfile::tempdir().expect("temporary directory should be created");
    let config_directory = workspace.path().join("config");
    std::fs::create_dir(&config_directory).expect("config directory should be created");
    let config_path = config_directory.join("daemon.toml");
    std::fs::write(
        &config_path,
        r#"
[daemon]
control_socket = "run/control.sock"
socket_dir = "run/proxies"
trusted_operator_uid = 1000
create_mode = "file_only"
session_config_dir = "../sessions"

[ca]
certificate = "ca.pem"
private_key = "ca-key.pem"

[secrets]
directory = "secrets"
"#,
    )
    .expect("daemon config should be written");

    let error = DaemonConfig::load(&config_path)
        .expect_err("relative file-only directory must retain dot-component validation");
    assert!(error.to_string().contains("absolute directory path"));
}
