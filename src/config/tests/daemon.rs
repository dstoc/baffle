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
    assert_eq!(config.daemon.connection_timeout_ms, 5_000);
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
