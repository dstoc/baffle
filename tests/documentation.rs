use std::path::PathBuf;

use baffle_proxy::config::{ControlRequest, DaemonConfig, InjectionFormat, RuleMode};

#[test]
fn daemon_configuration_example_parses_and_defaults_match_the_reference() {
    let example = DaemonConfig::from_toml(include_str!("../examples/daemon.toml"))
        .expect("daemon example should parse");
    assert_eq!(example.daemon.max_sessions, 64);
    assert_eq!(example.daemon.max_connections_per_session, 128);
    assert_eq!(example.daemon.shutdown_grace_seconds, 5);
    assert_eq!(example.daemon.control_read_timeout_ms, 5_000);
    assert_eq!(example.daemon.max_provisioning_requests, 8);
    assert_eq!(example.daemon.connection_timeout_ms, 5_000);
    assert_eq!(example.daemon.io_timeout_ms, 30_000);

    let minimal = DaemonConfig::from_toml(
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
    .expect("minimum required daemon configuration should parse");
    assert_eq!(minimal.daemon.max_sessions, 64);
    assert_eq!(minimal.daemon.max_connections_per_session, 128);
    assert_eq!(minimal.daemon.shutdown_grace_seconds, 5);
    assert_eq!(minimal.daemon.control_read_timeout_ms, 5_000);
    assert_eq!(minimal.daemon.max_provisioning_requests, 8);
    assert_eq!(minimal.daemon.connection_timeout_ms, 5_000);
    assert_eq!(minimal.daemon.io_timeout_ms, 30_000);
    assert!(minimal.secrets.allowed.is_empty());
    assert_eq!(
        minimal.ca.certificate,
        PathBuf::from("/var/lib/baffle/ca.pem")
    );
}

#[test]
fn session_configuration_examples_parse() {
    let ControlRequest::Create { session, .. } =
        ControlRequest::from_toml(include_str!("../examples/session.toml"))
            .expect("session example should parse")
    else {
        panic!("session example should create a session");
    };
    assert!(!session.persistent);
    assert_eq!(session.rules.len(), 1);
    assert_eq!(session.rules[0].host, "example.com");
    assert_eq!(session.rules[0].mode, RuleMode::Tunnel);
    assert_eq!(session.rules[0].ports, [443]);

    let ControlRequest::Create { session, .. } =
        ControlRequest::from_toml(include_str!("../examples/session-credentials.toml"))
            .expect("credential example should parse")
    else {
        panic!("credential example should create a session");
    };
    let injection = &session.rules[0].inject[0];
    assert_eq!(session.rules[0].mode, RuleMode::Intercept);
    assert_eq!(session.rules[0].paths[0].as_str(), "/v1/**");
    assert_eq!(injection.header, "Authorization");
    assert_eq!(injection.secret.as_str(), "example-api");
    assert_eq!(injection.format, InjectionFormat::Bearer);
}

#[test]
fn protocol_operation_examples_parse() {
    assert!(matches!(
        ControlRequest::from_toml(include_str!("../examples/protocol/list.toml")),
        Ok(ControlRequest::List { version: 1 })
    ));
    assert!(matches!(
        ControlRequest::from_toml(include_str!("../examples/protocol/stop.toml")),
        Ok(ControlRequest::Stop { version: 1, .. })
    ));
}
