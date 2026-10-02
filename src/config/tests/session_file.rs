use crate::config::{RuleMode, SessionFile, UnmatchedHostPolicy};

const MINIMAL: &str = "version = 2\n\n[rules.\"example.com\"]\n";

#[test]
fn parses_root_settings_quoted_hosts_and_session_defaults() {
    let session = SessionFile::from_toml(
        "version = 2\npersistent = true\nsocket_name = \"apps/api.sock\"\n\n[rules.\"Example.COM.\"]\n",
    )
    .expect("version 2 session file should parse");

    assert!(session.persistent);
    assert_eq!(session.socket_name.as_deref(), Some("apps/api.sock"));
    assert_eq!(session.rules.len(), 1);
    assert_eq!(session.rules[0].host, "example.com");
    assert_eq!(session.rules[0].mode, RuleMode::Tunnel);
    assert_eq!(session.rules[0].ports, [443]);

    let minimal = SessionFile::from_toml(MINIMAL).expect("minimal v2 file should parse");
    assert!(!minimal.persistent);
    assert_eq!(minimal.socket_name, None);
    assert_eq!(minimal.unmatched, UnmatchedHostPolicy::Deny);
    assert_eq!(minimal.rules[0].mode, RuleMode::Tunnel);
}

#[test]
fn parses_unmatched_policy_and_allows_empty_rule_sets() {
    let explicit_deny = SessionFile::from_toml("version = 2\nunmatched = \"deny\"\n")
        .expect("an empty deny-all session should parse");
    assert!(explicit_deny.rules.is_empty());
    assert_eq!(explicit_deny.unmatched, UnmatchedHostPolicy::Deny);

    let tunnel = SessionFile::from_toml("version = 2\nunmatched = \"tunnel\"\n")
        .expect("an empty unmatched-tunnel session should parse");
    assert!(tunnel.rules.is_empty());
    assert_eq!(tunnel.unmatched, UnmatchedHostPolicy::Tunnel);

    let invalid = SessionFile::from_toml("version = 2\nunmatched = \"intercept\"\n")
        .expect_err("unsupported unmatched policies must fail");
    assert_eq!(
        invalid.to_string(),
        "unmatched must be \"deny\" or \"tunnel\""
    );
}

#[test]
fn infers_interception_for_paths_and_credentials_and_accepts_explicit_intercept() {
    let session = SessionFile::from_toml(
        r#"
version = 2

[rules."api.example.com"]
paths = ["/v1/**"]

[[rules."api.example.com".inject]]
header = "Authorization"
secret = "api-token"
format = "bearer"

[rules."login.example.com"]
mode = "intercept"
"#,
    )
    .expect("paths and credentials should infer interception");

    let api = session
        .rules
        .iter()
        .find(|rule| rule.host == "api.example.com")
        .expect("API rule should exist");
    assert_eq!(api.mode, RuleMode::Intercept);
    assert_eq!(api.paths[0].as_str(), "/v1/**");
    assert_eq!(api.inject[0].secret.as_str(), "api-token");
    assert_eq!(api.ports, [443]);

    let login = session
        .rules
        .iter()
        .find(|rule| rule.host == "login.example.com")
        .expect("login rule should exist");
    assert_eq!(login.mode, RuleMode::Intercept);
    assert!(login.paths.is_empty());
}

#[test]
fn an_explicit_empty_interception_field_does_not_select_opaque_tunneling() {
    for field in ["paths = []", "inject = []"] {
        let input = format!("version = 2\n\n[rules.\"example.com\"]\n{field}\n");
        let session = SessionFile::from_toml(&input)
            .expect("an explicitly declared interception field should parse");
        assert_eq!(session.rules[0].mode, RuleMode::Intercept);
    }

    let error = SessionFile::from_toml(
        "version = 2\n\n[rules.\"example.com\"]\nmode = \"tunnel\"\npaths = []\n",
    )
    .expect_err("explicit tunnel mode must reject a paths field");
    assert!(error.to_string().contains("cannot use paths or inject"));
}

#[test]
fn rejects_tunnel_mode_with_paths_or_injection() {
    let cases = [
        r#"version = 2
[rules."example.com"]
mode = "tunnel"
paths = ["/private"]
"#,
        r#"version = 2
[rules."example.com"]
mode = "tunnel"
[[rules."example.com".inject]]
header = "Authorization"
secret = "api-token"
format = "bearer"
"#,
    ];

    for input in cases {
        let error = SessionFile::from_toml(input).expect_err("unsafe tunnel policy must fail");
        assert!(
            error
                .to_string()
                .contains("tunnel rules cannot use paths or inject")
        );
    }
}

#[test]
fn rejects_hostname_collisions_and_unsupported_host_forms() {
    let duplicate = r#"
version = 2
[rules."EXAMPLE.com"]
[rules."example.com."]
"#;
    let error = SessionFile::from_toml(duplicate).expect_err("normalized duplicate must fail");
    assert!(error.to_string().contains("duplicates another rule"));

    for host in ["*.example.com", "127.0.0.1", "127.1", "2130706433"] {
        let input = format!("version = 2\n\n[rules.{host:?}]\n");
        assert!(
            SessionFile::from_toml(&input).is_err(),
            "unsupported host form should fail: {host}"
        );
    }

    let unquoted = SessionFile::from_toml("version = 2\n\n[rules.internal.example]\n")
        .expect_err("a dotted hostname key must be quoted");
    assert!(unquoted.to_string().contains("invalid version 2 session"));
}

#[test]
fn validates_nested_socket_names_paths_and_injection_fields() {
    let valid = r#"
version = 2
socket_name = "apps/api.sock"

[rules."api.example.com"]
paths = ["/v1/**"]

[[rules."api.example.com".inject]]
header = "Authorization"
secret = "api-token"
format = "bearer"
"#;
    let session = SessionFile::from_toml(valid).expect("valid nested config should parse");
    assert_eq!(session.socket_name.as_deref(), Some("apps/api.sock"));
    assert_eq!(session.rules[0].mode, RuleMode::Intercept);

    for socket_name in [
        "",
        "/absolute.sock",
        "./socket.sock",
        "apps/../socket.sock",
        "apps//socket.sock",
        "apps\\socket.sock",
    ] {
        let input =
            format!("version = 2\nsocket_name = {socket_name:?}\n\n[rules.\"example.com\"]\n");
        assert!(
            SessionFile::from_toml(&input).is_err(),
            "unsafe socket name should fail: {socket_name:?}"
        );
    }

    let invalid_path = "version = 2\n\n[rules.\"example.com\"]\npaths = [\"/private?token=1\"]\n";
    assert!(SessionFile::from_toml(invalid_path).is_err());
    let invalid_secret = "version = 2\n\n[rules.\"example.com\"]\n[[rules.\"example.com\".inject]]\nheader = \"Authorization\"\nsecret = \"../private\"\nformat = \"bearer\"\n";
    assert!(SessionFile::from_toml(invalid_secret).is_err());
}

#[test]
fn rejects_v1_and_protocol_shaped_session_files_with_migration_hints() {
    let v1 = SessionFile::from_toml(
        "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"tunnel\"\n",
    )
    .expect_err("v1 session file must be rejected");
    assert!(v1.to_string().contains("version 1 is unsupported"));
    assert!(v1.to_string().contains("migrate to version 2"));

    let operation = SessionFile::from_toml("version = 2\noperation = \"create\"\n")
        .expect_err("operation is not part of a session file");
    assert!(operation.to_string().contains("control-protocol field"));

    let session_table = SessionFile::from_toml("version = 2\n\n[session]\npersistent = true\n")
        .expect_err("the old session table must be rejected");
    assert!(
        session_table
            .to_string()
            .contains("move persistent, socket_name, and unmatched")
    );

    let old_rules = SessionFile::from_toml(
        "version = 2\n\n[[rules]]\nhost = \"example.com\"\nmode = \"tunnel\"\n",
    )
    .expect_err("array rules must be rejected");
    assert!(old_rules.to_string().contains("quoted hostname tables"));

    let missing_version = SessionFile::from_toml("[rules.\"example.com\"]\n")
        .expect_err("schema version is required");
    assert!(missing_version.to_string().contains("version = 2"));
}

#[test]
fn rejects_malformed_or_empty_v2_documents_without_echoing_values() {
    assert!(
        SessionFile::from_toml("version = 2\nunknown_secret = \"private-value\"\n")
            .expect_err("unknown field must fail")
            .to_string()
            .contains("values omitted")
    );

    let malformed = SessionFile::from_toml("version = 2\n[rules.\"example.com\"\n")
        .expect_err("malformed TOML must fail");
    assert!(malformed.to_string().contains("TOML syntax"));

    let unsupported = SessionFile::from_toml("version = 3\n\n[rules.\"example.com\"]\n")
        .expect_err("unknown schema versions must fail");
    assert!(unsupported.to_string().contains("expected version = 2"));

    let inferred =
        SessionFile::from_toml("version = 2\n[rules.\"example.com\"]\npaths = [\"/x\"]\n")
            .expect("a path rule should infer interception");
    assert_eq!(inferred.rules[0].mode, RuleMode::Intercept);

    let empty = SessionFile::from_toml("version = 2\n")
        .expect("an empty session should be a valid deny-all policy");
    assert!(empty.rules.is_empty());
    assert_eq!(empty.unmatched, UnmatchedHostPolicy::Deny);
}
