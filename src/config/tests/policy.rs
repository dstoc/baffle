use super::{MINIMAL_CREATE, SESSION_EXAMPLE, config_with};
use crate::config::{
    ControlRequest, CredentialMode, InjectionFormat, PROTOCOL_VERSION, RuleMode, SessionConfig,
    SessionFile,
};

#[test]
fn parses_the_proposal_session_example_into_a_validated_policy() {
    let session = SessionFile::from_toml(SESSION_EXAMPLE)
        .expect("proposal session configuration should parse");
    assert!(!session.persistent);
    assert_eq!(session.rules.len(), 3);
    let crates = session
        .rules
        .iter()
        .find(|rule| rule.host == "crates.io")
        .expect("crates.io rule should exist");
    assert_eq!(crates.mode, RuleMode::Tunnel);
    let api = session
        .rules
        .iter()
        .find(|rule| rule.host == "api.github.com")
        .expect("GitHub API rule should exist");
    assert_eq!(api.paths[0].as_str(), "/repos/dstoc/cladding");
    assert_eq!(api.inject[0].format, InjectionFormat::Bearer);
    assert_eq!(
        session
            .rules
            .iter()
            .find(|rule| rule.host == "github.com")
            .expect("GitHub rule should exist")
            .inject[0]
            .username
            .as_deref(),
        Some("x-access-token")
    );
}

#[test]
fn validates_optional_nested_session_socket_names() {
    let request = ControlRequest::from_toml(
        "version = 2\noperation = \"create\"\n\n[session]\nversion = 2\nsocket_name = \"cladding/github.sock\"\n\n[session.rules.\"example.com\"]\nmode = \"tunnel\"",
    )
    .expect("a nested socket name should parse");
    let ControlRequest::Create { session, .. } = request else {
        panic!("expected create request");
    };
    assert_eq!(session.socket_name.as_deref(), Some("cladding/github.sock"));

    for name in [
        "",
        "/absolute.sock",
        "./socket.sock",
        "directory/../socket.sock",
        "../socket.sock",
        "directory//socket.sock",
        "directory/",
        "directory\\socket.sock",
        &"x".repeat(108),
    ] {
        let input = format!(
            "version = 2\noperation = \"create\"\n\n[session]\nversion = 2\nsocket_name = {name:?}\n\n[session.rules.\"example.com\"]\nmode = \"tunnel\""
        );
        assert!(
            ControlRequest::from_toml(&input).is_err(),
            "unsafe socket name should fail: {name:?}"
        );
    }
}

#[test]
fn accepts_interception_paths_and_injection_on_configured_port_80() {
    let request = ControlRequest::from_toml(
        "version = 2\noperation = \"create\"\n\n[session]\nversion = 2\n\n[session.rules.\"example.com\"]\nmode = \"intercept\"\nports = [80]\npaths = [\"/public\"]\n\n[[session.rules.\"example.com\".inject]]\nheader = \"Authorization\"\nsecret = \"api-token\"\nformat = \"bearer\"",
    )
    .expect("configured TLS on port 80 should parse");
    let ControlRequest::Create { session, .. } = request else {
        panic!("expected create request");
    };
    assert_eq!(session.rules[0].mode, RuleMode::Intercept);
    assert_eq!(session.rules[0].ports, [80]);
    assert_eq!(session.rules[0].paths[0].as_str(), "/public");
    assert_eq!(session.rules[0].inject[0].secret.as_str(), "api-token");
}

#[test]
fn defaults_create_persistence_and_destination_port() {
    let request =
        ControlRequest::from_toml(MINIMAL_CREATE).expect("minimal create request should parse");
    let ControlRequest::Create { session, version } = request else {
        panic!("expected create request");
    };
    assert_eq!(version, PROTOCOL_VERSION);
    assert!(!session.persistent);
    assert_eq!(session.rules[0].host, "example.com");
    assert_eq!(session.rules[0].ports, [443]);
}

#[test]
fn credential_modes_follow_override_default_then_inject_precedence() {
    let session = SessionFile::from_toml(
        r#"version = 2

[credentials]
default_mode = "substitute"

[credentials.overrides.github-api]
mode = "inject"

[credentials.overrides.openai]
mode = "disabled"

[credentials.overrides.default_mode]
mode = "disabled"
"#,
    )
    .expect("credential mode configuration should parse");

    assert_eq!(
        session.effective_credential_mode("github-api"),
        CredentialMode::Inject
    );
    assert_eq!(
        session.effective_credential_mode("another-api"),
        CredentialMode::Substitute
    );
    assert_eq!(
        session.effective_credential_mode("openai"),
        CredentialMode::Disabled
    );
    assert_eq!(
        session.effective_credential_mode("default_mode"),
        CredentialMode::Disabled
    );

    let legacy = SessionFile::from_toml("version = 2\n")
        .expect("existing session configuration should parse");
    assert_eq!(
        legacy.effective_credential_mode("github-api"),
        CredentialMode::Inject
    );
}

#[test]
fn rejects_invalid_credential_mode_identifiers_and_values() {
    for credentials in [
        "[credentials]\ndefault_mode = \"replace\"",
        "[credentials.overrides.\"../secret\"]\nmode = \"substitute\"",
        "[credentials.overrides.github]\nmode = \"replace\"",
        "[credentials.overrides.github]\nunknown = \"substitute\"",
        "[credentials.github]\nmode = \"inject\"",
    ] {
        let input = format!("version = 2\n\n{credentials}\n");
        assert!(
            SessionFile::from_toml(&input).is_err(),
            "invalid credential settings should fail"
        );
    }
}

#[test]
fn rejects_removed_private_addresses_field() {
    assert!(
        ControlRequest::from_toml(
            "version = 2\noperation = \"create\"\n\n[session]\nversion = 2\n\n[session.rules.\"internal.example\"]\nmode = \"tunnel\"\nports = [8443]\nprivate_addresses = [\"10.20.30.40\"]",
        )
        .is_err(),
        "removed address exceptions must fail strict schema validation"
    );
}

#[test]
fn rejects_invalid_or_ambiguous_policies_in_a_table() {
    let cases = [
        (
            "invalid hostname",
            config_with("host = \"*.example.com\"\nmode = \"tunnel\""),
        ),
        (
            "IP literal",
            config_with("host = \"127.0.0.1\"\nmode = \"tunnel\""),
        ),
        (
            "abbreviated IPv4 address",
            config_with("host = \"127.1\"\nmode = \"tunnel\""),
        ),
        (
            "three-part IPv4 address",
            config_with("host = \"127.0.1\"\nmode = \"tunnel\""),
        ),
        (
            "octal IPv4 address",
            config_with("host = \"0177.0.0.1\"\nmode = \"tunnel\""),
        ),
        (
            "hexadecimal IPv4 address",
            config_with("host = \"0x7f.1\"\nmode = \"tunnel\""),
        ),
        (
            "single-integer IPv4 address",
            config_with("host = \"2130706433\"\nmode = \"tunnel\""),
        ),
        (
            "zero port",
            config_with("host = \"example.com\"\nmode = \"tunnel\"\nports = [0]"),
        ),
        (
            "duplicate port",
            config_with("host = \"example.com\"\nmode = \"tunnel\"\nports = [443, 443]"),
        ),
        (
            "empty port list",
            config_with("host = \"example.com\"\nmode = \"tunnel\"\nports = []"),
        ),
        (
            "injection on tunnel",
            "version = 2\noperation = \"create\"\n\n[session]\nversion = 2\n\n[session.rules.\"example.com\"]\nmode = \"tunnel\"\n\n[[session.rules.\"example.com\".inject]]\nheader = \"Authorization\"\nsecret = \"token\"\nformat = \"bearer\"".to_string(),
        ),
        (
            "duplicate canonical host",
            "version = 2\noperation = \"create\"\n\n[session]\nversion = 2\n\n[session.rules.\"EXAMPLE.com\"]\nmode = \"tunnel\"\n\n[session.rules.\"example.com.\"]\nmode = \"tunnel\"".into(),
        ),
        (
            "overlapping paths",
            config_with(
                "host = \"example.com\"\nmode = \"intercept\"\npaths = [\"/x/**\", \"/x/y\"]",
            ),
        ),
        (
            "encoded separator",
            config_with(
                "host = \"example.com\"\nmode = \"intercept\"\npaths = [\"/x%2fy\"]",
            ),
        ),
        (
            "encoded dot segment",
            config_with(
                "host = \"example.com\"\nmode = \"intercept\"\npaths = [\"/%2e%2e/private\"]",
            ),
        ),
        (
            "malformed percent escape",
            config_with(
                "host = \"example.com\"\nmode = \"intercept\"\npaths = [\"/x%2\"]",
            ),
        ),
        (
            "routing-critical header",
            "version = 2\noperation = \"create\"\n\n[session]\nversion = 2\n\n[session.rules.\"example.com\"]\nmode = \"intercept\"\n\n[[session.rules.\"example.com\".inject]]\nheader = \"Host\"\nsecret = \"token\"\nformat = \"raw\"".to_string(),
        ),
        (
            "invalid secret identifier",
            "version = 2\noperation = \"create\"\n\n[session]\nversion = 2\n\n[session.rules.\"example.com\"]\nmode = \"intercept\"\n\n[[session.rules.\"example.com\".inject]]\nheader = \"Authorization\"\nsecret = \"../credential\"\nformat = \"bearer\"".to_string(),
        ),
        (
            "absolute secret path",
            "version = 2\noperation = \"create\"\n\n[session]\nversion = 2\n\n[session.rules.\"example.com\"]\nmode = \"intercept\"\n\n[[session.rules.\"example.com\".inject]]\nheader = \"Authorization\"\nsecret = \"/var/lib/token\"\nformat = \"bearer\"".to_string(),
        ),
        (
            "relative secret path",
            "version = 2\noperation = \"create\"\n\n[session]\nversion = 2\n\n[session.rules.\"example.com\"]\nmode = \"intercept\"\n\n[[session.rules.\"example.com\".inject]]\nheader = \"Authorization\"\nsecret = \"credentials/token\"\nformat = \"bearer\"".to_string(),
        ),
        (
            "embedded credentials",
            "version = 2\noperation = \"create\"\n\n[session]\nversion = 2\n\n[session.rules.\"example.com\"]\nmode = \"intercept\"\n\n[[session.rules.\"example.com\".inject]]\nheader = \"Authorization\"\nsecret = \"operator:credential\"\nformat = \"bearer\"".to_string(),
        ),
        (
            "basic password without username",
            "version = 2\noperation = \"create\"\n\n[session]\nversion = 2\n\n[session.rules.\"example.com\"]\nmode = \"intercept\"\n\n[[session.rules.\"example.com\".inject]]\nheader = \"Authorization\"\nsecret = \"token\"\nformat = \"basic_password\"".to_string(),
        ),
        (
            "literal credential field",
            "version = 2\noperation = \"create\"\n\n[session]\nversion = 2\n\n[session.rules.\"example.com\"]\nmode = \"intercept\"\n\n[[session.rules.\"example.com\".inject]]\nheader = \"Authorization\"\nsecret = \"token\"\nformat = \"bearer\"\nvalue = \"do-not-leak-this\"".to_string(),
        ),
    ];

    for (name, input) in cases {
        let error =
            ControlRequest::from_toml(&input).expect_err("invalid policy should be rejected");
        assert!(!error.to_string().contains("do-not-leak-this"), "{name}");
        assert!(!error.to_string().contains("credential"), "{name}");
    }
}

#[test]
fn rejects_duplicate_injection_headers_without_echoing_secret_values() {
    let input = r#"
version = 2
operation = "create"

[session]
version = 2

[session.rules."example.com"]
mode = "intercept"

[[session.rules."example.com".inject]]
header = "Authorization"
secret = "secret-value-one"
format = "bearer"

[[session.rules."example.com".inject]]
header = "authorization"
secret = "secret-value-two"
format = "raw""#;
    let error = ControlRequest::from_toml(input).expect_err("duplicate header should fail");
    assert!(error.to_string().contains("duplicates"));
    assert!(!error.to_string().contains("secret-value"));
}

#[test]
fn rejects_hop_by_hop_and_routing_sensitive_injection_headers() {
    for header in [
        "Connection",
        "Content-Length",
        "Forwarded",
        "Host",
        "HTTP2-Settings",
        "Proxy-Connection",
        "Transfer-Encoding",
        "Upgrade",
        "X-Forwarded-Host",
        "X-Original-URL",
    ] {
        let input = format!(
            "version = 2\noperation = \"create\"\n\n[session]\nversion = 2\n\n[session.rules.\"example.com\"]\nmode = \"intercept\"\n\n[[session.rules.\"example.com\".inject]]\nheader = \"{header}\"\nsecret = \"token\"\nformat = \"raw\""
        );
        let error =
            ControlRequest::from_toml(&input).expect_err("unsafe header names should be rejected");
        assert!(error.to_string().contains("hop-by-hop or routing-critical"));
    }
}

#[test]
fn validates_all_three_injection_formats() {
    for format in ["raw", "bearer"] {
        let request = ControlRequest::from_toml(&format!(
            "version = 2\noperation = \"create\"\n\n[session]\nversion = 2\n\n[session.rules.\"example.com\"]\nmode = \"intercept\"\n\n[[session.rules.\"example.com\".inject]]\nheader = \"X-Token\"\nsecret = \"api-token\"\nformat = \"{format}\""
        ))
        .expect("raw and bearer formats should parse");
        let ControlRequest::Create {
            session: SessionConfig { rules, .. },
            ..
        } = request
        else {
            panic!("expected create request");
        };
        assert_eq!(rules[0].inject[0].username, None);
    }

    let basic = ControlRequest::from_toml(
        "version = 2\noperation = \"create\"\n\n[session]\nversion = 2\n\n[session.rules.\"example.com\"]\nmode = \"intercept\"\n\n[[session.rules.\"example.com\".inject]]\nheader = \"Authorization\"\nsecret = \"git-token\"\nformat = \"basic_password\"\nusername = \"git\"",
    )
    .expect("basic_password should parse");
    let ControlRequest::Create { session, .. } = basic else {
        panic!("expected create request");
    };
    assert_eq!(
        session.rules[0].inject[0].format,
        InjectionFormat::BasicPassword
    );
}
