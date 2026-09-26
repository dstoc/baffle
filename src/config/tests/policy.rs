use super::{MINIMAL_CREATE, SESSION_EXAMPLE, config_with};
use crate::config::{ControlRequest, InjectionFormat, PROTOCOL_VERSION, RuleMode, SessionConfig};

#[test]
fn parses_the_proposal_session_example_into_a_validated_policy() {
    let request = ControlRequest::from_toml(SESSION_EXAMPLE)
        .expect("proposal session configuration should parse");
    let ControlRequest::Create { version, session } = request else {
        panic!("expected create request");
    };
    assert_eq!(version, PROTOCOL_VERSION);
    assert!(!session.persistent);
    assert_eq!(session.rules.len(), 3);
    assert_eq!(session.rules[0].mode, RuleMode::Tunnel);
    assert_eq!(session.rules[1].paths[0].as_str(), "/repos/dstoc/cladding");
    assert_eq!(session.rules[1].inject[0].format, InjectionFormat::Bearer);
    assert_eq!(
        session.rules[2].inject[0].username.as_deref(),
        Some("x-access-token")
    );
}

#[test]
fn validates_optional_nested_session_socket_names() {
    let request = ControlRequest::from_toml(
        "version = 1\noperation = \"create\"\n\n[session]\nsocket_name = \"cladding/github.sock\"\n\n[[rules]]\nhost = \"example.com\"\nmode = \"tunnel\"\n",
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
            "version = 1\noperation = \"create\"\n\n[session]\nsocket_name = {name:?}\n\n[[rules]]\nhost = \"example.com\"\nmode = \"tunnel\"\n"
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
        "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\nports = [80]\npaths = [\"/public\"]\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"api-token\"\nformat = \"bearer\"\n",
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
fn rejects_removed_private_addresses_field_for_migration() {
    assert!(
        ControlRequest::from_toml(
            "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"internal.example\"\nmode = \"tunnel\"\nports = [8443]\nprivate_addresses = [\"10.20.30.40\"]\n",
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
            "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"tunnel\"\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"token\"\nformat = \"bearer\"\n".to_string(),
        ),
        (
            "duplicate canonical host",
            "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"EXAMPLE.com\"\nmode = \"tunnel\"\n\n[[rules]]\nhost = \"example.com.\"\nmode = \"tunnel\"\n".into(),
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
            "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\n\n[[rules.inject]]\nheader = \"Host\"\nsecret = \"token\"\nformat = \"raw\"\n".to_string(),
        ),
        (
            "invalid secret identifier",
            "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"../credential\"\nformat = \"bearer\"\n".to_string(),
        ),
        (
            "absolute secret path",
            "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"/var/lib/token\"\nformat = \"bearer\"\n".to_string(),
        ),
        (
            "relative secret path",
            "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"credentials/token\"\nformat = \"bearer\"\n".to_string(),
        ),
        (
            "embedded credentials",
            "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"operator:credential\"\nformat = \"bearer\"\n".to_string(),
        ),
        (
            "basic password without username",
            "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"token\"\nformat = \"basic_password\"\n".to_string(),
        ),
        (
            "literal credential field",
            "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"token\"\nformat = \"bearer\"\nvalue = \"do-not-leak-this\"\n".to_string(),
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
version = 1
operation = "create"

[session]

[[rules]]
host = "example.com"
mode = "intercept"

[[rules.inject]]
header = "Authorization"
secret = "secret-value-one"
format = "bearer"

[[rules.inject]]
header = "authorization"
secret = "secret-value-two"
format = "raw"
"#;
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
            "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\n\n[[rules.inject]]\nheader = \"{header}\"\nsecret = \"token\"\nformat = \"raw\"\n"
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
            "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\n\n[[rules.inject]]\nheader = \"X-Token\"\nsecret = \"api-token\"\nformat = \"{format}\"\n"
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
        "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"git-token\"\nformat = \"basic_password\"\nusername = \"git\"\n",
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
