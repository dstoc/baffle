use std::{
    collections::{BTreeMap, HashSet},
    error::Error,
    fmt,
    net::IpAddr,
};

use serde::Deserialize;
use url::Host;

use crate::{
    CredentialMode, HeaderInjection, HostRule, InjectionFormat, RuleMode, SessionConfig,
    UnmatchedHostPolicy,
};

/// The version of the session configuration document.
pub const SESSION_CONFIG_VERSION: u16 = 2;

/// Maximum UTF-8 byte length of a daemon-managed session configuration name.
pub const MAX_SESSION_CONFIG_NAME_BYTES: usize = 1_024;

/// Maximum UTF-8 byte length of one session configuration name component.
pub const MAX_SESSION_CONFIG_COMPONENT_BYTES: usize = 255;

/// Safe message used when a daemon cannot load a managed session document.
pub const SESSION_CONFIG_INVALID_MESSAGE: &str =
    "session configuration file is invalid; use the current schema with version = 2";

/// A safe error produced while parsing or validating a session policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfigError(String);

impl SessionConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for SessionConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for SessionConfigError {}

impl SessionConfig {
    /// Parse and validate a version 2 session configuration document.
    pub fn from_toml(input: &str) -> Result<Self, SessionConfigError> {
        let raw: RawSessionConfig = toml::from_str(input).map_err(|_| {
            SessionConfigError::new(
                "invalid session configuration TOML syntax or value (values omitted)",
            )
        })?;
        validate_session_document(raw)
    }
}

/// Validate a session configuration name used by the daemon's file-backed API.
pub fn validate_session_config_name(name: &str) -> Result<(), SessionConfigError> {
    if name.is_empty()
        || name.len() > MAX_SESSION_CONFIG_NAME_BYTES
        || !name.ends_with(".toml")
        || name.contains(['\\', ':'])
        || name.chars().any(char::is_control)
        || name.split('/').any(|component| {
            component.is_empty()
                || component == "."
                || component == ".."
                || component.len() > MAX_SESSION_CONFIG_COMPONENT_BYTES
        })
    {
        return Err(SessionConfigError::new(
            "session configuration name is invalid",
        ));
    }
    Ok(())
}

/// Validate a symbolic secret identifier used by policy rules or daemon settings.
pub fn validate_secret_name(input: &str) -> Result<(), SessionConfigError> {
    validate_secret_id(input)
        .map(|_| ())
        .map_err(SessionConfigError::new)
}

/// Normalize and validate an exact ASCII DNS hostname.
///
/// A final dot is removed and ASCII letters are converted to lowercase. IP
/// literals, wildcards, invalid labels, and names longer than 253 bytes are
/// rejected.
pub fn normalize_dns_name(input: &str) -> Result<String, &'static str> {
    if input.is_empty() || input.contains('*') {
        return Err("must be an exact DNS hostname");
    }

    let input = input.to_ascii_lowercase();
    let host = input.strip_suffix('.').unwrap_or(&input);
    if host.is_empty() || host.len() > 253 || host.parse::<IpAddr>().is_ok() || !host.is_ascii() {
        return Err("must be an exact DNS hostname, not an IP address or wildcard");
    }

    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err("contains an invalid DNS label");
        }
    }

    match Host::parse(host) {
        Ok(Host::Domain(domain)) => Ok(domain),
        Ok(Host::Ipv4(_) | Host::Ipv6(_)) => {
            Err("must be an exact DNS hostname, not an IP address or wildcard")
        }
        Err(_) => Err("must be a valid exact DNS hostname"),
    }
}

/// Canonicalize an HTTP request path before matching it against a policy rule.
pub fn canonicalize_request_path(path: &str) -> Result<String, &'static str> {
    canonicalize_path(if path.is_empty() { "/" } else { path })
}

fn validate_session_document(raw: RawSessionConfig) -> Result<SessionConfig, SessionConfigError> {
    match raw.version {
        Some(version) if version == i64::from(SESSION_CONFIG_VERSION) => {}
        Some(_) => {
            return Err(SessionConfigError::new(format!(
                "unsupported session configuration version; expected version = {SESSION_CONFIG_VERSION}"
            )));
        }
        None => {
            return Err(SessionConfigError::new(format!(
                "session configuration must declare version = {SESSION_CONFIG_VERSION}"
            )));
        }
    }

    if !raw.unsupported_fields.is_empty() {
        return Err(invalid_session_file());
    }

    let unmatched = match raw.unmatched.as_deref().unwrap_or("deny") {
        "deny" => UnmatchedHostPolicy::Deny,
        "tunnel" => UnmatchedHostPolicy::Tunnel,
        _ => {
            return Err(SessionConfigError::new(
                "unmatched must be \"deny\" or \"tunnel\"",
            ));
        }
    };
    let rules = match raw.rules {
        Some(RawRules::Named(rules)) => rules,
        Some(RawRules::Other(value)) => {
            let _ = value;
            return Err(invalid_session_file());
        }
        None => BTreeMap::new(),
    };

    let rules = validate_named_rules(rules)?;
    let socket_name = raw.socket_name.map(validate_socket_name).transpose()?;
    let (default_credential_mode, credential_modes) = validate_credentials(raw.credentials)?;
    Ok(SessionConfig {
        persistent: raw.persistent,
        socket_name,
        unmatched,
        default_credential_mode,
        credential_modes,
        rules,
    })
}

fn validate_credentials(
    raw: Option<RawCredentials>,
) -> Result<(Option<CredentialMode>, BTreeMap<String, CredentialMode>), SessionConfigError> {
    let Some(raw) = raw else {
        return Ok((None, BTreeMap::new()));
    };
    let mut modes = BTreeMap::new();
    for (name, raw_mode) in raw.overrides {
        validate_secret_id(&name).map_err(|_| {
            SessionConfigError::new("credentials contains an invalid secret identifier")
        })?;
        if modes.insert(name, raw_mode.mode).is_some() {
            return Err(SessionConfigError::new(
                "credentials contains a duplicate secret identifier",
            ));
        }
    }
    Ok((raw.default_mode, modes))
}

fn validate_named_rules(
    raw_rules: BTreeMap<String, RawNamedRule>,
) -> Result<Vec<HostRule>, SessionConfigError> {
    let mut hosts = HashSet::new();
    let mut rules = Vec::with_capacity(raw_rules.len());
    for (index, (raw_host, raw)) in raw_rules.into_iter().enumerate() {
        let context = format!("rules[{index}]");
        let RawNamedRule {
            mode: raw_mode,
            ports,
            paths: raw_paths,
            inject: raw_inject,
        } = raw;
        let host = normalize_dns_name(&raw_host)
            .map_err(|message| SessionConfigError::new(format!("{context}.host {message}")))?;
        if !hosts.insert(host.clone()) {
            return Err(SessionConfigError::new(format!(
                "{context}.host duplicates another rule; use one rule per exact host"
            )));
        }

        let has_intercept_features = raw_paths.is_some() || raw_inject.is_some();
        let mode = raw_mode.unwrap_or(if has_intercept_features {
            RuleMode::Intercept
        } else {
            RuleMode::Tunnel
        });
        let paths = raw_paths.unwrap_or_default();
        let inject = raw_inject
            .unwrap_or_default()
            .into_iter()
            .map(|raw| HeaderInjection {
                header: raw.header,
                secret: raw.secret,
                format: raw.format,
                username: raw.username,
            })
            .collect();

        rules.push(validate_rule(
            HostRule {
                host,
                mode,
                ports,
                paths,
                inject,
            },
            &context,
            has_intercept_features,
        )?);
    }
    Ok(rules)
}

fn validate_rule(
    mut rule: HostRule,
    context: &str,
    has_intercept_features: bool,
) -> Result<HostRule, SessionConfigError> {
    if rule.ports.is_empty() {
        return Err(SessionConfigError::new(format!(
            "{context}.ports must not be empty"
        )));
    }
    let mut unique_ports = HashSet::new();
    for port in &rule.ports {
        if *port == 0 {
            return Err(SessionConfigError::new(format!(
                "{context}.ports entries must be between 1 and 65535"
            )));
        }
        if !unique_ports.insert(*port) {
            return Err(SessionConfigError::new(format!(
                "{context}.ports contains a duplicate"
            )));
        }
    }

    if rule.mode == RuleMode::Tunnel && has_intercept_features {
        return Err(SessionConfigError::new(format!(
            "{context} tunnel rules cannot use paths or inject headers"
        )));
    }

    let mut paths = Vec::<String>::with_capacity(rule.paths.len());
    for (index, raw_path) in rule.paths.into_iter().enumerate() {
        let path = validate_path(&raw_path).map_err(|message| {
            SessionConfigError::new(format!("{context}.paths[{index}] {message}"))
        })?;
        if paths.iter().any(|existing| paths_overlap(existing, &path)) {
            return Err(SessionConfigError::new(format!(
                "{context}.paths contains duplicate or overlapping patterns"
            )));
        }
        paths.push(path);
    }
    rule.paths = paths;

    let mut headers = HashSet::new();
    for (index, injection) in rule.inject.iter_mut().enumerate() {
        let injection_context = format!("{context}.inject[{index}]");
        injection.header = validate_header(&injection.header).map_err(|message| {
            SessionConfigError::new(format!("{injection_context}.header {message}"))
        })?;
        if !headers.insert(injection.header.to_ascii_lowercase()) {
            return Err(SessionConfigError::new(format!(
                "{injection_context}.header duplicates another injected header"
            )));
        }
        validate_secret_id(&injection.secret).map_err(|message| {
            SessionConfigError::new(format!("{injection_context}.secret {message}"))
        })?;
        match (injection.format, injection.username.as_deref()) {
            (InjectionFormat::BasicPassword, Some(username)) => {
                validate_basic_username(username).map_err(|message| {
                    SessionConfigError::new(format!("{injection_context}.username {message}"))
                })?;
            }
            (InjectionFormat::BasicPassword, None) => {
                return Err(SessionConfigError::new(format!(
                    "{injection_context}.username is required for basic_password"
                )));
            }
            (_, Some(_)) => {
                return Err(SessionConfigError::new(format!(
                    "{injection_context}.username is only valid for basic_password"
                )));
            }
            (_, None) => {}
        }
    }

    Ok(rule)
}

fn validate_socket_name(input: String) -> Result<String, SessionConfigError> {
    if input.is_empty() || input.starts_with('/') || input.contains(['\\', '\0']) {
        return Err(SessionConfigError::new(
            "socket_name must be a relative Unix socket path",
        ));
    }
    if input
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(SessionConfigError::new(
            "socket_name must not contain empty, dot, or parent components",
        ));
    }
    if input.len() > 107 {
        return Err(SessionConfigError::new("socket_name is too long"));
    }
    Ok(input)
}

fn validate_path(input: &str) -> Result<String, &'static str> {
    if !input.starts_with('/') || input.contains(['?', '#', '\\']) {
        return Err("must be an absolute URL path without query, fragment, or backslash");
    }

    let (path, recursive) = if let Some(prefix) = input.strip_suffix("/**") {
        (
            if prefix.is_empty() {
                "/"
            } else {
                &input[..prefix.len() + 1]
            },
            true,
        )
    } else {
        (input, false)
    };
    if path.contains('*') {
        return Err("may use ** only as the final recursive path segment");
    }

    let canonical = canonicalize_path(path)?;
    Ok(if recursive {
        format!("{canonical}**")
    } else {
        canonical
    })
}

fn paths_overlap(left: &str, right: &str) -> bool {
    let (left_path, left_recursive) = path_pattern_parts(left);
    let (right_path, right_recursive) = path_pattern_parts(right);
    match (left_recursive, right_recursive) {
        (false, false) => left_path == right_path,
        (true, false) => right_path.starts_with(left_path),
        (false, true) => left_path.starts_with(right_path),
        (true, true) => left_path.starts_with(right_path) || right_path.starts_with(left_path),
    }
}

fn path_pattern_parts(pattern: &str) -> (&str, bool) {
    pattern
        .strip_suffix("**")
        .map_or((pattern, false), |path| (path, true))
}

fn canonicalize_path(path: &str) -> Result<String, &'static str> {
    if !path.starts_with('/') || path.contains(['?', '#', '\\']) {
        return Err("must be an absolute URL path without query, fragment, or backslash");
    }

    let mut canonical = String::with_capacity(path.len());
    let bytes = path.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len() {
                return Err("contains malformed percent encoding");
            }
            let high = hex_value(bytes[index + 1]).ok_or("contains malformed percent encoding")?;
            let low = hex_value(bytes[index + 2]).ok_or("contains malformed percent encoding")?;
            let decoded = high * 16 + low;
            if matches!(decoded, b'/' | b'\\' | b'%') {
                return Err("contains an encoded path separator or ambiguous double encoding");
            }
            if is_unreserved(decoded) {
                canonical.push(char::from(decoded));
            } else {
                canonical.push('%');
                canonical.push(char::from(bytes[index + 1].to_ascii_uppercase()));
                canonical.push(char::from(bytes[index + 2].to_ascii_uppercase()));
            }
            index += 3;
            continue;
        }

        if !is_path_character(byte) {
            return Err("contains a character that is not valid in a URL path");
        }
        canonical.push(char::from(byte));
        index += 1;
    }

    if canonical.contains("//") {
        return Err("contains an ambiguous repeated path separator");
    }
    if canonical
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return Err("contains an unsafe dot segment");
    }

    Ok(canonical)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn is_path_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'/' | b'-'
                | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
        )
}

fn validate_header(input: &str) -> Result<String, &'static str> {
    const PROHIBITED: &[&str] = &[
        "connection",
        "content-length",
        "forwarded",
        "host",
        "http2-settings",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-port",
        "x-forwarded-proto",
        "x-original-host",
        "x-original-url",
        "x-real-ip",
        "x-rewrite-url",
    ];
    if input.is_empty()
        || !input
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
    {
        return Err("must be a valid HTTP header name");
    }
    if PROHIBITED.contains(&input.to_ascii_lowercase().as_str()) {
        return Err("is a hop-by-hop or routing-critical header");
    }
    Ok(input.to_string())
}

fn validate_secret_id(input: &str) -> Result<(), &'static str> {
    if input.is_empty()
        || input.len() > 64
        || !input
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || !input.as_bytes()[0].is_ascii_alphanumeric()
        || input
            .chars()
            .last()
            .is_some_and(|character| matches!(character, '.' | '-' | '_'))
        || input.contains("..")
    {
        return Err("must be a valid symbolic secret identifier");
    }
    Ok(())
}

fn validate_basic_username(input: &str) -> Result<(), &'static str> {
    if input.is_empty()
        || input.contains(':')
        || !input.bytes().all(|byte| (b' '..=b'~').contains(&byte))
    {
        return Err("must be printable ASCII and must not contain a colon");
    }
    Ok(())
}

fn invalid_session_file() -> SessionConfigError {
    SessionConfigError::new(format!(
        "invalid version {SESSION_CONFIG_VERSION} session configuration field or value (values omitted)"
    ))
}

#[derive(Deserialize)]
struct RawSessionConfig {
    #[serde(default)]
    version: Option<i64>,
    #[serde(default)]
    persistent: bool,
    #[serde(default)]
    socket_name: Option<String>,
    #[serde(default)]
    unmatched: Option<String>,
    #[serde(default)]
    rules: Option<RawRules>,
    #[serde(default)]
    credentials: Option<RawCredentials>,
    #[serde(default, flatten)]
    unsupported_fields: BTreeMap<String, toml::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCredentials {
    #[serde(default)]
    default_mode: Option<CredentialMode>,
    #[serde(default)]
    overrides: BTreeMap<String, RawCredentialModeOverride>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCredentialModeOverride {
    mode: CredentialMode,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawRules {
    Named(BTreeMap<String, RawNamedRule>),
    Other(toml::Value),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNamedRule {
    #[serde(default)]
    mode: Option<RuleMode>,
    #[serde(default = "default_ports")]
    ports: Vec<u16>,
    #[serde(default)]
    paths: Option<Vec<String>>,
    #[serde(default)]
    inject: Option<Vec<RawHeaderInjection>>,
}

fn default_ports() -> Vec<u16> {
    vec![443]
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHeaderInjection {
    header: String,
    secret: String,
    format: InjectionFormat,
    username: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_canonicalizes_v2_session_policy() {
        let session = SessionConfig::from_toml(
            r#"version = 2

[rules."Example.COM."]
paths = ["/v1/%7euser/**"]

[[rules."Example.COM.".inject]]
header = "Authorization"
secret = "api-token"
format = "bearer""#,
        )
        .expect("session policy should parse");
        assert_eq!(session.rules[0].host, "example.com");
        assert_eq!(session.rules[0].mode, RuleMode::Intercept);
        assert_eq!(session.rules[0].paths, ["/v1/~user/**"]);
        assert_eq!(session.rules[0].inject[0].secret, "api-token");
    }

    #[test]
    fn shares_session_config_name_validation() {
        assert!(validate_session_config_name("cladding/github.toml").is_ok());
        assert!(validate_session_config_name(&format!("{}.toml", "a".repeat(256))).is_err());
        assert!(validate_session_config_name("../outside.toml").is_err());
    }

    #[test]
    fn preserves_public_policy_serde_formats() {
        let rule = HostRule::intercept("api.example.com");
        assert_eq!(
            serde_json::to_string(&rule).expect("host rule should serialize"),
            r#"{"host":"api.example.com","mode":"intercept","ports":[443]}"#
        );
        assert_eq!(
            serde_json::to_string(&RuleMode::Intercept).expect("mode should serialize"),
            "\"intercept\""
        );
        let injection = HeaderInjection::basic_password("Authorization", "git-token", "git");
        let encoded = serde_json::to_string(&injection).expect("injection should serialize");
        assert!(encoded.contains("\"basic_password\""));
        assert!(encoded.contains("\"secret\":\"git-token\""));
        assert_eq!(
            serde_json::from_str::<HeaderInjection>(&encoded)
                .expect("injection should deserialize"),
            injection
        );
    }
}
