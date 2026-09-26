use std::{collections::HashSet, net::IpAddr};

use serde::Deserialize;
use url::Host;

use super::ConfigError;

/// The supported per-host action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleMode {
    Tunnel,
    Intercept,
}

/// A validated exact-host policy rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRule {
    /// Lowercase DNS hostname without a trailing dot.
    pub host: String,
    pub mode: RuleMode,
    pub ports: Vec<u16>,
    pub paths: Vec<PathRule>,
    pub inject: Vec<HeaderInjection>,
}

/// A validated exact path or recursive path prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRule {
    path: String,
    recursive: bool,
}

impl PathRule {
    /// Return the canonical path pattern used by this rule.
    pub fn as_str(&self) -> String {
        if self.recursive {
            format!("{}**", self.path)
        } else {
            self.path.clone()
        }
    }

    pub fn is_recursive(&self) -> bool {
        self.recursive
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub(crate) fn matches_canonical_path(&self, path: &str) -> bool {
        if self.recursive {
            path.starts_with(&self.path)
        } else {
            path == self.path
        }
    }

    fn overlaps(&self, other: &Self) -> bool {
        match (self.recursive, other.recursive) {
            (false, false) => self.path == other.path,
            (true, false) => other.path.starts_with(&self.path),
            (false, true) => self.path.starts_with(&other.path),
            (true, true) => {
                self.path.starts_with(&other.path) || other.path.starts_with(&self.path)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectionFormat {
    Raw,
    Bearer,
    BasicPassword,
}

/// A symbolic secret reference. Its value is never a secret credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef(String);

impl SecretRef {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated declaration for injecting a daemon-managed secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderInjection {
    pub header: String,
    pub secret: SecretRef,
    pub format: InjectionFormat,
    pub username: Option<String>,
}
pub(super) fn validate_rules(raw_rules: Vec<RawHostRule>) -> Result<Vec<HostRule>, ConfigError> {
    if raw_rules.is_empty() {
        return Err(ConfigError::new("create requires at least one rule"));
    }

    let mut hosts = HashSet::new();
    let mut rules = Vec::with_capacity(raw_rules.len());
    for (index, raw) in raw_rules.into_iter().enumerate() {
        let context = format!("rules[{index}]");
        let host = validate_hostname(&raw.host)
            .map_err(|message| ConfigError::new(format!("{context}.host {message}")))?;
        if !hosts.insert(host.clone()) {
            return Err(ConfigError::new(format!(
                "{context}.host duplicates another rule; use one rule per exact host"
            )));
        }

        if raw.ports.is_empty() {
            return Err(ConfigError::new(format!(
                "{context}.ports must not be empty"
            )));
        }
        let mut ports = HashSet::new();
        for port in &raw.ports {
            if *port == 0 {
                return Err(ConfigError::new(format!(
                    "{context}.ports entries must be between 1 and 65535"
                )));
            }
            if !ports.insert(*port) {
                return Err(ConfigError::new(format!(
                    "{context}.ports contains a duplicate"
                )));
            }
        }

        if raw.mode == RuleMode::Tunnel && !raw.inject.is_empty() {
            return Err(ConfigError::new(format!(
                "{context} tunnel rules cannot inject headers"
            )));
        }
        let mut paths = Vec::with_capacity(raw.paths.len());
        for (path_index, raw_path) in raw.paths.into_iter().enumerate() {
            let path = validate_path(&raw_path.0).map_err(|message| {
                ConfigError::new(format!("{context}.paths[{path_index}] {message}"))
            })?;
            if paths
                .iter()
                .any(|existing: &PathRule| existing.overlaps(&path))
            {
                return Err(ConfigError::new(format!(
                    "{context}.paths contains duplicate or overlapping patterns"
                )));
            }
            paths.push(path);
        }

        let mut inject = Vec::with_capacity(raw.inject.len());
        let mut headers = HashSet::new();
        for (inject_index, raw_injection) in raw.inject.into_iter().enumerate() {
            let injection_context = format!("{context}.inject[{inject_index}]");
            let header = validate_header(&raw_injection.header).map_err(|message| {
                ConfigError::new(format!("{injection_context}.header {message}"))
            })?;
            if !headers.insert(header.to_ascii_lowercase()) {
                return Err(ConfigError::new(format!(
                    "{injection_context}.header duplicates another injected header"
                )));
            }
            let secret = validate_secret_id(&raw_injection.secret.0).map_err(|message| {
                ConfigError::new(format!("{injection_context}.secret {message}"))
            })?;
            let username = match (raw_injection.format, raw_injection.username) {
                (InjectionFormat::BasicPassword, Some(username)) => {
                    validate_basic_username(&username).map_err(|message| {
                        ConfigError::new(format!("{injection_context}.username {message}"))
                    })?;
                    Some(username)
                }
                (InjectionFormat::BasicPassword, None) => {
                    return Err(ConfigError::new(format!(
                        "{injection_context}.username is required for basic_password"
                    )));
                }
                (_, Some(_)) => {
                    return Err(ConfigError::new(format!(
                        "{injection_context}.username is only valid for basic_password"
                    )));
                }
                (_, None) => None,
            };

            inject.push(HeaderInjection {
                header,
                secret,
                format: raw_injection.format,
                username,
            });
        }

        rules.push(HostRule {
            host,
            mode: raw.mode,
            ports: raw.ports,
            paths,
            inject,
        });
    }

    Ok(rules)
}

fn validate_hostname(input: &str) -> Result<String, &'static str> {
    if input.is_empty() || input.contains('*') {
        return Err("must be an exact DNS hostname");
    }
    let host = input.to_ascii_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host);
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

    // Match the URL host parser used for HTTP destinations. It recognizes
    // non-canonical IPv4 forms such as 127.1, octal components, and a single
    // integer. Parsing is local and does not perform DNS resolution.
    match Host::parse(host) {
        Ok(Host::Domain(domain)) => Ok(domain),
        Ok(Host::Ipv4(_) | Host::Ipv6(_)) => {
            Err("must be an exact DNS hostname, not an IP address or wildcard")
        }
        Err(_) => Err("must be a valid exact DNS hostname"),
    }
}

fn validate_path(input: &str) -> Result<PathRule, &'static str> {
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

    Ok(PathRule {
        path: canonical,
        recursive,
    })
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

pub(crate) fn canonicalize_request_path(path: &str) -> Result<String, &'static str> {
    canonicalize_path(if path.is_empty() { "/" } else { path })
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
    let prohibited = [
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
    if prohibited.contains(&input.to_ascii_lowercase().as_str()) {
        return Err("is a hop-by-hop or routing-critical header");
    }
    Ok(input.to_string())
}

fn validate_secret_id(input: &str) -> Result<SecretRef, &'static str> {
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
    Ok(SecretRef(input.to_string()))
}

pub(super) fn validate_allowed_secrets(
    raw: Vec<RawSecretRef>,
) -> Result<HashSet<String>, ConfigError> {
    let mut allowed = HashSet::with_capacity(raw.len());
    for secret in raw {
        let secret = validate_secret_id(&secret.0).map_err(|_| {
            ConfigError::new("secrets.allowed must contain valid secret identifiers")
        })?;
        if !allowed.insert(secret.as_str().to_owned()) {
            return Err(ConfigError::new(
                "secrets.allowed must not contain duplicate secret identifiers",
            ));
        }
    }
    Ok(allowed)
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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawHostRule {
    host: String,
    mode: RuleMode,
    #[serde(default = "default_ports")]
    ports: Vec<u16>,
    #[serde(default)]
    paths: Vec<RawPathRule>,
    #[serde(default)]
    inject: Vec<RawHeaderInjection>,
}

#[derive(Deserialize)]
#[serde(transparent)]
struct RawPathRule(String);

fn default_ports() -> Vec<u16> {
    vec![443]
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHeaderInjection {
    header: String,
    secret: RawSecretRef,
    format: InjectionFormat,
    username: Option<String>,
}

#[derive(Deserialize)]
#[serde(transparent)]
pub(super) struct RawSecretRef(String);
