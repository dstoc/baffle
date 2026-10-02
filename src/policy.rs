//! Immutable authorization policy compiled for one proxy session.

use std::collections::{HashMap, HashSet};

use url::Host;

use crate::config::{
    HeaderInjection, PathRule, RuleMode, SessionConfig, UnmatchedHostPolicy,
    canonicalize_request_path,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthorizationError {
    InvalidAuthority,
    Denied,
}

/// A canonical destination accepted by the shared session policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Destination {
    pub(crate) host: String,
    pub(crate) port: u16,
}

/// Backend-neutral facts from one decrypted HTTP request.
pub(crate) struct RequestFacts<'a> {
    pub(crate) method: &'a str,
    pub(crate) scheme: Option<&'a str>,
    pub(crate) uri_authority: Option<&'a str>,
    pub(crate) path: &'a str,
    pub(crate) host_headers: &'a [&'a str],
    pub(crate) secure_transport: bool,
}

#[derive(Clone)]
struct CompiledRule {
    mode: RuleMode,
    ports: HashSet<u16>,
    paths: Vec<PathRule>,
    injections: Vec<HeaderInjection>,
}

/// A read-only set of host and port rules for one proxy session.
///
/// The policy owns normalized rule keys and cannot be changed after compile.
/// Proxy handler clones share this value through an `Arc`.
pub(crate) struct SessionPolicy {
    rules: HashMap<String, CompiledRule>,
    unmatched: UnmatchedHostPolicy,
}

impl SessionPolicy {
    pub(crate) fn compile(session: &SessionConfig) -> Self {
        let rules = session
            .rules
            .iter()
            .map(|rule| {
                (
                    rule.host.clone(),
                    CompiledRule {
                        mode: rule.mode,
                        ports: rule.ports.iter().copied().collect(),
                        paths: rule.paths.clone(),
                        injections: rule.inject.clone(),
                    },
                )
            })
            .collect();
        Self {
            rules,
            unmatched: session.unmatched,
        }
    }

    /// Authorize a CONNECT target. A CONNECT authority without a port uses 443.
    pub(crate) fn authorize_connect_authority(
        &self,
        authority: &str,
        host_headers: &[&str],
    ) -> Result<(RuleMode, Destination), AuthorizationError> {
        let destination = parse_authority_text(authority, Some(443))?;
        validate_host_header_text(host_headers, &destination)?;
        if let Some(rule) = self.rules.get(&destination.host) {
            if !rule.ports.contains(&destination.port)
                || (rule.mode == RuleMode::Tunnel && !rule.paths.is_empty())
            {
                return Err(AuthorizationError::Denied);
            }
            return Ok((rule.mode, destination));
        }

        if self.unmatched == UnmatchedHostPolicy::Tunnel && destination.port == 443 {
            return Ok((RuleMode::Tunnel, destination));
        }
        Err(AuthorizationError::Denied)
    }

    /// Confirm that CONNECT authority and TLS SNI identify one intercept rule.
    pub(crate) fn permits_tls_interception_authority(
        &self,
        authority: &str,
        server_name: Option<&str>,
    ) -> bool {
        let Ok((mode, destination)) = self.authorize_connect_authority(authority, &[]) else {
            return false;
        };
        let Some(server_name) = server_name.and_then(normalize_dns_name) else {
            return false;
        };
        mode == RuleMode::Intercept && server_name == destination.host
    }

    /// Apply policy to a decrypted request and return injections only after
    /// transport, authority, and canonical path checks succeed.
    pub(crate) fn authorize_intercepted_request<'a>(
        &'a self,
        facts: &RequestFacts<'_>,
        connect_authority: &str,
    ) -> Result<(&'a [HeaderInjection], Option<String>), AuthorizationError> {
        if facts.method.eq_ignore_ascii_case("CONNECT")
            || (!facts.secure_transport
                && !facts
                    .scheme
                    .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https")))
            || facts
                .scheme
                .is_some_and(|scheme| !scheme.eq_ignore_ascii_case("https"))
        {
            return Err(AuthorizationError::InvalidAuthority);
        }

        let connect = parse_authority_text(connect_authority, Some(443))?;
        let uri_destination = facts
            .uri_authority
            .map(|authority| parse_authority_text(authority, Some(443)))
            .transpose()?;
        let host_destination = if facts.host_headers.is_empty() {
            None
        } else {
            if facts.host_headers.len() != 1 {
                return Err(AuthorizationError::InvalidAuthority);
            }
            Some(parse_authority_text(facts.host_headers[0], Some(443))?)
        };
        if uri_destination
            .as_ref()
            .is_some_and(|destination| destination != &connect)
            || host_destination
                .as_ref()
                .is_some_and(|destination| destination != &connect)
            || (uri_destination.is_none() && host_destination.is_none())
        {
            return Err(AuthorizationError::InvalidAuthority);
        }

        let rule = self
            .rules
            .get(&connect.host)
            .filter(|rule| rule.ports.contains(&connect.port))
            .ok_or(AuthorizationError::Denied)?;
        let path = canonical_authorized_path(rule, facts.path)?;
        Ok((&rule.injections, path))
    }
}

fn validate_host_header_text(
    host_headers: &[&str],
    destination: &Destination,
) -> Result<(), AuthorizationError> {
    if host_headers.len() > 1 {
        return Err(AuthorizationError::InvalidAuthority);
    }
    if let Some(host) = host_headers.first()
        && parse_authority_text(host, Some(443))? != *destination
    {
        return Err(AuthorizationError::InvalidAuthority);
    }
    Ok(())
}

fn parse_authority_text(
    authority: &str,
    default_port: Option<u16>,
) -> Result<Destination, AuthorizationError> {
    if authority.is_empty()
        || !authority.is_ascii()
        || authority
            .chars()
            .any(|character| matches!(character, '@' | '%'))
    {
        return Err(AuthorizationError::InvalidAuthority);
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) if !host.contains(':') => (
            host,
            port.parse::<u16>()
                .map_err(|_| AuthorizationError::InvalidAuthority)?,
        ),
        Some(_) => return Err(AuthorizationError::InvalidAuthority),
        None => (
            authority,
            default_port.ok_or(AuthorizationError::InvalidAuthority)?,
        ),
    };
    if port == 0 {
        return Err(AuthorizationError::InvalidAuthority);
    }
    let host = normalize_dns_name(host).ok_or(AuthorizationError::InvalidAuthority)?;
    Ok(Destination { host, port })
}

fn canonical_authorized_path(
    rule: &CompiledRule,
    path: &str,
) -> Result<Option<String>, AuthorizationError> {
    if rule.paths.is_empty() {
        return Ok(None);
    }

    let canonical = canonicalize_request_path(path).map_err(|_| AuthorizationError::Denied)?;
    if !rule
        .paths
        .iter()
        .any(|pattern| pattern.matches_canonical_path(&canonical))
    {
        return Err(AuthorizationError::Denied);
    }
    Ok(Some(canonical))
}

fn normalize_dns_name(input: &str) -> Option<String> {
    if input.is_empty() || !input.is_ascii() || input.contains('%') {
        return None;
    }
    let input = input.to_ascii_lowercase();
    let input = input.strip_suffix('.').unwrap_or(&input);
    if input.is_empty() || input.len() > 253 {
        return None;
    }

    // URL host parsing rejects non-canonical IP literals such as `127.1`.
    let Host::Domain(host) = Host::parse(input).ok()? else {
        return None;
    };
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return None;
        }
    }
    Some(host)
}

#[cfg(test)]
mod tests {
    use crate::config::{ControlRequest, SessionFile};

    use super::*;

    fn policy(input: &str) -> SessionPolicy {
        let ControlRequest::Create { session, .. } =
            ControlRequest::from_toml(input).expect("test policy should be valid")
        else {
            panic!("test request should create a session");
        };
        SessionPolicy::compile(&session)
    }

    fn intercept_policy(paths: &str) -> SessionPolicy {
        policy(&format!(
            "version = 1\noperation = \"create\"\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\nports = [443]\npaths = {paths}\n"
        ))
    }

    fn session_file_policy(input: &str) -> SessionPolicy {
        SessionPolicy::compile(
            &SessionFile::from_toml(input).expect("test session file should be valid"),
        )
    }

    #[test]
    fn unmatched_tunnel_policy_allows_only_valid_dns_hosts_on_port_443() {
        let policy = session_file_policy("version = 2\nunmatched = \"tunnel\"\n");
        let (mode, destination) = policy
            .authorize_connect_authority("Other.Example.", &[])
            .expect("an unmatched DNS hostname should use the tunnel fallback");
        assert_eq!(mode, RuleMode::Tunnel);
        assert_eq!(destination.host, "other.example");
        assert_eq!(destination.port, 443);

        for authority in [
            "other.example:8443",
            "127.0.0.1:443",
            "127.1:443",
            "*.example.com:443",
            "bad host:443",
            "user@other.example:443",
        ] {
            assert!(
                policy.authorize_connect_authority(authority, &[]).is_err(),
                "unmatched policy must reject {authority}"
            );
        }
        assert_eq!(
            policy.authorize_connect_authority("other.example:443", &["evil.example"]),
            Err(AuthorizationError::InvalidAuthority)
        );
    }

    #[test]
    fn explicit_normalized_hosts_never_fall_back_after_a_denied_port() {
        let policy = session_file_policy(
            "version = 2\nunmatched = \"tunnel\"\n\n[rules.\"api.example.com\"]\nmode = \"intercept\"\nports = [443]\n",
        );

        assert_eq!(
            policy
                .authorize_connect_authority("other.example:443", &[])
                .expect("absent hosts should use the unmatched policy")
                .0,
            RuleMode::Tunnel
        );
        assert_eq!(
            policy
                .authorize_connect_authority("API.EXAMPLE.COM.:443", &[])
                .expect("normalized explicit host should match its rule")
                .0,
            RuleMode::Intercept
        );
        assert_eq!(
            policy.authorize_connect_authority("api.example.com:8443", &[]),
            Err(AuthorizationError::Denied)
        );

        let explicit_non_443 = session_file_policy(
            "version = 2\nunmatched = \"tunnel\"\n\n[rules.\"api.example.com\"]\nports = [8443]\n",
        );
        assert_eq!(
            explicit_non_443.authorize_connect_authority("api.example.com:443", &[]),
            Err(AuthorizationError::Denied),
            "a present rule that omits 443 must not use the 443 fallback"
        );
    }

    #[test]
    fn explicit_path_rules_remain_fail_closed_with_unmatched_tunneling() {
        let policy = session_file_policy(
            "version = 2\nunmatched = \"tunnel\"\n\n[rules.\"api.example.com\"]\npaths = [\"/allowed\"]\n",
        );
        let facts = RequestFacts {
            method: "GET",
            scheme: Some("https"),
            uri_authority: Some("api.example.com:443"),
            path: "/private",
            host_headers: &["api.example.com"],
            secure_transport: true,
        };
        assert_eq!(
            policy.authorize_intercepted_request(&facts, "api.example.com:443"),
            Err(AuthorizationError::Denied)
        );
    }

    #[test]
    fn empty_default_policy_denies_connect_destinations() {
        for input in ["version = 2\n", "version = 2\nunmatched = \"deny\"\n"] {
            let policy = session_file_policy(input);
            assert_eq!(
                policy.authorize_connect_authority("other.example:443", &[]),
                Err(AuthorizationError::Denied)
            );
        }
    }

    #[test]
    fn connect_requires_an_exact_authorized_host_port_and_matching_host_header() {
        let policy = intercept_policy("[]");
        let (mode, destination) = policy
            .authorize_connect_authority("EXAMPLE.COM.:443", &["example.com"])
            .expect("normalized exact destination should be allowed");
        assert_eq!(mode, RuleMode::Intercept);
        assert_eq!(destination.host, "example.com");
        assert_eq!(destination.port, 443);

        for authority in ["example.com:80", "other.example:443", "127.0.0.1:443"] {
            assert!(policy.authorize_connect_authority(authority, &[]).is_err());
        }
        assert_eq!(
            policy.authorize_connect_authority("example.com:443", &["example.com:444"]),
            Err(AuthorizationError::InvalidAuthority)
        );
        assert_eq!(
            policy.authorize_connect_authority("example.com:443", &["example.com", "example.com"]),
            Err(AuthorizationError::InvalidAuthority)
        );
    }

    #[test]
    fn interception_requires_sni_bound_to_the_connect_authority() {
        let policy = intercept_policy("[]");
        assert!(policy.permits_tls_interception_authority("example.com:443", Some("EXAMPLE.COM.")));
        assert!(
            !policy.permits_tls_interception_authority("example.com:443", Some("other.example"))
        );
        assert!(!policy.permits_tls_interception_authority("example.com:80", Some("example.com")));
    }

    #[test]
    fn intercepted_requests_bind_tls_uri_and_host_then_check_canonical_path() {
        let policy = intercept_policy("[\"/allowed/**\"]");
        let facts = RequestFacts {
            method: "GET",
            scheme: Some("https"),
            uri_authority: Some("example.com:443"),
            path: "/allowed/%7Euser",
            host_headers: &["example.com"],
            secure_transport: true,
        };
        let (_, canonical) = policy
            .authorize_intercepted_request(&facts, "example.com:443")
            .expect("authorized request should pass");
        assert_eq!(canonical.as_deref(), Some("/allowed/~user"));

        let wrong_authority = RequestFacts {
            uri_authority: Some("other.example"),
            ..facts
        };
        assert!(matches!(
            policy.authorize_intercepted_request(&wrong_authority, "example.com:443"),
            Err(AuthorizationError::InvalidAuthority)
        ));
        let unsafe_path = RequestFacts {
            path: "/allowed%2fprivate",
            ..facts
        };
        assert!(matches!(
            policy.authorize_intercepted_request(&unsafe_path, "example.com:443"),
            Err(AuthorizationError::Denied)
        ));
        let plaintext = RequestFacts {
            secure_transport: false,
            scheme: Some("http"),
            ..facts
        };
        assert!(matches!(
            policy.authorize_intercepted_request(&plaintext, "example.com:443"),
            Err(AuthorizationError::InvalidAuthority)
        ));
    }

    #[test]
    fn tunnel_rules_cannot_claim_path_specific_authorization() {
        let error = ControlRequest::from_toml(
            "version = 1\noperation = \"create\"\n[session]\n\n[[rules]]\nhost = \"example.com\"\nmode = \"tunnel\"\nports = [443]\npaths = [\"/allowed\"]\n",
        )
        .expect_err("tunnel rules cannot carry path restrictions");
        assert!(error.to_string().contains("cannot use paths or inject"));
    }
}
