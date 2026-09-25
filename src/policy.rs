//! Immutable authorization policy compiled for one proxy session.

use std::collections::{HashMap, HashSet};

use hudsucker::hyper::{
    Method, Request, Uri, Version,
    header::{HOST, HeaderMap},
    http::uri::{Authority, PathAndQuery},
};
use url::Host;

use crate::config::{
    HeaderInjection, PathRule, RuleMode, SessionConfig, canonicalize_request_path,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthorizationError {
    InvalidAuthority,
    Denied,
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
        Self { rules }
    }

    /// Authorize an ordinary HTTP request or a CONNECT request.
    pub(crate) fn authorize<B>(
        &self,
        request: &Request<B>,
    ) -> Result<RuleMode, AuthorizationError> {
        let rule = self.rule_for_request(request)?;

        if request.method() != Method::CONNECT {
            canonical_authorized_path(rule, request.uri().path())?;
        }

        Ok(rule.mode)
    }

    /// Authorize a request and replace its path with the canonical path that
    /// was checked. This keeps the upstream request target identical to the
    /// path used for the policy decision.
    pub(crate) fn authorize_request<B>(
        &self,
        request: &mut Request<B>,
    ) -> Result<RuleMode, AuthorizationError> {
        let rule = self.rule_for_request(request)?;

        if request.method() != Method::CONNECT
            && let Some(path) = canonical_authorized_path(rule, request.uri().path())?
        {
            rewrite_request_path(request, &path)?;
        }

        Ok(rule.mode)
    }

    /// Authorize an intercepted HTTPS request and canonicalize its path before
    /// forwarding it to the origin.
    #[cfg(test)]
    pub(crate) fn authorize_inner_request<B>(
        &self,
        request: &mut Request<B>,
        connect_authority: &Authority,
    ) -> Result<RuleMode, AuthorizationError> {
        self.authorize_inner_request_with_injections(request, connect_authority)
            .map(|(mode, _)| mode)
    }

    /// Authorize an intercepted HTTPS request and return the matching rule's
    /// injection declarations only after authority and canonical path checks.
    pub(crate) fn authorize_inner_request_with_injections<'a, B>(
        &'a self,
        request: &mut Request<B>,
        connect_authority: &Authority,
    ) -> Result<(RuleMode, &'a [HeaderInjection]), AuthorizationError> {
        if request.method() == Method::CONNECT {
            return Err(AuthorizationError::InvalidAuthority);
        }
        if !request
            .uri()
            .scheme_str()
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https"))
        {
            return Err(AuthorizationError::InvalidAuthority);
        }
        if matches!(request.version(), Version::HTTP_10 | Version::HTTP_11)
            && !request.headers().contains_key(HOST)
        {
            return Err(AuthorizationError::InvalidAuthority);
        }

        let expected = parse_authority(connect_authority, None)?;
        let actual = http_destination(request)?;
        if actual != expected {
            return Err(AuthorizationError::InvalidAuthority);
        }
        let mode = self.authorize_request(request)?;
        let rule = self.rule_for_request(request)?;
        Ok((mode, &rule.injections))
    }

    /// Authorize a proxy request for the handler. Only inner requests carried
    /// by an intercepted CONNECT may receive credentials. The outer CONNECT
    /// itself is authorized so Hudsucker can establish the inspected stream.
    pub(crate) fn authorize_proxy_request<'a, B>(
        &'a self,
        request: &mut Request<B>,
        connect_authority: Option<&Authority>,
    ) -> Result<(RuleMode, &'a [HeaderInjection]), AuthorizationError> {
        if let Some(connect_authority) = connect_authority {
            return self.authorize_inner_request_with_injections(request, connect_authority);
        }

        let mode = self.authorize_request(request)?;
        let rule = self.rule_for_request(request)?;
        if request.method() != Method::CONNECT && !rule.injections.is_empty() {
            return Err(AuthorizationError::Denied);
        }
        Ok((mode, &[]))
    }

    /// Check that an intercepted CONNECT uses a policy-authorized SNI name
    /// that identifies the same host as the CONNECT authority.
    pub(crate) fn permits_tls_interception(
        &self,
        connect_authority: &Authority,
        server_name: Option<&str>,
    ) -> bool {
        let Ok((connect_host, port)) = parse_authority(connect_authority, None) else {
            return false;
        };
        let Some(server_name) = server_name.and_then(normalize_dns_name) else {
            return false;
        };
        if server_name != connect_host {
            return false;
        }
        self.rules
            .get(&connect_host)
            .is_some_and(|rule| rule.mode == RuleMode::Intercept && rule.ports.contains(&port))
    }

    fn rule_for_request<B>(
        &self,
        request: &Request<B>,
    ) -> Result<&CompiledRule, AuthorizationError> {
        let (host, port) = if request.method() == Method::CONNECT {
            connect_destination(request)?
        } else {
            http_destination(request)?
        };

        let rule = self
            .rules
            .get(&host)
            .filter(|rule| rule.ports.contains(&port))
            .ok_or(AuthorizationError::Denied)?;
        if request.method() != Method::CONNECT
            && request
                .uri()
                .scheme_str()
                .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http"))
            && !rule.injections.is_empty()
        {
            return Err(AuthorizationError::Denied);
        }
        if request.method() == Method::CONNECT
            && rule.mode == RuleMode::Tunnel
            && !rule.paths.is_empty()
        {
            return Err(AuthorizationError::Denied);
        }
        Ok(rule)
    }
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

fn rewrite_request_path<B>(request: &mut Request<B>, path: &str) -> Result<(), AuthorizationError> {
    let mut path_and_query = path.to_string();
    if let Some(query) = request.uri().query() {
        path_and_query.push('?');
        path_and_query.push_str(query);
    }

    let mut parts = request.uri().clone().into_parts();
    parts.path_and_query = Some(
        PathAndQuery::try_from(path_and_query).map_err(|_| AuthorizationError::InvalidAuthority)?,
    );
    *request.uri_mut() =
        Uri::from_parts(parts).map_err(|_| AuthorizationError::InvalidAuthority)?;
    Ok(())
}

fn connect_destination<B>(request: &Request<B>) -> Result<(String, u16), AuthorizationError> {
    let uri = request.uri();
    if uri.scheme().is_some() || uri.path_and_query().is_some() {
        return Err(AuthorizationError::InvalidAuthority);
    }
    let authority = uri
        .authority()
        .ok_or(AuthorizationError::InvalidAuthority)?;
    let destination = parse_authority(authority, None)?;
    validate_host_header(request.headers(), &destination, Some(443))?;
    Ok(destination)
}

fn http_destination<B>(request: &Request<B>) -> Result<(String, u16), AuthorizationError> {
    let uri = request.uri();
    let default_port = match uri.scheme_str() {
        Some(scheme) if scheme.eq_ignore_ascii_case("http") => 80,
        Some(scheme) if scheme.eq_ignore_ascii_case("https") => 443,
        _ => return Err(AuthorizationError::InvalidAuthority),
    };
    let authority = uri
        .authority()
        .ok_or(AuthorizationError::InvalidAuthority)?;
    let destination = parse_authority(authority, Some(default_port))?;
    validate_host_header(request.headers(), &destination, Some(default_port))?;
    Ok(destination)
}

fn validate_host_header(
    headers: &HeaderMap,
    destination: &(String, u16),
    default_port: Option<u16>,
) -> Result<(), AuthorizationError> {
    let mut values = headers.get_all(HOST).iter();
    let Some(value) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err(AuthorizationError::InvalidAuthority);
    }

    let value = value
        .to_str()
        .map_err(|_| AuthorizationError::InvalidAuthority)?;
    let authority = value
        .parse::<Authority>()
        .map_err(|_| AuthorizationError::InvalidAuthority)?;
    let host_destination = parse_authority(&authority, default_port)?;
    if host_destination == *destination {
        Ok(())
    } else {
        Err(AuthorizationError::InvalidAuthority)
    }
}

fn parse_authority(
    authority: &Authority,
    default_port: Option<u16>,
) -> Result<(String, u16), AuthorizationError> {
    if authority.as_str().contains('@') {
        return Err(AuthorizationError::InvalidAuthority);
    }

    let host = normalize_dns_name(authority.host()).ok_or(AuthorizationError::InvalidAuthority)?;
    let port = match authority.port() {
        Some(_) => authority
            .port_u16()
            .ok_or(AuthorizationError::InvalidAuthority)?,
        None => default_port.ok_or(AuthorizationError::InvalidAuthority)?,
    };
    if port == 0 {
        return Err(AuthorizationError::InvalidAuthority);
    }
    Ok((host, port))
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

    // URL host parsing catches IPv4 literals in non-canonical forms such as
    // 127.1 and a single integer. IPv6 literals do not parse as DNS names.
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
    use std::sync::Arc;

    use hudsucker::hyper::http::uri::Uri;
    use hudsucker::{Body, RequestOrResponse};

    use super::*;
    use crate::{
        config::ControlRequest,
        proxy_runtime::{PolicyHandler, RuntimeId},
    };

    fn policy(input: &str) -> SessionPolicy {
        let ControlRequest::Create { session, .. } =
            ControlRequest::from_toml(input).expect("test policy should be valid")
        else {
            panic!("test request should create a session");
        };
        SessionPolicy::compile(&session)
    }

    fn request(method: &str, uri: &str, host: Option<&str>) -> Request<Body> {
        let request_uri = if method == "CONNECT" {
            let authority = uri
                .parse::<Authority>()
                .expect("CONNECT authority should parse");
            Uri::builder()
                .authority(authority)
                .build()
                .expect("CONNECT URI should be valid")
        } else {
            uri.parse::<Uri>().expect("HTTP URI should parse")
        };
        let mut builder = Request::builder().method(method).uri(request_uri);
        if let Some(host) = host {
            builder = builder.header(HOST, host);
        }
        builder
            .body(Body::empty())
            .expect("test request should be valid")
    }

    fn policy_with(host: &str, mode: &str, ports: &str) -> SessionPolicy {
        policy(&format!(
            "version = 1\noperation = \"create\"\n[session]\n\n[[rules]]\nhost = \"{host}\"\nmode = \"{mode}\"\n{ports}"
        ))
    }

    fn path_policy(paths: &str) -> SessionPolicy {
        policy(&format!(
            "version = 1\noperation = \"create\"\n[session]\n\n[[rules]]\nhost = \"github.com\"\nmode = \"intercept\"\nports = [443]\npaths = {paths}\n"
        ))
    }

    fn plaintext_path_policy(paths: &str) -> SessionPolicy {
        policy(&format!(
            "version = 1\noperation = \"create\"\n[session]\n\n[[rules]]\nhost = \"github.com\"\nmode = \"tunnel\"\nports = [80]\npaths = {paths}\n"
        ))
    }

    #[test]
    fn ordinary_http_matches_normalized_exact_hosts_and_ports() {
        let policy = policy_with("github.com", "tunnel", "ports = [80, 443]");
        let cases = [
            ("http://GitHub.com./path", Some("github.com:80"), true),
            ("http://github.com:443/path", Some("github.com:443"), true),
            (
                "http://github.com:8080/path",
                Some("github.com:8080"),
                false,
            ),
            ("http://evilgithub.com/path", Some("evilgithub.com"), false),
            (
                "http://github.com.evil.example/path",
                Some("github.com.evil.example"),
                false,
            ),
            ("http://example.com/path", Some("example.com"), false),
            ("http://127.1/path", Some("127.1"), false),
            ("http://2130706433/path", Some("2130706433"), false),
            ("http://[::1]:80/path", Some("[::1]:80"), false),
        ];

        for (uri, host, expected) in cases {
            assert_eq!(
                policy.authorize(&request("GET", uri, host)).is_ok(),
                expected,
                "authorization for {uri} with Host {host:?}"
            );
        }
    }

    #[test]
    fn omitted_rule_ports_default_to_https_and_request_scheme_ports_are_used() {
        let policy = policy_with("github.com", "tunnel", "");
        assert!(
            policy
                .authorize(&request("GET", "https://github.com/path", None))
                .is_ok()
        );
        assert_eq!(
            policy.authorize(&request("GET", "http://github.com/path", None)),
            Err(AuthorizationError::Denied)
        );
    }

    #[test]
    fn ordinary_http_enforces_exact_and_recursive_intercept_paths() {
        let exact = path_policy("[\"/allowed\"]");
        let exact_cases = [
            ("https://github.com/allowed", true),
            ("https://github.com/%61llowed?ref=main", true),
            ("https://github.com/allowed?ref=main", true),
            ("https://github.com/allowed/", false),
            ("https://github.com/allowed/child", false),
            ("https://github.com/allowedness", false),
            ("https://github.com/Allowed", false),
            ("https://github.com/private", false),
            ("https://github.com/allowed%2fprivate", false),
            ("https://github.com/allowed%5cprivate", false),
            ("https://github.com/allowed%252fprivate", false),
            ("https://github.com/%2e%2e/private", false),
            ("https://github.com/../private", false),
            ("https://github.com//allowed", false),
            ("https://github.com/allowed%2", false),
        ];

        for (uri, expected) in exact_cases {
            assert_eq!(
                exact.authorize(&request("GET", uri, None)).is_ok(),
                expected,
                "exact path authorization for {uri}"
            );
        }

        let recursive = path_policy("[\"/allowed/**\"]");
        let recursive_cases = [
            ("https://github.com/allowed/", true),
            ("https://github.com/allowed/child", true),
            ("https://github.com/allowed/child/grandchild", true),
            ("https://github.com/allowed", false),
            ("https://github.com/allowedness/child", false),
            ("https://github.com/private", false),
        ];

        for (uri, expected) in recursive_cases {
            assert_eq!(
                recursive.authorize(&request("GET", uri, None)).is_ok(),
                expected,
                "recursive path authorization for {uri}"
            );
        }

        let plaintext = plaintext_path_policy("[\"/allowed\"]");
        for (uri, expected) in [
            ("http://github.com/allowed", true),
            ("http://github.com/allowed?ref=main", true),
            ("http://github.com/private", false),
        ] {
            assert_eq!(
                plaintext.authorize(&request("GET", uri, None)).is_ok(),
                expected,
                "plaintext HTTP path authorization for {uri}"
            );
        }
        assert_eq!(
            plaintext.authorize(&request("CONNECT", "github.com:80", None)),
            Err(AuthorizationError::Denied),
            "a tunnel rule with path restrictions must not bypass them with CONNECT"
        );
    }

    #[test]
    fn cladding_repository_rules_allow_only_the_exact_repository_and_descendants() {
        let policy = policy(
            "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"api.github.com\"\nmode = \"intercept\"\nports = [443]\npaths = [\"/repos/dstoc/cladding\", \"/repos/dstoc/cladding/**\"]\n",
        );
        for (path, expected) in [
            ("/repos/dstoc/cladding", true),
            ("/repos/dstoc/cladding/", true),
            ("/repos/dstoc/cladding/issues", true),
            ("/repos/dstoc/other", false),
            ("/repos/dstoc/cladding-extra", false),
            ("/repos/dstoc/cladding%2fprivate", false),
        ] {
            let uri = format!("https://api.github.com{path}");
            assert_eq!(
                policy.authorize(&request("GET", &uri, None)).is_ok(),
                expected,
                "repository path authorization for {uri}"
            );
        }
    }

    #[test]
    fn forwards_the_same_canonical_path_that_the_policy_authorized() {
        let policy = path_policy("[\"/allowed\"]");
        let mut allowed = request("GET", "https://github.com/%61llowed?ref=main", None);
        assert_eq!(
            policy.authorize_request(&mut allowed),
            Ok(RuleMode::Intercept)
        );
        assert_eq!(allowed.uri().path(), "/allowed");
        assert_eq!(allowed.uri().query(), Some("ref=main"));

        let mut missing_path = request("GET", "https://github.com", None);
        let root = path_policy("[\"/\"]");
        assert_eq!(
            root.authorize_request(&mut missing_path),
            Ok(RuleMode::Intercept)
        );
        assert_eq!(missing_path.uri().path(), "/");
    }

    #[test]
    fn rejects_plaintext_requests_for_rules_with_credential_injection() {
        let policy = policy(
            "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"github.com\"\nmode = \"intercept\"\nports = [443]\npaths = [\"/allowed\"]\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"api-token\"\nformat = \"bearer\"\n",
        );
        assert_eq!(
            policy.authorize(&request("GET", "http://github.com:443/allowed", None)),
            Err(AuthorizationError::Denied),
            "HTTP must not use a rule that has credential injection, regardless of port"
        );
    }

    #[test]
    fn path_restricted_connect_is_authorized_only_for_interception() {
        let policy = path_policy("[\"/allowed\"]");
        let connect = request("CONNECT", "github.com:443", None);

        assert_eq!(policy.authorize(&connect), Ok(RuleMode::Intercept));
        assert!(
            PolicyHandler::new(RuntimeId::new("test"), Arc::new(policy))
                .connect_should_intercept(&connect)
        );
    }

    #[test]
    fn connect_checks_exact_destination_and_selects_rule_mode() {
        let intercept = policy_with("github.com", "intercept", "ports = [443]");
        let tunnel = policy_with("github.com", "tunnel", "ports = [443]");
        let allowed = request("CONNECT", "github.com:443", Some("github.com:443"));
        assert_eq!(intercept.authorize(&allowed), Ok(RuleMode::Intercept));
        assert_eq!(tunnel.authorize(&allowed), Ok(RuleMode::Tunnel));

        for target in [
            "evilgithub.com:443",
            "github.com.evil.example:443",
            "github.com:444",
            "github.com",
            "user@github.com:443",
            "127.0.0.1:443",
            "[::1]:443",
        ] {
            assert!(
                intercept
                    .authorize(&request("CONNECT", target, None))
                    .is_err(),
                "CONNECT to {target} must be rejected"
            );
        }
    }

    #[test]
    fn host_header_mismatch_and_duplicates_are_rejected() {
        let policy = policy_with("github.com", "intercept", "ports = [443]");
        let mismatch = request("GET", "https://github.com/path", Some("evilgithub.com"));
        assert_eq!(
            policy.authorize(&mismatch),
            Err(AuthorizationError::InvalidAuthority)
        );

        let mut duplicate = request("GET", "https://github.com/path", Some("github.com"));
        duplicate
            .headers_mut()
            .append(HOST, "github.com".parse().expect("valid header"));
        assert_eq!(
            policy.authorize(&duplicate),
            Err(AuthorizationError::InvalidAuthority)
        );
    }

    #[test]
    fn session_policies_do_not_share_host_or_port_permissions() {
        let first = policy_with("github.com", "intercept", "ports = [443]");
        let second = policy_with("example.org", "tunnel", "ports = [8443]");
        let github = request("CONNECT", "github.com:443", None);
        let example = request("CONNECT", "example.org:8443", None);

        assert_eq!(first.authorize(&github), Ok(RuleMode::Intercept));
        assert_eq!(second.authorize(&github), Err(AuthorizationError::Denied));
        assert_eq!(second.authorize(&example), Ok(RuleMode::Tunnel));
        assert_eq!(first.authorize(&example), Err(AuthorizationError::Denied));
    }

    #[test]
    fn connect_interception_follows_the_compiled_rule_mode() {
        let intercept = PolicyHandler::new(
            RuntimeId::new("test"),
            Arc::new(policy_with("github.com", "intercept", "")),
        );
        let tunnel = PolicyHandler::new(
            RuntimeId::new("test"),
            Arc::new(policy_with("github.com", "tunnel", "")),
        );
        let request = request("CONNECT", "github.com:443", None);

        assert!(intercept.connect_should_intercept(&request));
        assert!(!tunnel.connect_should_intercept(&request));
    }

    #[test]
    fn intercepted_tls_requires_matching_sni_and_intercept_policy() {
        let intercept = policy_with("github.com", "intercept", "ports = [443]");
        let tunnel = policy_with("github.com", "tunnel", "ports = [443]");
        let authority = "github.com:443".parse::<Authority>().unwrap();

        assert!(intercept.permits_tls_interception(&authority, Some("github.com")));
        assert!(intercept.permits_tls_interception(&authority, Some("GITHUB.COM.")));
        assert!(!intercept.permits_tls_interception(&authority, None));
        assert!(!intercept.permits_tls_interception(&authority, Some("other.example")));
        assert!(!tunnel.permits_tls_interception(&authority, Some("github.com")));
    }

    #[test]
    fn inner_http_authority_stays_bound_for_http1_and_http2() {
        let policy = policy(
            "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"github.com\"\nmode = \"intercept\"\nports = [443]\n\n[[rules]]\nhost = \"example.org\"\nmode = \"intercept\"\nports = [443]\n",
        );
        let connect_authority = "github.com:443".parse::<Authority>().unwrap();

        let mut http1 = Request::builder()
            .method("GET")
            .version(Version::HTTP_11)
            .uri("https://github.com/allowed")
            .header(HOST, "github.com")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            policy.authorize_inner_request(&mut http1, &connect_authority),
            Ok(RuleMode::Intercept)
        );

        let mut http2 = Request::builder()
            .method("GET")
            .version(Version::HTTP_2)
            .uri("https://github.com/allowed")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            policy.authorize_inner_request(&mut http2, &connect_authority),
            Ok(RuleMode::Intercept),
            "HTTP/2 :authority must match the CONNECT destination"
        );

        let mut missing_http1_host = Request::builder()
            .method("GET")
            .version(Version::HTTP_11)
            .uri("https://github.com/allowed")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            policy.authorize_inner_request(&mut missing_http1_host, &connect_authority),
            Err(AuthorizationError::InvalidAuthority)
        );

        let mut conflicting_http1 = Request::builder()
            .method("GET")
            .version(Version::HTTP_11)
            .uri("https://github.com/allowed")
            .header(HOST, "example.org")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            policy.authorize_inner_request(&mut conflicting_http1, &connect_authority),
            Err(AuthorizationError::InvalidAuthority)
        );

        let mut conflicting_http2 = Request::builder()
            .method("GET")
            .version(Version::HTTP_2)
            .uri("https://example.org/allowed")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            policy.authorize_inner_request(&mut conflicting_http2, &connect_authority),
            Err(AuthorizationError::InvalidAuthority),
            "HTTP/2 :authority must not change the CONNECT destination"
        );
    }

    #[test]
    fn handler_rejects_unauthorized_host_or_path_before_returning_it_upstream() {
        let handler = PolicyHandler::new(
            RuntimeId::new("test"),
            Arc::new(path_policy("[\"/allowed\"]")),
        );

        for (uri, host) in [
            ("http://example.net:8080/", Some("example.net:8080")),
            ("https://github.com/private", None),
        ] {
            let response = handler.handle_policy_request(request("GET", uri, host));
            assert!(
                matches!(response, RequestOrResponse::Response(response) if response.status() == 403),
                "handler must reject {uri} before returning it upstream"
            );
        }
    }
}
