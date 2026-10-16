use std::net::IpAddr;

use url::Host;

/// Normalize and validate an exact ASCII DNS hostname.
///
/// A final dot is removed and ASCII letters are converted to lowercase. IP
/// literals, wildcards, invalid labels, and names longer than 253 bytes are
/// rejected.
pub(crate) fn normalize_dns_name(input: &str) -> Result<String, &'static str> {
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

    // The URL host parser also rejects non-canonical IPv4 forms such as
    // 127.1, octal components, and a single integer. Parsing is local and
    // does not perform DNS resolution.
    match Host::parse(host) {
        Ok(Host::Domain(domain)) => Ok(domain),
        Ok(Host::Ipv4(_) | Host::Ipv6(_)) => {
            Err("must be an exact DNS hostname, not an IP address or wildcard")
        }
        Err(_) => Err("must be a valid exact DNS hostname"),
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_dns_name;

    #[test]
    fn normalizes_valid_dns_names() {
        assert_eq!(normalize_dns_name("EXAMPLE.COM."), Ok("example.com".into()));
        assert_eq!(normalize_dns_name("localhost"), Ok("localhost".into()));

        let longest_valid_name = [63, 63, 63, 61]
            .into_iter()
            .map(|length| "a".repeat(length))
            .collect::<Vec<_>>()
            .join(".");
        assert_eq!(longest_valid_name.len(), 253);
        assert_eq!(
            normalize_dns_name(&longest_valid_name),
            Ok(longest_valid_name)
        );
    }

    #[test]
    fn rejects_invalid_dns_names() {
        let too_long_name = format!("{}a", "a".repeat(253));
        let too_long_label = "a".repeat(64);

        for invalid in [
            "",
            "*.example.com",
            "127.0.0.1",
            "127.1",
            "2130706433",
            "::1",
            "bad..example",
            "-bad.example",
            "bad-.example",
            "bad_name.example",
            "café.example",
            &too_long_name,
            &too_long_label,
        ] {
            assert!(
                normalize_dns_name(invalid).is_err(),
                "expected {invalid:?} to be rejected"
            );
        }
    }
}
