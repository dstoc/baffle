pub(crate) use baffle_client::normalize_dns_name;

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
