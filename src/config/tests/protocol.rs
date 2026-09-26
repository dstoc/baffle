use crate::config::{ControlRequest, MAX_SESSION_CONFIG_NAME_BYTES, PROTOCOL_VERSION};

#[test]
fn parses_stop_and_list_requests_with_an_explicit_protocol_version() {
    assert_eq!(
        ControlRequest::from_toml("version = 1\noperation = \"stop\"\nsession_id = \"s_123\"\n")
            .expect("stop should parse"),
        ControlRequest::Stop {
            version: PROTOCOL_VERSION,
            session_id: "s_123".into(),
        }
    );
    assert_eq!(
        ControlRequest::from_toml("version = 1\noperation = \"list\"\n")
            .expect("list should parse"),
        ControlRequest::List {
            version: PROTOCOL_VERSION,
        }
    );
    assert_eq!(
        ControlRequest::from_toml("version = 1\noperation = \"reload\"\nsession_id = \"s_123\"\n")
            .expect("reload should parse"),
        ControlRequest::Reload {
            version: PROTOCOL_VERSION,
            session_id: "s_123".into(),
        }
    );
    assert_eq!(
        ControlRequest::from_toml("version = 1\noperation = \"reload_all\"\n")
            .expect("reload_all should parse"),
        ControlRequest::ReloadAll {
            version: PROTOCOL_VERSION,
        }
    );
    assert!(
        ControlRequest::from_toml("version = 1\noperation = \"reload\"\nsession_id = \"../bad\"\n")
            .is_err()
    );
}

#[test]
fn validates_nested_session_config_names_and_rejects_path_forms() {
    assert_eq!(
        ControlRequest::from_toml(
            "version = 1\noperation = \"create_from_file\"\nname = \"cladding/github.toml\"\n"
        )
        .expect("nested session config path should parse"),
        ControlRequest::CreateFromFile {
            version: PROTOCOL_VERSION,
            name: "cladding/github.toml".into(),
        }
    );
    for name in [
        "",
        "/etc/passwd.toml",
        "../outside.toml",
        "cladding/../outside.toml",
        "cladding//github.toml",
        "cladding/github.toml/",
        "cladding\\github.toml",
        "C:/outside.toml",
        "cladding/config.txt",
    ] {
        let input = format!("version = 1\noperation = \"create_from_file\"\nname = {name:?}\n");
        assert!(
            ControlRequest::from_toml(&input).is_err(),
            "invalid session config name {name:?} must fail"
        );
    }
    let too_long = "a".repeat(MAX_SESSION_CONFIG_NAME_BYTES + 1);
    let input =
        format!("version = 1\noperation = \"create_from_file\"\nname = \"{too_long}.toml\"\n");
    assert!(ControlRequest::from_toml(&input).is_err());
}

#[test]
fn validates_protocol_versions_and_session_ids() {
    assert!(ControlRequest::from_toml("operation = \"list\"\n").is_err());
    assert!(ControlRequest::from_toml("version = 2\noperation = \"list\"\n").is_err());
    assert!(
        ControlRequest::from_toml("version = 1\noperation = \"stop\"\nsession_id = \"../bad\"\n")
            .is_err()
    );
}
