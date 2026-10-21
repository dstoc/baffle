use super::*;

use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::{
    config::{CredentialMode, HeaderInjection},
    credentials::{CredentialSeed, derive_fake_credential},
    policy::CompiledCredential,
};

fn compiled(
    injection: HeaderInjection,
    mode: CredentialMode,
    fake_value: Option<String>,
) -> CompiledCredential {
    CompiledCredential {
        injection,
        mode,
        fake_value,
    }
}

fn make_request(headers: &[(&str, &str)]) -> rama::http::Request {
    let mut builder = rama::http::Request::builder()
        .method("GET")
        .uri("https://api.example.com/");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder
        .body(rama::http::Body::empty())
        .expect("test request should build")
}

fn header<'a>(request: &'a rama::http::Request, name: &str) -> Option<&'a str> {
    request.headers().get(name)?.to_str().ok()
}

#[test]
fn substitutes_raw_bearer_and_basic_password_values() {
    let seed = CredentialSeed::from_test_bytes([0x11; 32]);
    let raw_fake = derive_fake_credential(&seed, "raw-token");
    let bearer_fake = derive_fake_credential(&seed, "bearer-token");
    let basic_fake = derive_fake_credential(&seed, "basic-token");
    let basic_header = format!(
        "Basic {}",
        STANDARD.encode(format!("git-user:{basic_fake}"))
    );
    let mut request = make_request(&[
        ("X-Raw-Token", &raw_fake),
        ("Authorization", &format!("Bearer {bearer_fake}")),
        ("X-Basic", &basic_header),
    ]);
    let credentials = [
        compiled(
            HeaderInjection::raw("X-Raw-Token", "raw-token"),
            CredentialMode::Substitute,
            Some(raw_fake),
        ),
        compiled(
            HeaderInjection::bearer("Authorization", "bearer-token"),
            CredentialMode::Substitute,
            Some(bearer_fake),
        ),
        compiled(
            HeaderInjection::basic_password("X-Basic", "basic-token", "git-user"),
            CredentialMode::Substitute,
            Some(basic_fake.clone()),
        ),
    ];
    let secrets = ResolvedSecrets::from_values([
        ("raw-token".to_owned(), "raw-real-value".to_owned()),
        ("bearer-token".to_owned(), "bearer-real-value".to_owned()),
        ("basic-token".to_owned(), "basic-real-value".to_owned()),
    ]);

    super::super::http::apply_header_credentials(&mut request, &credentials, &secrets)
        .expect("matching fake values should be substituted");

    assert!(header(&request, "X-Raw-Token") == Some("raw-real-value"));
    assert!(header(&request, "Authorization") == Some("Bearer bearer-real-value"));
    let expected_basic = format!("Basic {}", STANDARD.encode("git-user:basic-real-value"));
    assert!(header(&request, "X-Basic") == Some(expected_basic.as_str()));

    let wrong_user = format!(
        "Basic {}",
        STANDARD.encode(format!("other-user:{basic_fake}"))
    );
    let mut wrong_user_request = make_request(&[("X-Basic", wrong_user.as_str())]);
    super::super::http::apply_header_credentials(
        &mut wrong_user_request,
        std::slice::from_ref(&credentials[2]),
        &secrets,
    )
    .expect("a different Basic username should leave the request unchanged");
    assert!(header(&wrong_user_request, "X-Basic") == Some(wrong_user.as_str()));
}

#[test]
fn missing_and_unrecognized_fake_values_do_not_fall_back_to_injection() {
    let seed = CredentialSeed::from_test_bytes([0x22; 32]);
    let expected_fake = derive_fake_credential(&seed, "api-token");
    let credential = compiled(
        HeaderInjection::bearer("Authorization", "api-token"),
        CredentialMode::Substitute,
        Some(expected_fake),
    );
    let secrets = ResolvedSecrets::from_values([(
        "api-token".to_owned(),
        "real-value-must-not-be-injected".to_owned(),
    )]);
    let mut unrecognized = make_request(&[("Authorization", "Bearer unrelated-value")]);

    super::super::http::apply_header_credentials(
        &mut unrecognized,
        std::slice::from_ref(&credential),
        &secrets,
    )
    .expect("an unrecognized fake should leave the request unchanged");
    assert!(header(&unrecognized, "Authorization") == Some("Bearer unrelated-value"));

    let mut missing = make_request(&[]);
    super::super::http::apply_header_credentials(
        &mut missing,
        std::slice::from_ref(&credential),
        &secrets,
    )
    .expect("a missing fake should leave the request unchanged");
    assert!(header(&missing, "Authorization").is_none());
}

#[test]
fn disabled_mode_does_not_read_or_change_a_credential_header() {
    let fake = "baffle_v1_example";
    let credential = compiled(
        HeaderInjection::raw("X-Token", "api-token"),
        CredentialMode::Disabled,
        None,
    );
    let mut request = make_request(&[("X-Token", fake)]);

    super::super::http::apply_header_credentials(
        &mut request,
        std::slice::from_ref(&credential),
        &ResolvedSecrets::default(),
    )
    .expect("disabled mode should not need a resolved secret");
    assert!(header(&request, "X-Token") == Some(fake));
}

#[test]
fn a_fake_from_another_session_cannot_authorize_substitution() {
    let session_a = CredentialSeed::from_test_bytes([0x31; 32]);
    let session_b = CredentialSeed::from_test_bytes([0x32; 32]);
    let fake_a = derive_fake_credential(&session_a, "api-token");
    let fake_b = derive_fake_credential(&session_b, "api-token");
    assert!(
        fake_a != fake_b,
        "different session seeds must derive different fakes"
    );

    let credential_b = compiled(
        HeaderInjection::bearer("Authorization", "api-token"),
        CredentialMode::Substitute,
        Some(fake_b),
    );
    let secrets =
        ResolvedSecrets::from_values([("api-token".to_owned(), "session-b-real-value".to_owned())]);
    let fake_a_header = format!("Bearer {fake_a}");
    let mut request = make_request(&[("Authorization", fake_a_header.as_str())]);
    super::super::http::apply_header_credentials(
        &mut request,
        std::slice::from_ref(&credential_b),
        &secrets,
    )
    .expect("a different session fake should be ignored");
    assert!(header(&request, "Authorization") == Some(fake_a_header.as_str()));
}
