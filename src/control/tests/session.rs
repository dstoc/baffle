use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
};

use crate::{config::ControlRequest, secrets::SecretStore};

use super::super::test_support::session_manager;
use super::SessionError;

#[tokio::test]
async fn concurrent_provisioning_reservations_enforce_the_session_limit() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("test directory should be private");
    let uid = fs::metadata(directory.path())
        .expect("test directory should have metadata")
        .uid();
    let manager = session_manager(directory.path(), 1);
    let request = ControlRequest::from_toml(
        "version = 1\noperation = \"create\"\n\n[session]\npersistent = true\n\n[[rules]]\nhost = \"limit.example.test\"\nmode = \"tunnel\"\n",
    )
    .expect("test request should parse");
    let ControlRequest::Create { session, .. } = request else {
        panic!("test request should create a session");
    };
    let secret_store = SecretStore::new(directory.path().to_path_buf(), uid, Default::default());
    let first_secrets = secret_store
        .resolve(uid, &session)
        .expect("empty secret requirements should resolve");
    let second_secrets = secret_store
        .resolve(uid, &session)
        .expect("empty secret requirements should resolve");

    let (first, second) = tokio::join!(
        manager.create(uid, session.clone(), first_secrets, None),
        manager.create(uid, session.clone(), second_secrets, None),
    );
    assert_eq!(u8::from(first.is_ok()) + u8::from(second.is_ok()), 1);
    let created = match (first, second) {
        (Ok(created), Err(SessionError::AtCapacity))
        | (Err(SessionError::AtCapacity), Ok(created)) => created,
        _ => panic!("one create should reserve the only session slot"),
    };
    assert_eq!(manager.list(uid).await.len(), 1);
    assert!(matches!(
        manager
            .create(
                uid,
                session.clone(),
                secret_store
                    .resolve(uid, &session)
                    .expect("empty secret requirements should resolve"),
                None,
            )
            .await,
        Err(super::SessionError::AtCapacity)
    ));
    assert!(manager.stop(&created.id, uid).await);
}
