use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
};

use crate::{config::ControlRequest, secrets::SecretStore};

use super::support::session_manager;
use crate::control::session::SessionError;

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
        "version = 2\noperation = \"create\"\n\n[session]\nversion = 2\npersistent = true\n\n[session.rules.\"limit.example.test\"]\nmode = \"tunnel\"",
    )
    .expect("test request should parse");
    let ControlRequest::Create { session, .. } = request else {
        panic!("test request should create a session");
    };
    let secret_store = SecretStore::new(directory.path().to_path_buf(), uid, Default::default());
    let first_secrets = secret_store
        .resolve(&session)
        .expect("empty secret requirements should resolve");
    let second_secrets = secret_store
        .resolve(&session)
        .expect("empty secret requirements should resolve");

    let (first, second) = tokio::join!(
        manager.create(session.clone(), first_secrets, None),
        manager.create(session.clone(), second_secrets, None),
    );
    assert_eq!(u8::from(first.is_ok()) + u8::from(second.is_ok()), 1);
    let created = match (first, second) {
        (Ok(created), Err(SessionError::AtCapacity))
        | (Err(SessionError::AtCapacity), Ok(created)) => created,
        _ => panic!("one create should reserve the only session slot"),
    };
    assert_eq!(manager.list().await.len(), 1);
    assert!(matches!(
        manager
            .create(
                session.clone(),
                secret_store
                    .resolve(&session)
                    .expect("empty secret requirements should resolve"),
                None,
            )
            .await,
        Err(SessionError::AtCapacity)
    ));
    assert!(manager.stop(&created.info.id).await);
}

#[tokio::test]
async fn socket_directory_registry_is_scoped_to_each_session_manager() {
    let root = tempfile::tempdir().expect("temporary directory should be created");
    let first_directory = root.path().join("first-daemon");
    let second_directory = root.path().join("second-daemon");
    fs::create_dir(&first_directory).expect("first daemon directory should be created");
    fs::create_dir(&second_directory).expect("second daemon directory should be created");

    let first_manager = session_manager(&first_directory, 4);
    let second_manager = session_manager(&second_directory, 2);
    assert!(!std::sync::Arc::ptr_eq(
        &first_manager.socket_directories,
        &second_manager.socket_directories
    ));

    let request = ControlRequest::from_toml(
        "version = 2\noperation = \"create\"\n\n[session]\nversion = 2\npersistent = true\n\n[session.rules.\"directory.example.test\"]\nmode = \"tunnel\"",
    )
    .expect("test request should parse");
    let ControlRequest::Create { session, .. } = request else {
        panic!("test request should create a session");
    };
    let mut first = session.clone();
    first.socket_name = Some("nested/first.sock".to_owned());
    let mut second = session.clone();
    second.socket_name = Some("nested/second.sock".to_owned());
    let mut independent = session;
    independent.socket_name = Some("nested/independent.sock".to_owned());

    let (first, second, independent) = tokio::join!(
        first_manager.create(first, Default::default(), None),
        first_manager.create(second, Default::default(), None),
        second_manager.create(independent, Default::default(), None),
    );
    let first = first.expect("first session should start");
    let second = second.expect("second session should start");
    let independent = independent.expect("independent session should start");
    let first_nested = first_directory.join("nested");
    let second_nested = second_directory.join("nested");
    assert!(first_nested.is_dir());
    assert!(second_nested.is_dir());

    assert!(first_manager.stop(&first.info.id).await);
    assert!(
        first_nested.is_dir(),
        "the sibling lease keeps the parent alive"
    );
    assert!(
        second_nested.is_dir(),
        "the other manager keeps its own parent"
    );

    assert!(first_manager.stop(&second.info.id).await);
    assert!(
        !first_nested.exists(),
        "the last same-manager lease removes the parent"
    );
    assert!(
        second_nested.is_dir(),
        "cleanup must not touch another manager"
    );

    assert!(second_manager.stop(&independent.info.id).await);
    assert!(!second_nested.exists());
}
