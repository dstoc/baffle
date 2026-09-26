use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    sync::Arc,
    time::Duration,
};

use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
};

use crate::{config::SessionCreateMode, secrets::SecretStore};

use super::super::test_support::session_manager;
use super::{ControlState, handle_connection};

fn state(directory: &std::path::Path, uid: u32, allowed: &[&str]) -> ControlState {
    ControlState {
        trusted_operator_uid: uid,
        create_mode: SessionCreateMode::Inline,
        read_timeout: Duration::from_secs(1),
        secret_store: SecretStore::new(
            directory.to_path_buf(),
            uid,
            allowed.iter().map(|name| (*name).to_owned()).collect(),
        ),
        sessions: session_manager(directory, 1),
        provisioning_slots: Arc::new(Semaphore::new(1)),
        session_configs: None,
    }
}

async fn connect_handler(
    listener: &UnixListener,
    state: Arc<ControlState>,
) -> (UnixStream, tokio::task::JoinHandle<()>) {
    let client = UnixStream::connect(listener.local_addr().unwrap().as_pathname().unwrap())
        .await
        .expect("test client should connect");
    let (server, _) = listener
        .accept()
        .await
        .expect("server should accept client");
    let task = tokio::spawn(async move {
        handle_connection(server, state).await;
    });
    (client, task)
}

async fn write_request(client: &mut UnixStream, body: &str) {
    client
        .write_all(&(body.len() as u32).to_be_bytes())
        .await
        .expect("frame header should be written");
    client
        .write_all(body.as_bytes())
        .await
        .expect("frame payload should be written");
}

async fn read_response(client: &mut UnixStream) -> (Vec<u8>, Value) {
    let mut header = [0; 4];
    client
        .read_exact(&mut header)
        .await
        .expect("response header should be complete");
    let mut body = vec![0; u32::from_be_bytes(header) as usize];
    client
        .read_exact(&mut body)
        .await
        .expect("response body should be complete");
    let response = serde_json::from_slice(&body).expect("response should be JSON");
    (body, response)
}

#[tokio::test]
async fn denies_a_peer_whose_uid_differs_from_the_configured_operator() {
    let directory = tempfile::tempdir().expect("test directory should be created");
    let socket = directory.path().join("auth.sock");
    let listener = UnixListener::bind(&socket).expect("test socket should bind");
    let mut client = UnixStream::connect(&socket)
        .await
        .expect("test client should connect");
    let (server, _) = listener
        .accept()
        .await
        .expect("server should accept client");
    let peer_uid = server
        .peer_cred()
        .expect("peer credentials should be available")
        .uid();
    let state = Arc::new(ControlState {
        trusted_operator_uid: peer_uid.wrapping_add(1),
        create_mode: SessionCreateMode::Inline,
        read_timeout: Duration::from_secs(1),
        secret_store: SecretStore::new(
            directory.path().to_path_buf(),
            peer_uid.wrapping_add(1),
            Default::default(),
        ),
        sessions: session_manager(directory.path(), 1),
        provisioning_slots: Arc::new(Semaphore::new(1)),
        session_configs: None,
    });
    let task = tokio::spawn(async move {
        handle_connection(server, state).await;
    });

    let request = b"version = 1\noperation = \"list\"\n";
    client
        .write_all(&(request.len() as u32).to_be_bytes())
        .await
        .expect("frame header should be written");
    client
        .write_all(request)
        .await
        .expect("frame payload should be written");
    let mut header = [0; 4];
    client
        .read_exact(&mut header)
        .await
        .expect("error response header should be complete");
    let mut body = vec![0; u32::from_be_bytes(header) as usize];
    client
        .read_exact(&mut body)
        .await
        .expect("error response body should be complete");
    let response: Value = serde_json::from_slice(&body).expect("response should be JSON");
    assert_eq!(response["error"]["code"], "unauthorized");
    task.await.expect("connection handler should finish");
}

#[tokio::test]
async fn refuses_unentitled_secret_before_creating_a_session() {
    let directory = tempfile::tempdir().expect("test directory should be created");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("secret directory should be private");
    let secret_path = directory.path().join("api-token");
    fs::write(&secret_path, "credential-must-not-leak").expect("test secret should be written");
    fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600))
        .expect("test secret should be private");

    let socket = directory.path().join("control.sock");
    let listener = UnixListener::bind(&socket).expect("test socket should bind");
    let uid = fs::metadata(directory.path())
        .expect("test directory should have metadata")
        .uid();
    let control_state = Arc::new(state(directory.path(), uid, &[]));
    let (mut client, task) = connect_handler(&listener, Arc::clone(&control_state)).await;
    let request = "version = 1\noperation = \"create\"\n\n[session]\npersistent = true\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"api-token\"\nformat = \"bearer\"\n";
    write_request(&mut client, request).await;
    let (body, response) = read_response(&mut client).await;

    assert_eq!(response["error"]["code"], "secret_unavailable");
    assert!(!String::from_utf8_lossy(&body).contains("credential-must-not-leak"));
    task.await.expect("control handler should finish");
    assert!(
        control_state.sessions.list(uid).await.is_empty(),
        "unauthorized references must fail before session creation"
    );
}

#[tokio::test]
async fn provisioning_limit_rejects_an_excess_create_request() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let uid = fs::metadata(directory.path())
        .expect("test directory should have metadata")
        .uid();
    let control_state = state(directory.path(), uid, &[]);
    let occupied = control_state
        .provisioning_slots
        .clone()
        .try_acquire_owned()
        .expect("the configured single provisioning slot should be available");
    let control_state = Arc::new(control_state);
    let socket = directory.path().join("provisioning.sock");
    let listener = UnixListener::bind(&socket).expect("test socket should bind");
    let (mut client, task) = connect_handler(&listener, Arc::clone(&control_state)).await;
    write_request(
        &mut client,
        "version = 1\noperation = \"create\"\n\n[session]\npersistent = true\n\n[[rules]]\nhost = \"busy.example.test\"\nmode = \"tunnel\"\n",
    )
    .await;
    let (_, response) = read_response(&mut client).await;
    assert_eq!(response["error"]["code"], "busy");
    assert!(control_state.sessions.list(uid).await.is_empty());
    drop(occupied);
    task.await.expect("control handler should finish");
}

#[tokio::test]
async fn authorized_create_keeps_secret_private_from_control_responses() {
    let directory = tempfile::tempdir().expect("test directory should be created");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("secret directory should be private");
    let secret_path = directory.path().join("api-token");
    fs::write(&secret_path, "credential-must-not-leak").expect("test secret should be written");
    fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600))
        .expect("test secret should be private");
    let uid = fs::metadata(directory.path())
        .expect("test directory should have metadata")
        .uid();
    let state = Arc::new(state(directory.path(), uid, &["api-token"]));
    let socket = directory.path().join("control.sock");
    let listener = UnixListener::bind(&socket).expect("test socket should bind");
    let (mut client, task) = connect_handler(&listener, Arc::clone(&state)).await;
    let request = "version = 1\noperation = \"create\"\n\n[session]\npersistent = true\n\n[[rules]]\nhost = \"example.com\"\nmode = \"intercept\"\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"api-token\"\nformat = \"bearer\"\n";
    write_request(&mut client, request).await;
    let (body, response) = read_response(&mut client).await;
    task.await.expect("control handler should finish");

    assert!(response["ok"].as_bool().expect("ok should be boolean"));
    assert!(!String::from_utf8_lossy(&body).contains("credential-must-not-leak"));
    let id = response["result"]["id"]
        .as_str()
        .expect("created session should have an id");
    assert!(state.sessions.list(uid.wrapping_add(1)).await.is_empty());
    assert!(!state.sessions.stop(id, uid.wrapping_add(1)).await);
    let registry = state.sessions.registry.lock().await;
    let created = registry
        .sessions
        .get(id)
        .expect("session should be retained");
    assert_eq!(created.owner_uid, uid);
    assert_eq!(created.configuration.rules[0].host, "example.com");
    assert_eq!(
        created
            .secrets
            .get("api-token")
            .expect("session should own its resolved secret")
            .as_str(),
        "credential-must-not-leak"
    );
}
