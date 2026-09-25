#![cfg(target_os = "linux")]

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::Shutdown,
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::UnixStream,
    },
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use hudsucker::rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use serde_json::Value;
use tempfile::TempDir;

struct DaemonProcess {
    child: Child,
    _directory: TempDir,
    socket: PathBuf,
    socket_dir: PathBuf,
}

impl Drop for DaemonProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn control_listener_handles_requests_and_rejects_bad_connections() {
    let daemon = start_daemon(250);
    let metadata = fs::symlink_metadata(&daemon.socket).expect("control socket should exist");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    let control_dir = daemon.socket.parent().expect("socket should have parent");
    assert_eq!(
        fs::metadata(control_dir)
            .expect("control directory should exist")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    assert!(
        request(&daemon.socket, "version = 1\noperation = \"list\"\n")["ok"]
            .as_bool()
            .unwrap()
    );

    let response = request(&daemon.socket, "version = 2\noperation = \"list\"\n");
    assert_eq!(response["error"]["code"], "unsupported_version");
    let response = request(&daemon.socket, "version = 1\noperation = \"unknown\"\n");
    assert_eq!(response["error"]["code"], "invalid_request");

    let mut oversized = UnixStream::connect(&daemon.socket).expect("client should connect");
    oversized
        .write_all(&((256_u32 * 1024 + 1).to_be_bytes()))
        .expect("length should be written");
    assert_eq!(
        read_response(&mut oversized)["error"]["code"],
        "frame_too_large"
    );

    let mut partial = UnixStream::connect(&daemon.socket).expect("client should connect");
    partial
        .write_all(&[0, 0])
        .expect("partial header should be written");
    partial
        .shutdown(Shutdown::Write)
        .expect("client write half should close");
    assert_eq!(
        read_response(&mut partial)["error"]["code"],
        "truncated_frame"
    );

    let mut stalled = UnixStream::connect(&daemon.socket).expect("client should connect");
    stalled
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout should be set");
    stalled
        .write_all(&[0])
        .expect("partial header should be written");
    assert_eq!(read_response(&mut stalled)["error"]["code"], "read_timeout");

    assert!(
        request(&daemon.socket, "version = 1\noperation = \"list\"\n")["ok"]
            .as_bool()
            .unwrap()
    );

    let mut multiple = UnixStream::connect(&daemon.socket).expect("client should connect");
    multiple
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout should be set");
    let frame = encode_frame(b"version = 1\noperation = \"list\"\n");
    multiple
        .write_all(&[frame.as_slice(), frame.as_slice()].concat())
        .expect("two requests should be written");
    assert_eq!(read_response(&mut multiple)["ok"], true);
    let mut extra = [0];
    assert!(matches!(multiple.read(&mut extra), Ok(0) | Err(_)));

    let (ephemeral_one, created_one) = create_session(&daemon.socket, false, "one.example.test");
    let (ephemeral_two, created_two) = create_session(&daemon.socket, false, "two.example.test");
    let (persistent_creator, created_persistent) =
        create_session(&daemon.socket, true, "persistent.example.test");
    drop(persistent_creator);

    let persistent_id = created_persistent["result"]["id"]
        .as_str()
        .expect("persistent create should return an ID")
        .to_owned();
    let first_path = PathBuf::from(
        created_one["result"]["socket"]
            .as_str()
            .expect("first create should return a socket"),
    );
    let second_path = PathBuf::from(
        created_two["result"]["socket"]
            .as_str()
            .expect("second create should return a socket"),
    );
    let persistent_path = PathBuf::from(
        created_persistent["result"]["socket"]
            .as_str()
            .expect("persistent create should return a socket"),
    );
    let listed = list_sessions(&daemon.socket);
    assert_eq!(listed.len(), 3, "three sessions should run concurrently");
    assert!(listed.iter().all(|session| session["state"] == "running"));
    for session in &listed {
        let keys = session
            .as_object()
            .expect("list entries should be objects")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert_eq!(keys, ["id", "persistent", "socket", "state"]);
    }
    let list_json = serde_json::to_string(&listed).expect("list should serialize");
    assert!(
        !list_json.contains("example.test"),
        "list must not expose policy hosts"
    );

    drop(ephemeral_one);
    wait_for_session_count(&daemon.socket, 2);
    assert!(
        !first_path.exists(),
        "closing the first lease removes its socket"
    );
    assert!(
        second_path.exists(),
        "closing one lease must preserve the second socket"
    );
    assert!(
        persistent_path.exists(),
        "persistent socket survives creator disconnect"
    );
    assert_proxy_available(&second_path);
    assert_proxy_available(&persistent_path);

    let stopped = request(
        &daemon.socket,
        &format!("version = 1\noperation = \"stop\"\nsession_id = \"{persistent_id}\"\n"),
    );
    assert_eq!(stopped["result"]["stopped"], true);
    assert!(
        !persistent_path.exists(),
        "explicit stop removes the persistent socket"
    );
    wait_for_session_count(&daemon.socket, 1);
    assert_proxy_available(&second_path);

    drop(ephemeral_two);
    wait_for_session_count(&daemon.socket, 0);
    assert!(
        !second_path.exists(),
        "closing the remaining lease removes its socket"
    );
}

#[test]
fn failed_session_creation_leaves_no_socket_or_registry_entry() {
    // Unix-domain socket paths are limited to 107 bytes on Linux. This makes
    // runtime startup fail after the loopback listener is provisioned but
    // before a session can be registered or its socket can be created.
    let daemon = start_daemon_with_socket_dir(250, &"s".repeat(80));
    let failed = request(
        &daemon.socket,
        "version = 1\noperation = \"create\"\n\n[session]\npersistent = true\n\n[[rules]]\nhost = \"rollback.example.test\"\nmode = \"tunnel\"\n",
    );
    assert_eq!(failed["error"]["code"], "internal_error");
    assert!(list_sessions(&daemon.socket).is_empty());
    assert_eq!(
        fs::read_dir(&daemon.socket_dir)
            .expect("session socket directory should exist")
            .count(),
        0,
        "failed startup must not leave a session socket"
    );
}

#[test]
fn daemon_reclaims_stale_control_and_session_sockets_after_crash() {
    let mut daemon = start_daemon(250);
    let (_creator, created) = create_session(&daemon.socket, true, "crash.example.test");
    let stale_proxy_path = PathBuf::from(
        created["result"]["socket"]
            .as_str()
            .expect("persistent session should return its socket path"),
    );
    let competing_start = Command::new(env!("CARGO_BIN_EXE_baffle"))
        .arg("daemon")
        .arg("--config")
        .arg(daemon._directory.path().join("daemon.toml"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("a competing daemon process should start");
    assert!(
        !competing_start.success(),
        "a second daemon must not remove an active control socket"
    );
    assert_eq!(
        request(&daemon.socket, "version = 1\noperation = \"list\"\n")["ok"],
        true,
        "the active daemon should remain available"
    );
    daemon.child.kill().expect("daemon should be killable");
    daemon
        .child
        .wait()
        .expect("crashed daemon should be reaped");
    assert!(
        daemon.socket.exists(),
        "SIGKILL should leave the control socket"
    );
    assert!(
        stale_proxy_path.exists(),
        "SIGKILL should leave the session socket"
    );

    let config_path = daemon._directory.path().join("daemon.toml");
    daemon.child = Command::new(env!("CARGO_BIN_EXE_baffle"))
        .arg("daemon")
        .arg("--config")
        .arg(config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("daemon should restart with the same paths");

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = daemon
            .child
            .try_wait()
            .expect("restarted daemon status should be readable")
        {
            panic!("daemon failed to reclaim stale sockets: {status}");
        }
        if UnixStream::connect(&daemon.socket).is_ok() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "daemon should bind its control socket"
        );
        thread::sleep(Duration::from_millis(10));
    }

    assert!(
        !stale_proxy_path.exists(),
        "restart should remove the stale session socket"
    );
    assert_eq!(
        fs::read_dir(&daemon.socket_dir)
            .expect("session socket directory should remain available")
            .count(),
        0,
        "restart should leave no stale session socket entries"
    );
    assert_eq!(
        request(&daemon.socket, "version = 1\noperation = \"list\"\n")["ok"],
        true
    );
}

fn start_daemon(read_timeout_ms: u64) -> DaemonProcess {
    start_daemon_with_socket_dir(read_timeout_ms, "proxies")
}

fn start_daemon_with_socket_dir(read_timeout_ms: u64, socket_dir_name: &str) -> DaemonProcess {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let socket = directory.path().join("run/control.sock");
    let socket_dir = directory.path().join(socket_dir_name);
    let config_path = directory.path().join("daemon.toml");
    let (certificate_path, private_key_path) = write_test_ca(directory.path());
    let trusted_uid = fs::metadata(directory.path())
        .expect("temporary directory should have metadata")
        .uid();
    let config = format!(
        "[daemon]\ncontrol_socket = \"{}\"\nsocket_dir = \"{}\"\ntrusted_operator_uid = {trusted_uid}\ncontrol_read_timeout_ms = {read_timeout_ms}\n\n[ca]\ncertificate = \"{}\"\nprivate_key = \"{}\"\n\n[secrets]\ndirectory = \"unused-secrets\"\n",
        socket.display(),
        socket_dir.display(),
        certificate_path.display(),
        private_key_path.display(),
    );
    fs::write(&config_path, config).expect("daemon config should be written");
    let child = Command::new(env!("CARGO_BIN_EXE_baffle"))
        .arg("daemon")
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("daemon should start");
    let mut daemon = DaemonProcess {
        child,
        _directory: directory,
        socket,
        socket_dir,
    };

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if daemon.socket.exists() {
            break;
        }
        if let Some(status) = daemon
            .child
            .try_wait()
            .expect("daemon status should be readable")
        {
            panic!("daemon exited before binding control socket: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "daemon should bind control socket"
        );
        thread::sleep(Duration::from_millis(10));
    }
    daemon
}

fn create_session(control_socket: &PathBuf, persistent: bool, host: &str) -> (UnixStream, Value) {
    let mut control = UnixStream::connect(control_socket).expect("client should connect");
    control
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout should be set");
    let body = format!(
        "version = 1\noperation = \"create\"\n\n[session]\npersistent = {persistent}\n\n[[rules]]\nhost = \"{host}\"\nmode = \"tunnel\"\n"
    );
    write_frame(&mut control, body.as_bytes());
    let response = read_response(&mut control);
    assert_eq!(response["ok"], true);
    (control, response)
}

fn list_sessions(control_socket: &PathBuf) -> Vec<Value> {
    request(control_socket, "version = 1\noperation = \"list\"\n")["result"]["sessions"]
        .as_array()
        .expect("list should return a session array")
        .clone()
}

fn wait_for_session_count(control_socket: &PathBuf, expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if list_sessions(control_socket).len() == expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "session count should reach {expected}"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn assert_proxy_available(socket_path: &PathBuf) {
    let mut stream = UnixStream::connect(socket_path).expect("proxy data socket should accept");
    stream
        .write_all(
            b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
        )
        .expect("proxy request should be sent");
    let mut reader = BufReader::new(stream);
    let mut status = String::new();
    reader
        .read_line(&mut status)
        .expect("proxy response should be readable");
    assert!(
        status.starts_with("HTTP/1.1 403") || status.starts_with("HTTP/1.0 403"),
        "running deny-all proxy should respond through its own bridge: {status:?}"
    );
}

fn write_test_ca(directory: &std::path::Path) -> (PathBuf, PathBuf) {
    let key_pair = KeyPair::generate().expect("CA key should be generated");
    let mut parameters = CertificateParams::default();
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let certificate = parameters
        .self_signed(&key_pair)
        .expect("CA certificate should be generated");

    let certificate_path = directory.join("ca.pem");
    let private_key_path = directory.join("ca-key.pem");
    fs::write(&certificate_path, certificate.pem()).expect("CA certificate should be saved");
    fs::write(&private_key_path, key_pair.serialize_pem()).expect("CA key should be saved");
    fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600))
        .expect("CA key permissions should be restricted");
    (certificate_path, private_key_path)
}

fn request(socket: &PathBuf, request: &str) -> Value {
    let mut stream = UnixStream::connect(socket).expect("client should connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout should be set");
    write_frame(&mut stream, request.as_bytes());
    read_response(&mut stream)
}

fn write_frame(stream: &mut UnixStream, payload: &[u8]) {
    let length = u32::try_from(payload.len()).expect("test frame should fit in u32");
    stream
        .write_all(&length.to_be_bytes())
        .expect("frame header should be written");
    stream
        .write_all(payload)
        .expect("frame payload should be written");
}

fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).expect("test frame should fit in u32");
    [length.to_be_bytes().as_slice(), payload].concat()
}

fn read_response(stream: &mut UnixStream) -> Value {
    let mut header = [0; 4];
    stream
        .read_exact(&mut header)
        .expect("response header should be complete");
    let length = u32::from_be_bytes(header) as usize;
    assert!(length <= 256 * 1024, "response should fit expected limit");
    let mut body = vec![0; length];
    stream
        .read_exact(&mut body)
        .expect("response body should be complete");
    serde_json::from_slice(&body).expect("response should be valid JSON")
}
