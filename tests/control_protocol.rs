#![cfg(target_os = "linux")]

use std::{
    fs,
    io::{Read, Write},
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

use serde_json::Value;
use tempfile::TempDir;

struct DaemonProcess {
    child: Child,
    _directory: TempDir,
    socket: PathBuf,
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

    let persistent = request(
        &daemon.socket,
        "version = 1\noperation = \"create\"\n\n[session]\npersistent = true\n\n[[rules]]\nhost = \"example.com\"\nmode = \"tunnel\"\n",
    );
    assert_eq!(persistent["ok"], true);
    assert_eq!(persistent["result"]["persistent"], true);
    let persistent_id = persistent["result"]["id"]
        .as_str()
        .expect("create should return an ID");
    let list = request(&daemon.socket, "version = 1\noperation = \"list\"\n");
    assert_eq!(list["result"]["sessions"].as_array().unwrap().len(), 1);
    let stopped = request(
        &daemon.socket,
        &format!("version = 1\noperation = \"stop\"\nsession_id = \"{persistent_id}\"\n"),
    );
    assert_eq!(stopped["result"]["stopped"], true);

    let mut ephemeral = UnixStream::connect(&daemon.socket).expect("client should connect");
    write_frame(
        &mut ephemeral,
        b"version = 1\noperation = \"create\"\n\n[session]\npersistent = false\n\n[[rules]]\nhost = \"example.com\"\nmode = \"tunnel\"\n",
    );
    let created = read_response(&mut ephemeral);
    assert_eq!(created["result"]["persistent"], false);
    let ephemeral_id = created["result"]["id"]
        .as_str()
        .expect("create should return an ID")
        .to_owned();
    let listed = request(&daemon.socket, "version = 1\noperation = \"list\"\n");
    assert_eq!(listed["result"]["sessions"].as_array().unwrap().len(), 1);
    drop(ephemeral);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let listed = request(&daemon.socket, "version = 1\noperation = \"list\"\n");
        let sessions = listed["result"]["sessions"]
            .as_array()
            .expect("list should return sessions");
        if sessions.is_empty() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "closed lease should remove its session"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert!(!ephemeral_id.is_empty());
}

fn start_daemon(read_timeout_ms: u64) -> DaemonProcess {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let socket = directory.path().join("run/control.sock");
    let config_path = directory.path().join("daemon.toml");
    let trusted_uid = fs::metadata(directory.path())
        .expect("temporary directory should have metadata")
        .uid();
    let config = format!(
        "[daemon]\ncontrol_socket = \"{}\"\nsocket_dir = \"{}\"\ntrusted_operator_uid = {trusted_uid}\ncontrol_read_timeout_ms = {read_timeout_ms}\n\n[ca]\ncertificate = \"unused.pem\"\nprivate_key = \"unused-key.pem\"\n\n[secrets]\ndirectory = \"unused-secrets\"\n",
        socket.display(),
        directory.path().join("proxies").display(),
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
