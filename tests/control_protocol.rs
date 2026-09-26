#![cfg(target_os = "linux")]

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::Shutdown,
    net::TcpListener as StdTcpListener,
    os::unix::{
        fs::{MetadataExt, PermissionsExt, symlink},
        net::UnixStream,
    },
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use serde_json::Value;
use tempfile::TempDir;

struct DaemonProcess {
    child: Child,
    _directory: TempDir,
    socket: PathBuf,
    socket_dir: PathBuf,
    session_config_dir: Option<PathBuf>,
    secret_dir: PathBuf,
}

struct DaemonProcesses(Vec<Child>);

impl Drop for DaemonProcesses {
    fn drop(&mut self) {
        for child in &mut self.0 {
            if matches!(child.try_wait(), Ok(None) | Err(_)) {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
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
        assert_eq!(
            keys,
            [
                "draining_generations",
                "generation",
                "id",
                "persistent",
                "socket",
                "state"
            ]
        );
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
fn file_only_creates_nested_sessions_from_fresh_policy_snapshots_and_keeps_ephemeral_leases() {
    let daemon = start_file_only_daemon(250);
    let name = "cladding/github.toml";
    let named_socket = "file-backed/named.sock";
    write_session_policy_contents(
        &daemon,
        name,
        &session_policy_with_socket_name("github.com", false, named_socket),
    );

    let (lease_one, created_one) = create_from_file(&daemon.socket, name);
    assert_eq!(created_one["ok"], true);
    assert_eq!(created_one["result"]["persistent"], false);
    let first_socket = PathBuf::from(created_one["result"]["socket"].as_str().unwrap());
    assert_eq!(first_socket, daemon.socket_dir.join(named_socket));
    assert!(
        first_socket.exists(),
        "the returned nested named socket should exist"
    );
    assert_proxy_available(&first_socket);
    assert_eq!(list_sessions(&daemon.socket).len(), 1);

    // A live session keeps its parsed policy snapshot. A later create reads
    // the current file and rejects an invalid replacement.
    write_session_policy_contents(
        &daemon,
        name,
        "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"*.example.test\"\nmode = \"tunnel\"\n",
    );
    assert_eq!(
        request(
            &daemon.socket,
            "version = 1\noperation = \"create_from_file\"\nname = \"cladding/github.toml\"\n",
        )["error"]["code"],
        "config_file_invalid"
    );
    assert_eq!(list_sessions(&daemon.socket).len(), 1);
    assert!(first_socket.exists());

    write_session_policy(&daemon, name, "api.github.com", false);
    let (lease_two, created_two) = create_from_file(&daemon.socket, name);
    assert_eq!(created_two["ok"], true);
    let second_socket = PathBuf::from(created_two["result"]["socket"].as_str().unwrap());
    assert_eq!(second_socket.parent(), Some(daemon.socket_dir.as_path()));
    assert_ne!(first_socket, second_socket);
    assert_proxy_available(&second_socket);
    assert_eq!(list_sessions(&daemon.socket).len(), 2);

    drop(lease_one);
    wait_for_session_count(&daemon.socket, 1);
    assert!(
        !first_socket.exists(),
        "disconnect must remove its leased socket"
    );
    assert!(
        second_socket.exists(),
        "disconnect must preserve the other lease"
    );
    assert!(
        !daemon.socket_dir.join("file-backed").exists(),
        "disconnect must remove the empty Baffle-created named socket directory"
    );
    drop(lease_two);
    wait_for_session_count(&daemon.socket, 0);
    assert!(!second_socket.exists());
}

#[test]
fn file_backed_reload_keeps_old_tunnels_and_cuts_over_new_connections_and_socket_paths() {
    let daemon = start_file_only_daemon(250);
    let upstream = StdTcpListener::bind(("127.0.0.1", 0)).expect("local tunnel origin should bind");
    let port = upstream
        .local_addr()
        .expect("local tunnel origin should have an address")
        .port();
    let (accepted_tx, accepted_rx) = std::sync::mpsc::channel();
    let origin_task = thread::spawn(move || {
        let (mut origin, _) = upstream
            .accept()
            .expect("proxy should connect to the tunnel origin");
        origin
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("origin timeout should be set");
        accepted_tx.send(()).expect("accepted signal should send");
        let mut bytes = [0; 256];
        loop {
            match origin.read(&mut bytes) {
                Ok(0) | Err(_) => break,
                Ok(length) => origin
                    .write_all(&bytes[..length])
                    .expect("origin should echo tunnel bytes"),
            }
        }
    });

    let name = "reload/tunnel.toml";
    write_session_policy_contents(&daemon, name, &tunnel_policy("localhost", port, true, None));
    let (creator, created) = create_from_file(&daemon.socket, name);
    assert_eq!(created["ok"], true);
    drop(creator);
    let session_id = created["result"]["id"]
        .as_str()
        .expect("created session should return its ID")
        .to_owned();
    let old_socket = PathBuf::from(
        created["result"]["socket"]
            .as_str()
            .expect("created session should return its socket"),
    );
    let before = fs::symlink_metadata(&old_socket).expect("data socket should exist");

    write_session_policy_contents(
        &daemon,
        name,
        &format!(
            "# Equivalent TOML must not replace the current generation.\n\n{}",
            tunnel_policy("localhost", port, false, None)
        ),
    );
    let unchanged = reload_session(&daemon.socket, &session_id);
    assert_eq!(unchanged["result"]["status"], "unchanged");
    assert_eq!(
        unchanged["result"]["socket"],
        old_socket.to_string_lossy().as_ref()
    );
    assert_eq!(
        fs::symlink_metadata(&old_socket)
            .expect("no-op reload must keep the listener")
            .ino(),
        before.ino()
    );
    assert_eq!(list_sessions(&daemon.socket)[0]["generation"], 1);

    let mut old_tunnel = connect_tunnel(&old_socket, port);
    accepted_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("old generation should connect to the origin");
    tunnel_round_trip(&mut old_tunnel, b"before reload");

    write_session_policy_contents(
        &daemon,
        name,
        &tunnel_policy("other.example", port, false, None),
    );
    let reloaded = reload_session(&daemon.socket, &session_id);
    assert_eq!(reloaded["result"]["status"], "reloaded");
    assert_eq!(
        reloaded["result"]["socket"],
        old_socket.to_string_lossy().as_ref()
    );
    assert_eq!(
        fs::symlink_metadata(&old_socket)
            .expect("same-path reload must reuse the listener")
            .ino(),
        before.ino()
    );
    assert_eq!(list_sessions(&daemon.socket)[0]["generation"], 2);

    tunnel_round_trip(&mut old_tunnel, b"old tunnel remains alive");
    let mut denied = UnixStream::connect(&old_socket).expect("same listener should accept clients");
    denied
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("proxy timeout should be set");
    denied
        .write_all(
            format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n")
                .as_bytes(),
        )
        .expect("CONNECT request should be written");
    assert!(
        read_http_headers(&mut denied).starts_with("HTTP/1.1 403"),
        "new connections should use the replacement policy"
    );

    let nested_name = "reloaded/current.sock";
    write_session_policy_contents(
        &daemon,
        name,
        &tunnel_policy("localhost", port, false, Some(nested_name)),
    );
    let path_changed = reload_session(&daemon.socket, &session_id);
    assert_eq!(path_changed["result"]["status"], "reloaded");
    let current_socket = PathBuf::from(
        path_changed["result"]["socket"]
            .as_str()
            .expect("reload result should report the current socket"),
    );
    assert_eq!(current_socket, daemon.socket_dir.join(nested_name));
    assert!(
        current_socket.exists(),
        "new listener should be ready at cutover"
    );
    assert_proxy_available(&current_socket);
    assert!(
        !old_socket.exists(),
        "old owned socket should be unlinked at cutover"
    );
    assert_eq!(
        list_sessions(&daemon.socket)[0]["socket"],
        current_socket.to_string_lossy().as_ref()
    );
    assert_eq!(list_sessions(&daemon.socket)[0]["persistent"], true);
    assert!(
        list_sessions(&daemon.socket)[0]["draining_generations"]
            .as_u64()
            .unwrap_or_default()
            <= 1,
        "one superseded listener should be tracked while it drains"
    );
    tunnel_round_trip(&mut old_tunnel, b"path change preserves old tunnel");

    drop(old_tunnel);
    let stopped = request(
        &daemon.socket,
        &format!("version = 1\noperation = \"stop\"\nsession_id = {session_id:?}\n"),
    );
    assert_eq!(stopped["result"]["stopped"], true);
    assert!(!current_socket.exists());
    assert!(!daemon.socket_dir.join("reloaded").exists());
    origin_task
        .join()
        .expect("tunnel origin should stop after disconnect");
}

#[test]
fn concurrent_reload_stop_and_creator_disconnect_do_not_resurrect_a_session() {
    let daemon = start_file_only_daemon(250);
    let name = "concurrent/reload.toml";
    write_session_policy(&daemon, name, "old.example", false);
    let (creator, created) = create_from_file(&daemon.socket, name);
    let id = created["result"]["id"]
        .as_str()
        .expect("created session should return its ID")
        .to_owned();
    let old_socket = PathBuf::from(created["result"]["socket"].as_str().unwrap());

    write_session_policy_contents(
        &daemon,
        name,
        &session_policy_with_socket_name("new.example", false, "concurrent/new.sock"),
    );

    let start = Arc::new(Barrier::new(4));
    let reload_start = Arc::clone(&start);
    let reload_control = daemon.socket.clone();
    let reload_id = id.clone();
    let reload = thread::spawn(move || {
        reload_start.wait();
        reload_session(&reload_control, &reload_id)
    });

    let stop_start = Arc::clone(&start);
    let stop_control = daemon.socket.clone();
    let stop_id = id.clone();
    let stop = thread::spawn(move || {
        stop_start.wait();
        request(
            &stop_control,
            &format!("version = 1\noperation = \"stop\"\nsession_id = {stop_id:?}\n"),
        )
    });

    let disconnect_start = Arc::clone(&start);
    let disconnect = thread::spawn(move || {
        disconnect_start.wait();
        drop(creator);
    });

    start.wait();
    let reload_result = reload.join().expect("reload worker should finish");
    let stop_result = stop.join().expect("stop worker should finish");
    disconnect
        .join()
        .expect("creator disconnect worker should finish");
    assert!(
        reload_result["ok"] == true || reload_result["error"]["code"] == "session_not_found",
        "reload should either finish independently or observe the stopped session: {reload_result}"
    );
    assert!(
        stop_result["ok"] == true || stop_result["error"]["code"] == "session_not_found",
        "stop should either stop the session or observe its completed cleanup: {stop_result}"
    );

    wait_for_session_count(&daemon.socket, 0);
    assert!(
        !old_socket.exists(),
        "concurrent cleanup must remove the original socket"
    );
    assert!(
        !daemon.socket_dir.join("concurrent/new.sock").exists(),
        "a completed reload must not leave its replacement socket behind"
    );
    assert!(
        !daemon.socket_dir.join("concurrent").exists(),
        "cleanup must remove the Baffle-created empty socket directory"
    );
}

#[test]
fn reload_failures_preserve_active_socket_and_reload_all_reports_each_file_session() {
    let daemon = start_file_only_daemon(250);
    write_session_policy(&daemon, "first.toml", "first.example", true);
    write_session_policy(&daemon, "second.toml", "second.example", true);
    let (_first_creator, first) = create_from_file(&daemon.socket, "first.toml");
    let (_second_creator, second) = create_from_file(&daemon.socket, "second.toml");
    let first_id = first["result"]["id"].as_str().unwrap().to_owned();
    let second_id = second["result"]["id"].as_str().unwrap().to_owned();
    let first_socket = PathBuf::from(first["result"]["socket"].as_str().unwrap());
    let before = fs::symlink_metadata(&first_socket).expect("active listener should exist");

    let occupied_path = daemon.socket_dir.join("occupied.sock");
    fs::write(&occupied_path, "operator-owned file").expect("occupied path should be created");
    write_session_policy_contents(
        &daemon,
        "first.toml",
        &session_policy_with_socket_name("first.example", true, "occupied.sock"),
    );
    let occupied = reload_session(&daemon.socket, &first_id);
    assert_eq!(occupied["result"]["status"], "failed");
    assert_eq!(occupied["result"]["reason"], "listener_unavailable");
    assert_eq!(
        occupied["result"]["socket"],
        first_socket.to_string_lossy().as_ref()
    );
    assert!(
        occupied_path.is_file(),
        "rollback must leave an unowned collision alone"
    );
    assert_eq!(
        fs::symlink_metadata(&first_socket)
            .expect("original listener should remain active")
            .ino(),
        before.ino()
    );

    write_session_policy_contents(&daemon, "first.toml", "not valid TOML = [\n");
    let invalid = reload_session(&daemon.socket, &first_id);
    assert_eq!(invalid["result"]["status"], "failed");
    assert_eq!(invalid["result"]["reason"], "configuration_invalid");
    assert!(first_socket.exists());

    let first_config = daemon
        .session_config_dir
        .as_ref()
        .unwrap()
        .join("first.toml");
    let outside_config = daemon._directory.path().join("outside-session.toml");
    fs::write(&outside_config, session_policy("outside.example", true))
        .expect("outside policy should be written");
    fs::set_permissions(&outside_config, fs::Permissions::from_mode(0o600))
        .expect("outside policy should be private");
    fs::remove_file(&first_config).expect("original policy should be removed");
    symlink(&outside_config, &first_config).expect("malicious replacement symlink should be made");
    let symlinked = reload_session(&daemon.socket, &first_id);
    assert_eq!(symlinked["result"]["status"], "failed");
    assert_eq!(symlinked["result"]["reason"], "configuration_unavailable");
    assert!(
        first_socket.exists(),
        "unsafe replacement must not affect the session"
    );

    fs::remove_file(&first_config).expect("replacement symlink should be removed");
    let missing = reload_session(&daemon.socket, &first_id);
    assert_eq!(missing["result"]["status"], "failed");
    assert_eq!(missing["result"]["reason"], "configuration_not_found");
    assert!(first_socket.exists());

    write_session_policy(&daemon, "first.toml", "first.example", true);
    fs::remove_file(
        daemon
            .session_config_dir
            .as_ref()
            .unwrap()
            .join("second.toml"),
    )
    .expect("second policy should be removed before reload-all");
    let all = request(&daemon.socket, "version = 1\noperation = \"reload_all\"\n");
    assert_eq!(all["ok"], true);
    let results = all["result"]["results"]
        .as_array()
        .expect("reload_all should return per-session results");
    assert_eq!(results.len(), 2);
    assert_eq!(
        results
            .iter()
            .filter(|result| result["status"] == "unchanged")
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result["status"] == "failed")
            .count(),
        1
    );
    let failed = results
        .iter()
        .find(|result| result["status"] == "failed")
        .expect("one session should fail");
    assert_eq!(failed["id"], second_id);
    assert_eq!(failed["reason"], "configuration_not_found");
    assert_eq!(list_sessions(&daemon.socket).len(), 2);

    for id in [first_id, second_id] {
        let stopped = request(
            &daemon.socket,
            &format!("version = 1\noperation = \"stop\"\nsession_id = {id:?}\n"),
        );
        assert_eq!(stopped["result"]["stopped"], true);
    }
}

#[test]
fn inline_session_reload_is_rejected_with_a_safe_reason() {
    let daemon = start_daemon(250);
    let (_creator, created) = create_session(&daemon.socket, true, "inline.example");
    let id = created["result"]["id"].as_str().unwrap();
    let result = reload_session(&daemon.socket, id);
    assert_eq!(result["result"]["status"], "failed");
    assert_eq!(result["result"]["reason"], "inline_session");
    assert_eq!(result["result"]["socket"], created["result"]["socket"]);
    assert_eq!(list_sessions(&daemon.socket).len(), 1);
}

#[test]
fn credential_rotation_is_an_effective_change_and_unavailable_credentials_roll_back() {
    let daemon = start_file_only_daemon(250);
    let secret_path = daemon.secret_dir.join("api-token");
    fs::write(&secret_path, "old-sensitive-value\n").expect("credential should be written");
    fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600))
        .expect("credential should be private");
    write_session_policy_contents(
        &daemon,
        "credentials.toml",
        &intercept_policy_with_secret("api.example", true),
    );
    let (_creator, created) = create_from_file(&daemon.socket, "credentials.toml");
    assert_eq!(created["ok"], true);
    let id = created["result"]["id"].as_str().unwrap().to_owned();
    let socket = PathBuf::from(created["result"]["socket"].as_str().unwrap());

    fs::write(&secret_path, "new-sensitive-value\n").expect("rotated credential should be written");
    fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600))
        .expect("rotated credential should remain private");
    let reloaded = reload_session(&daemon.socket, &id);
    assert_eq!(reloaded["result"]["status"], "reloaded");
    assert_eq!(list_sessions(&daemon.socket)[0]["generation"], 2);
    let response = serde_json::to_string(&reloaded).expect("reload result should serialize");
    assert!(!response.contains("old-sensitive-value"));
    assert!(!response.contains("new-sensitive-value"));

    fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o644))
        .expect("unsafe credential mode should be set");
    let failed = reload_session(&daemon.socket, &id);
    assert_eq!(failed["result"]["status"], "failed");
    assert_eq!(failed["result"]["reason"], "credentials_unavailable");
    assert_eq!(
        failed["result"]["socket"],
        socket.to_string_lossy().as_ref()
    );
    assert_eq!(list_sessions(&daemon.socket)[0]["generation"], 2);
    assert!(
        socket.exists(),
        "credential failure must preserve the active listener"
    );

    let stopped = request(
        &daemon.socket,
        &format!("version = 1\noperation = \"stop\"\nsession_id = {id:?}\n"),
    );
    assert_eq!(stopped["result"]["stopped"], true);
}

#[test]
fn reload_limits_pinned_policy_generations_without_closing_old_tunnels() {
    const GENERATIONS: usize = 8;
    let daemon = start_file_only_daemon(250);
    let (port, stop_origin, origin_task) = start_echo_origin();
    let name = "generation-limit.toml";
    write_session_policy_contents(&daemon, name, &generation_policy(1, port));
    let (_creator, created) = create_from_file(&daemon.socket, name);
    let id = created["result"]["id"].as_str().unwrap().to_owned();
    let socket = PathBuf::from(created["result"]["socket"].as_str().unwrap());

    let mut tunnels = Vec::new();
    tunnels.push(connect_tunnel(&socket, port));
    for generation in 2..=GENERATIONS {
        write_session_policy_contents(&daemon, name, &generation_policy(generation, port));
        let result = reload_session(&daemon.socket, &id);
        assert_eq!(result["result"]["status"], "reloaded");
        tunnels.push(connect_tunnel(&socket, port));
    }

    write_session_policy_contents(&daemon, name, &generation_policy(9, port));
    let limited = reload_session(&daemon.socket, &id);
    assert_eq!(limited["result"]["status"], "failed");
    assert_eq!(limited["result"]["reason"], "generation_limit");
    assert_eq!(
        limited["result"]["socket"],
        socket.to_string_lossy().as_ref()
    );
    assert_eq!(list_sessions(&daemon.socket)[0]["generation"], GENERATIONS);
    tunnel_round_trip(&mut tunnels[0], b"oldest tunnel is still active");
    tunnel_round_trip(
        &mut tunnels[GENERATIONS - 1],
        b"newest tunnel is still active",
    );

    drop(tunnels);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let result = reload_session(&daemon.socket, &id);
        if result["result"]["status"] == "reloaded" {
            break;
        }
        assert_eq!(result["result"]["reason"], "generation_limit");
        assert!(
            std::time::Instant::now() < deadline,
            "drained generations should release the resource limit"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let stopped = request(
        &daemon.socket,
        &format!("version = 1\noperation = \"stop\"\nsession_id = {id:?}\n"),
    );
    assert_eq!(stopped["result"]["stopped"], true);
    stop_origin.store(true, Ordering::Release);
    origin_task.join().expect("echo origin should stop");
}

#[test]
fn file_only_rejects_unsafe_names_files_and_inline_creation_without_changing_files() {
    let daemon = start_file_only_daemon(250);
    let root = daemon
        .session_config_dir
        .as_ref()
        .expect("file-only daemon should have a config directory");
    write_session_policy(&daemon, "cladding/github.toml", "github.com", false);
    let outside_dir = daemon._directory.path().join("outside");
    fs::create_dir(&outside_dir).expect("outside directory should be created");
    fs::set_permissions(&outside_dir, fs::Permissions::from_mode(0o700))
        .expect("outside directory should be private");
    let outside_file = outside_dir.join("github.toml");
    fs::write(&outside_file, session_policy("outside.example", false))
        .expect("outside policy should be written");
    fs::set_permissions(&outside_file, fs::Permissions::from_mode(0o600))
        .expect("outside policy should be private");

    assert_eq!(
        request(
            &daemon.socket,
            "version = 1\noperation = \"create_from_file\"\nname = \"missing.toml\"\n",
        )["error"]["code"],
        "config_file_not_found"
    );
    assert_eq!(
        request(
            &daemon.socket,
            "version = 1\noperation = \"create_from_file\"\nname = \"../outside/github.toml\"\n",
        )["error"]["code"],
        "invalid_request"
    );

    write_session_policy_contents(&daemon, "invalid.toml", "not valid TOML = [\n");
    assert_eq!(
        request(
            &daemon.socket,
            "version = 1\noperation = \"create_from_file\"\nname = \"invalid.toml\"\n",
        )["error"]["code"],
        "config_file_invalid"
    );
    write_session_policy_contents(&daemon, "oversized.toml", &"x".repeat(256 * 1024 + 1));
    assert_eq!(
        request(
            &daemon.socket,
            "version = 1\noperation = \"create_from_file\"\nname = \"oversized.toml\"\n",
        )["error"]["code"],
        "config_file_invalid"
    );

    write_session_policy(&daemon, "unreadable.toml", "unreadable.example", false);
    let unreadable_path = root.join("unreadable.toml");
    fs::set_permissions(&unreadable_path, fs::Permissions::from_mode(0o000))
        .expect("unreadable file mode should be set");
    assert_eq!(
        request(
            &daemon.socket,
            "version = 1\noperation = \"create_from_file\"\nname = \"unreadable.toml\"\n",
        )["error"]["code"],
        "config_file_unavailable"
    );

    let linked_file = root.join("linked.toml");
    symlink(&outside_file, &linked_file).expect("file symlink should be created");
    assert_eq!(
        request(
            &daemon.socket,
            "version = 1\noperation = \"create_from_file\"\nname = \"linked.toml\"\n",
        )["error"]["code"],
        "config_file_unavailable"
    );
    let linked_dir = root.join("redirected");
    symlink(&outside_dir, &linked_dir).expect("directory symlink should be created");
    assert_eq!(
        request(
            &daemon.socket,
            "version = 1\noperation = \"create_from_file\"\nname = \"redirected/github.toml\"\n",
        )["error"]["code"],
        "config_file_unavailable"
    );

    let protected_contents = fs::read(root.join("cladding/github.toml"))
        .expect("trusted configuration file should exist");
    let inline_create = request(
        &daemon.socket,
        "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"replacement.example\"\nmode = \"tunnel\"\n",
    );
    assert_eq!(inline_create["error"]["code"], "operation_not_allowed");
    let malformed_alternate = request(
        &daemon.socket,
        "version = 1\noperation = \"create_from_file\"\nname = \"cladding/github.toml\"\n\n[session]\npersistent = true\n",
    );
    assert_eq!(malformed_alternate["error"]["code"], "invalid_request");
    assert_eq!(
        fs::read(root.join("cladding/github.toml")).unwrap(),
        protected_contents
    );
    assert_eq!(list_sessions(&daemon.socket).len(), 0);
}

#[test]
fn file_only_keeps_the_config_directory_descriptor_across_rename_and_allows_authorized_stop() {
    let daemon = start_file_only_daemon(250);
    let root = daemon
        .session_config_dir
        .as_ref()
        .expect("file-only daemon should have a config directory");
    write_session_policy(&daemon, "cladding/github.toml", "github.com", false);
    write_session_policy(&daemon, "persistent.toml", "github.com", true);

    let moved_root = daemon._directory.path().join("moved-session-configs");
    fs::rename(root, &moved_root).expect("config directory should be renamed");
    let outside_dir = daemon._directory.path().join("replacement-configs");
    fs::create_dir(&outside_dir).expect("replacement directory should be created");
    fs::set_permissions(&outside_dir, fs::Permissions::from_mode(0o700))
        .expect("replacement directory should be private");
    fs::create_dir(outside_dir.join("cladding")).expect("nested replacement dir should exist");
    fs::write(
        outside_dir.join("cladding/github.toml"),
        "not a valid session policy",
    )
    .expect("replacement file should be written");
    symlink(&outside_dir, root).expect("replacement symlink should be created");

    let (lease, created) = create_from_file(&daemon.socket, "cladding/github.toml");
    assert_eq!(
        created["ok"], true,
        "daemon should read from the held directory descriptor"
    );
    let session_socket = PathBuf::from(created["result"]["socket"].as_str().unwrap());
    drop(lease);
    wait_for_session_count(&daemon.socket, 0);
    assert!(!session_socket.exists());

    let (creator, persistent) = create_from_file(&daemon.socket, "persistent.toml");
    assert_eq!(persistent["ok"], true);
    let persistent_id = persistent["result"]["id"].as_str().unwrap().to_owned();
    let persistent_socket = PathBuf::from(persistent["result"]["socket"].as_str().unwrap());
    drop(creator);
    assert_eq!(list_sessions(&daemon.socket).len(), 1);
    let stopped = request(
        &daemon.socket,
        &format!("version = 1\noperation = \"stop\"\nsession_id = \"{persistent_id}\"\n"),
    );
    assert_eq!(stopped["result"]["stopped"], true);
    assert!(!persistent_socket.exists());
}

#[test]
fn file_only_rolls_back_when_runtime_provisioning_fails() {
    let daemon = start_file_only_daemon_with_socket_dir(250, &"s".repeat(80));
    write_session_policy(&daemon, "rollback.toml", "rollback.example.test", true);
    let failed = request(
        &daemon.socket,
        "version = 1\noperation = \"create_from_file\"\nname = \"rollback.toml\"\n",
    );
    assert_eq!(failed["error"]["code"], "internal_error");
    assert!(list_sessions(&daemon.socket).is_empty());
    assert_eq!(
        fs::read_dir(&daemon.socket_dir)
            .expect("session socket directory should exist")
            .count(),
        0,
        "failed provisioning must not leave a session socket"
    );
}

#[test]
fn failed_session_creation_leaves_no_socket_or_registry_entry() {
    // Unix-domain socket paths are limited to 107 bytes on Linux. This makes
    // runtime startup fail before a session can be registered or its socket
    // can be created.
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

#[test]
fn concurrent_daemon_restarts_preserve_the_live_control_socket() {
    const STARTERS: usize = 16;

    let mut crashed_daemon = start_daemon(250);
    crashed_daemon
        .child
        .kill()
        .expect("daemon should be killable");
    crashed_daemon
        .child
        .wait()
        .expect("crashed daemon should be reaped");

    let config_path = crashed_daemon._directory.path().join("daemon.toml");
    let start_gate = Arc::new(Barrier::new(STARTERS));
    let mut launchers = Vec::with_capacity(STARTERS);
    for _ in 0..STARTERS {
        let config_path = config_path.clone();
        let start_gate = Arc::clone(&start_gate);
        launchers.push(thread::spawn(move || {
            start_gate.wait();
            Command::new(env!("CARGO_BIN_EXE_baffle"))
                .arg("daemon")
                .arg("--config")
                .arg(config_path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("concurrent daemon process should start")
        }));
    }
    let mut starters = DaemonProcesses(
        launchers
            .into_iter()
            .map(|launcher| launcher.join().expect("launcher thread should finish"))
            .collect(),
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut alive = 0;
        for child in &mut starters.0 {
            if child
                .try_wait()
                .expect("daemon process status should be readable")
                .is_none()
            {
                alive += 1;
            }
        }
        let responding = UnixStream::connect(&crashed_daemon.socket)
            .ok()
            .and_then(|mut stream| {
                stream.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
                write_frame(&mut stream, b"version = 1\noperation = \"list\"\n");
                Some(read_response(&mut stream)["ok"] == true)
            })
            .unwrap_or(false);

        if alive == 1 && responding {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "exactly one concurrent restart should own a responding control socket; {alive} processes remain"
        );
        thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        request(
            &crashed_daemon.socket,
            "version = 1\noperation = \"list\"\n"
        )["ok"],
        true,
        "the surviving daemon should retain its control socket"
    );

    drop(starters);
}

fn start_daemon(read_timeout_ms: u64) -> DaemonProcess {
    start_daemon_with_socket_dir(read_timeout_ms, "proxies")
}

fn start_daemon_with_socket_dir(read_timeout_ms: u64, socket_dir_name: &str) -> DaemonProcess {
    start_daemon_with_options(read_timeout_ms, socket_dir_name, false)
}

fn start_file_only_daemon(read_timeout_ms: u64) -> DaemonProcess {
    start_daemon_with_options(read_timeout_ms, "proxies", true)
}

fn start_file_only_daemon_with_socket_dir(
    read_timeout_ms: u64,
    socket_dir_name: &str,
) -> DaemonProcess {
    start_daemon_with_options(read_timeout_ms, socket_dir_name, true)
}

fn start_daemon_with_options(
    read_timeout_ms: u64,
    socket_dir_name: &str,
    file_only: bool,
) -> DaemonProcess {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let socket = directory.path().join("run/control.sock");
    let socket_dir = directory.path().join(socket_dir_name);
    let config_path = directory.path().join("daemon.toml");
    let secret_dir = directory.path().join("secrets");
    fs::create_dir(&secret_dir).expect("secret directory should be created");
    fs::set_permissions(&secret_dir, fs::Permissions::from_mode(0o700))
        .expect("secret directory should be private");
    let session_config_dir = file_only.then(|| directory.path().join("session-configs"));
    if let Some(session_config_dir) = &session_config_dir {
        fs::create_dir(session_config_dir).expect("session config directory should be created");
        fs::set_permissions(session_config_dir, fs::Permissions::from_mode(0o700))
            .expect("session config directory permissions should be private");
    }
    let (certificate_path, private_key_path) = write_test_ca(directory.path());
    let trusted_uid = fs::metadata(directory.path())
        .expect("temporary directory should have metadata")
        .uid();
    let file_settings = session_config_dir
        .as_ref()
        .map(|path| {
            format!(
                "create_mode = \"file_only\"\nsession_config_dir = \"{}\"\n",
                path.display()
            )
        })
        .unwrap_or_default();
    let config = format!(
        "[daemon]\ncontrol_socket = \"{}\"\nsocket_dir = \"{}\"\ntrusted_operator_uid = {trusted_uid}\ncontrol_read_timeout_ms = {read_timeout_ms}\n{file_settings}\n[ca]\ncertificate = \"{}\"\nprivate_key = \"{}\"\n\n[secrets]\ndirectory = \"{}\"\nallowed = [\"api-token\"]\n",
        socket.display(),
        socket_dir.display(),
        certificate_path.display(),
        private_key_path.display(),
        secret_dir.display(),
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
        session_config_dir,
        secret_dir,
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

fn create_from_file(control_socket: &PathBuf, name: &str) -> (UnixStream, Value) {
    let mut control = UnixStream::connect(control_socket).expect("client should connect");
    control
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout should be set");
    let body = format!("version = 1\noperation = \"create_from_file\"\nname = {name:?}\n");
    write_frame(&mut control, body.as_bytes());
    let response = read_response(&mut control);
    (control, response)
}

fn write_session_policy(daemon: &DaemonProcess, name: &str, host: &str, persistent: bool) {
    write_session_policy_contents(daemon, name, &session_policy(host, persistent));
}

fn session_policy(host: &str, persistent: bool) -> String {
    format!(
        "version = 1\noperation = \"create\"\n\n[session]\npersistent = {persistent}\n\n[[rules]]\nhost = \"{host}\"\nmode = \"tunnel\"\n"
    )
}

fn tunnel_policy(host: &str, port: u16, persistent: bool, socket_name: Option<&str>) -> String {
    let socket_setting = socket_name
        .map(|name| format!("socket_name = {name:?}\n"))
        .unwrap_or_default();
    format!(
        "version = 1\noperation = \"create\"\n\n[session]\npersistent = {persistent}\n{socket_setting}\n[[rules]]\nhost = \"{host}\"\nmode = \"tunnel\"\nports = [{port}]\n"
    )
}

fn generation_policy(generation: usize, port: u16) -> String {
    format!(
        "version = 1\noperation = \"create\"\n\n[session]\npersistent = true\n\n[[rules]]\nhost = \"localhost\"\nmode = \"tunnel\"\nports = [{port}]\n\n[[rules]]\nhost = \"generation-{generation}.example\"\nmode = \"tunnel\"\n"
    )
}

fn start_echo_origin() -> (u16, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let listener = StdTcpListener::bind(("127.0.0.1", 0)).expect("echo origin should bind");
    listener
        .set_nonblocking(true)
        .expect("echo origin should accept without blocking");
    let port = listener
        .local_addr()
        .expect("echo origin should have an address")
        .port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_signal = Arc::clone(&stop);
    let task = thread::spawn(move || {
        let mut clients = Vec::new();
        while !stop_signal.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    clients.push(thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                        let mut bytes = [0; 256];
                        loop {
                            match stream.read(&mut bytes) {
                                Ok(0) | Err(_) => break,
                                Ok(length) => {
                                    if stream.write_all(&bytes[..length]).is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("echo origin accept failed: {error}"),
            }
        }
        for client in clients {
            let _ = client.join();
        }
    });
    (port, stop, task)
}

fn intercept_policy_with_secret(host: &str, persistent: bool) -> String {
    format!(
        "version = 1\noperation = \"create\"\n\n[session]\npersistent = {persistent}\n\n[[rules]]\nhost = \"{host}\"\nmode = \"intercept\"\npaths = [\"/allowed\"]\n\n[[rules.inject]]\nheader = \"Authorization\"\nsecret = \"api-token\"\nformat = \"bearer\"\n"
    )
}

fn reload_session(control_socket: &PathBuf, session_id: &str) -> Value {
    request(
        control_socket,
        &format!("version = 1\noperation = \"reload\"\nsession_id = {session_id:?}\n"),
    )
}

fn connect_tunnel(socket_path: &PathBuf, port: u16) -> UnixStream {
    let mut stream = UnixStream::connect(socket_path).expect("proxy should accept a tunnel");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("proxy timeout should be set");
    stream
        .write_all(
            format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n")
                .as_bytes(),
        )
        .expect("CONNECT request should be written");
    let response = read_http_headers(&mut stream);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "CONNECT should establish the old tunnel: {response:?}"
    );
    stream
}

fn tunnel_round_trip(stream: &mut UnixStream, payload: &[u8]) {
    stream
        .write_all(payload)
        .expect("opaque tunnel payload should be written");
    let mut echoed = vec![0; payload.len()];
    stream
        .read_exact(&mut echoed)
        .expect("opaque tunnel payload should be echoed");
    assert_eq!(echoed, payload);
}

fn read_http_headers(stream: &mut UnixStream) -> String {
    let mut bytes = Vec::new();
    let mut byte = [0; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        stream
            .read_exact(&mut byte)
            .expect("proxy response headers should be complete");
        bytes.push(byte[0]);
        assert!(
            bytes.len() < 16 * 1024,
            "proxy response headers should be small"
        );
    }
    String::from_utf8(bytes).expect("proxy response headers should be UTF-8")
}

fn session_policy_with_socket_name(host: &str, persistent: bool, socket_name: &str) -> String {
    format!(
        "version = 1\noperation = \"create\"\n\n[session]\npersistent = {persistent}\nsocket_name = {socket_name:?}\n\n[[rules]]\nhost = \"{host}\"\nmode = \"tunnel\"\n"
    )
}

fn write_session_policy_contents(daemon: &DaemonProcess, name: &str, contents: &str) {
    let root = daemon
        .session_config_dir
        .as_ref()
        .expect("file-only daemon should have a session config directory");
    let path = root.join(name);
    let parent = path
        .parent()
        .expect("session config path should have a parent");
    fs::create_dir_all(parent).expect("session config parent directories should be created");
    let mut directory = parent;
    while directory != root {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .expect("nested session config directory should be private");
        directory = directory
            .parent()
            .expect("nested session config directory should have a parent");
    }
    fs::write(&path, contents).expect("session config should be written");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .expect("session config should be private");
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
        status.starts_with("HTTP/1.1 400")
            || status.starts_with("HTTP/1.0 400")
            || status.starts_with("HTTP/1.1 403")
            || status.starts_with("HTTP/1.0 403"),
        "running deny-all proxy should respond through its own Unix socket: {status:?}"
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
