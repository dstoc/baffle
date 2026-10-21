#![cfg(target_os = "linux")]

use serde_json::Value;
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    process::{Child, ChildStdout, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

#[allow(dead_code)]
mod common;
use common::DaemonProcess;

struct TestDaemon {
    daemon: DaemonProcess,
    session_config_dir: PathBuf,
}

impl TestDaemon {
    fn start(file_only: bool) -> Self {
        let daemon = DaemonProcess::start_for_cli(file_only);
        let session_config_dir = daemon
            .session_config_dir
            .clone()
            .unwrap_or_else(|| daemon.directory.path().join("sessions"));
        Self {
            daemon,
            session_config_dir,
        }
    }

    fn cli(&self) -> Command {
        self.daemon.cli()
    }

    fn list(&self) -> String {
        self.daemon.list()
    }

    fn directory(&self) -> &Path {
        self.daemon.directory.path()
    }
}

struct AttachedCreate {
    child: Child,
    _stdout: BufReader<ChildStdout>,
    id: String,
    socket_path: PathBuf,
    credential_seed: String,
}

impl AttachedCreate {
    fn start(daemon: &TestDaemon, config: &Path) -> Self {
        Self::start_inner(daemon, config, None).0
    }

    fn start_and_signal_on_readiness(
        daemon: &TestDaemon,
        config: &Path,
        signal: &str,
    ) -> (Self, ExitStatus) {
        let (create, status) = Self::start_inner(daemon, config, Some(signal));
        (create, status.expect("readiness signal should be sent"))
    }

    fn start_inner(
        daemon: &TestDaemon,
        config: &Path,
        readiness_signal: Option<&str>,
    ) -> (Self, Option<ExitStatus>) {
        let mut child = daemon
            .cli()
            .arg("create")
            .arg("--config")
            .arg(config)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("create command should start");
        let stdout = child.stdout.take().expect("create stdout should be piped");
        let mut stdout = BufReader::new(stdout);
        let mut created = String::new();
        stdout
            .read_line(&mut created)
            .expect("create JSON response should be written");
        assert!(
            created.ends_with('\n'),
            "create JSON should be newline-terminated"
        );
        let response = parse_json_line(&created);
        let id = response["id"]
            .as_str()
            .expect("create JSON should include the session ID")
            .to_owned();
        let socket_path = PathBuf::from(
            response["socket"]
                .as_str()
                .expect("create JSON should include the data socket"),
        );
        assert_eq!(response["persistent"], false);
        let credential_seed = response["credential_seed_base64url"]
            .as_str()
            .expect("create JSON should include the credential seed")
            .to_owned();
        let status = readiness_signal.map(|signal| {
            let sent = Command::new("kill")
                .arg(format!("-{signal}"))
                .arg(child.id().to_string())
                .status()
                .expect("kill command should be available");
            assert!(sent.success(), "could not send {signal}");
            wait_for_exit(&mut child)
        });
        if readiness_signal.is_none() {
            assert!(
                child
                    .try_wait()
                    .expect("create status should be readable")
                    .is_none(),
                "leased create must stay attached"
            );
        }
        (
            Self {
                child,
                _stdout: stdout,
                id,
                socket_path,
                credential_seed,
            },
            status,
        )
    }

    fn signal_and_wait(&mut self, signal: &str) -> ExitStatus {
        let sent = Command::new("kill")
            .arg(format!("-{signal}"))
            .arg(self.child.id().to_string())
            .status()
            .expect("kill command should be available");
        assert!(sent.success(), "could not send {signal}");
        wait_for_exit(&mut self.child)
    }
}

fn parse_json_line(line: &str) -> Value {
    assert!(
        line.ends_with('\n'),
        "JSON response should end with a newline"
    );
    assert_eq!(
        line.matches('\n').count(),
        1,
        "stdout should contain one JSON line"
    );
    serde_json::from_str(line).expect("stdout should contain one valid JSON object")
}

fn parse_json_stdout(stdout: &[u8]) -> Value {
    let text = std::str::from_utf8(stdout).expect("stdout should be UTF-8");
    parse_json_line(text)
}

fn wait_for_exit(child: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().expect("child status should be readable") {
            return status;
        }
        assert!(Instant::now() < deadline, "child process did not exit");
        thread::sleep(Duration::from_millis(10));
    }
}

fn session_is_listed(listed: &str, session_id: &str) -> bool {
    parse_json_stdout(listed.as_bytes())["sessions"]
        .as_array()
        .expect("list JSON should contain session entries")
        .iter()
        .any(|session| session["id"] == session_id)
}

fn wait_for_session_release(
    daemon: &TestDaemon,
    session: &AttachedCreate,
    sessions_to_preserve: &[&AttachedCreate],
) -> String {
    let timeout = Duration::from_secs(5);
    let deadline = Instant::now() + timeout;
    loop {
        let socket_exists = session.socket_path.exists();
        let listed = daemon.list();
        let target_is_listed = session_is_listed(&listed, &session.id);
        let missing_preserved = sessions_to_preserve
            .iter()
            .filter(|preserved| !session_is_listed(&listed, &preserved.id))
            .map(|preserved| preserved.id.as_str())
            .collect::<Vec<_>>();

        if !socket_exists && !target_is_listed && missing_preserved.is_empty() {
            return listed;
        }

        assert!(
            Instant::now() < deadline,
            "session {} was not released within {timeout:?} (socket exists: {socket_exists}, registry entry exists: {target_is_listed}, missing preserved sessions: {missing_preserved:?}); last session list:\n{listed}",
            session.id
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn inline_config(directory: &Path, persistent: bool) -> PathBuf {
    let path = directory.join("inline.toml");
    fs::write(
        &path,
        format!("version = 2\npersistent = {persistent}\n\n[rules.\"example.com\"]\n"),
    )
    .expect("inline session config should be written");
    path
}

#[test]
fn inline_create_lists_sessions_and_independent_stop_preserves_other_lease() {
    let daemon = TestDaemon::start(false);
    let config_a = inline_config(daemon.directory(), false);
    let config_b = inline_config(daemon.directory(), false);

    let mut first = AttachedCreate::start(&daemon, &config_a);
    let mut second = AttachedCreate::start(&daemon, &config_b);
    assert!(first.socket_path.exists());
    assert!(second.socket_path.exists());

    let listed = daemon.list();
    let list_json = parse_json_stdout(listed.as_bytes());
    let sessions = list_json["sessions"]
        .as_array()
        .expect("list JSON should contain session entries");
    assert_eq!(sessions.len(), 2);
    for create in [&first, &second] {
        let session = sessions
            .iter()
            .find(|session| session["id"] == create.id)
            .expect("created session should appear in list JSON");
        assert_eq!(session["id"], create.id);
        assert_eq!(session["socket"], create.socket_path.display().to_string());
        assert_eq!(session["state"], "running");
        assert_eq!(session["persistent"], false);
        assert!(!listed.contains(&create.credential_seed));
    }
    assert!(
        list_json["sessions"][0]
            .get("credential_seed_base64url")
            .is_none()
    );

    let stopped = daemon
        .cli()
        .arg("stop")
        .arg(&first.id)
        .output()
        .expect("stop command should run");
    assert!(
        stopped.status.success(),
        "stop failed: {}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    let stop_json = parse_json_stdout(&stopped.stdout);
    assert_eq!(stop_json["stopped"], true);
    assert_eq!(stop_json["id"], first.id);
    let listed = daemon.list();
    assert!(!listed.contains(&first.id));
    assert!(listed.contains(&second.id));
    assert!(
        second
            .child
            .try_wait()
            .expect("second status should be readable")
            .is_none(),
        "stopping one session must not interrupt another CLI lease"
    );

    let first_status = first.signal_and_wait("INT");
    let second_status = second.signal_and_wait("INT");
    assert!(first_status.success(), "first CLI failed: {first_status}");
    assert!(
        second_status.success(),
        "second CLI failed: {second_status}"
    );
    let listed = wait_for_session_release(&daemon, &second, &[]);
    assert_eq!(
        parse_json_stdout(listed.as_bytes())["sessions"],
        serde_json::json!([])
    );
}

#[test]
fn inline_create_accepts_empty_deny_and_unmatched_tunnel_policies() {
    let daemon = TestDaemon::start(false);

    for (name, setting, allowed_status) in [
        ("deny", "", &["403"][..]),
        ("tunnel", "unmatched = \"tunnel\"\n", &["200", "502"][..]),
    ] {
        let path = daemon.directory().join(format!("{name}.toml"));
        fs::write(&path, format!("version = 2\npersistent = true\n{setting}"))
            .expect("empty session file should be written");
        let created = daemon
            .cli()
            .arg("create")
            .arg("--config")
            .arg(&path)
            .output()
            .expect("local config create should run");
        assert!(
            created.status.success(),
            "empty {name} policy should be accepted: {}",
            String::from_utf8_lossy(&created.stderr)
        );
        let response = parse_json_stdout(&created.stdout);
        let id = response["id"]
            .as_str()
            .expect("create JSON should include the session ID");
        let socket_path = response["socket"]
            .as_str()
            .expect("create JSON should include the data socket");
        let mut stream = UnixStream::connect(socket_path)
            .expect("created proxy should accept an unmatched CONNECT request");
        stream
            .set_read_timeout(Some(Duration::from_secs(4)))
            .expect("CONNECT response timeout should be set");
        write!(
            stream,
            "CONNECT unmatched.localhost:443 HTTP/1.1\r\nHost: unmatched.localhost:443\r\n\r\n"
        )
        .expect("CONNECT request should be written");
        let mut response = String::new();
        BufReader::new(stream)
            .read_line(&mut response)
            .expect("CONNECT status should arrive");
        assert!(
            allowed_status
                .iter()
                .any(|code| response.split_whitespace().nth(1) == Some(*code)),
            "unexpected status for empty {name} policy: {response:?}"
        );
        let stopped = daemon
            .cli()
            .arg("stop")
            .arg(id)
            .output()
            .expect("created session should stop");
        assert!(
            stopped.status.success(),
            "empty {name} policy should remain manageable: {}",
            String::from_utf8_lossy(&stopped.stderr)
        );
    }
}

#[test]
fn inline_create_cli_exit_releases_only_its_own_lease() {
    let daemon = TestDaemon::start(false);
    let config = inline_config(daemon.directory(), false);
    let mut first = AttachedCreate::start(&daemon, &config);
    let (second, second_status) =
        AttachedCreate::start_and_signal_on_readiness(&daemon, &config, "INT");
    assert!(
        second_status.success(),
        "second CLI failed: {second_status}"
    );
    let listed = wait_for_session_release(&daemon, &second, &[&first]);
    assert!(
        first.socket_path.exists(),
        "the first session's data socket should remain after the second lease closes"
    );
    assert!(
        first
            .child
            .try_wait()
            .expect("first CLI status should be readable")
            .is_none(),
        "closing the second lease must not interrupt the first CLI"
    );
    assert!(
        session_is_listed(&listed, &first.id),
        "the first lease should remain in the session registry:\n{listed}"
    );
    {
        let _connection = UnixStream::connect(&first.socket_path)
            .expect("the first session should still accept data connections");
    }

    let first_status = first.signal_and_wait("INT");
    assert!(first_status.success(), "first CLI failed: {first_status}");
    let listed = wait_for_session_release(&daemon, &first, &[]);
    assert_eq!(
        parse_json_stdout(listed.as_bytes())["sessions"],
        serde_json::json!([])
    );
}

#[test]
fn inline_create_forwards_named_socket_and_prints_daemon_assigned_path() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let socket = directory.path().join("control.sock");
    let listener = UnixListener::bind(&socket).expect("fake control socket should bind");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("CLI should connect");
        let mut header = [0; 4];
        stream
            .read_exact(&mut header)
            .expect("request frame header should arrive");
        let mut request = vec![0; u32::from_be_bytes(header) as usize];
        stream
            .read_exact(&mut request)
            .expect("request frame should arrive");
        let request = String::from_utf8(request).expect("request should be UTF-8 TOML");
        assert!(request.contains("socket_name = \"cladding/github.sock\""));

        let response = br#"{"version":2,"ok":true,"result":{"id":"named_session","socket":"/run/baffle/proxies/cladding/github.sock","persistent":true,"ca_certificate_pem":"test-ca-pem","credential_seed_base64url":"exact-client-api-seed"}}"#;
        stream
            .write_all(&(response.len() as u32).to_be_bytes())
            .expect("response frame header should be sent");
        stream
            .write_all(response)
            .expect("response frame should be sent");
    });

    let config = directory.path().join("inline.toml");
    fs::write(
        &config,
        "version = 2\npersistent = true\nsocket_name = \"cladding/github.sock\"\n\n[rules.\"github.com\"]\n",
    )
    .expect("inline session config should be written");
    let output = Command::new(env!("CARGO_BIN_EXE_baffle"))
        .arg("--control-socket")
        .arg(&socket)
        .arg("create")
        .arg("--config")
        .arg(config)
        .output()
        .expect("create command should run");
    server.join().expect("fake control server should finish");

    assert!(
        output.status.success(),
        "create failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response = parse_json_stdout(&output.stdout);
    assert_eq!(response["id"], "named_session");
    assert_eq!(
        response["socket"],
        "/run/baffle/proxies/cladding/github.sock"
    );
    assert_eq!(response["persistent"], true);
    assert_eq!(response["ca_certificate_pem"], "test-ca-pem");
    assert_eq!(
        response["credential_seed_base64url"],
        "exact-client-api-seed"
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains("exact-client-api-seed"));
}

#[test]
fn file_only_create_uses_nested_server_file_and_rejects_inline_config() {
    let daemon = TestDaemon::start(true);
    let nested_dir = daemon.session_config_dir.join("cladding");
    fs::create_dir(&nested_dir).expect("nested session directory should be created");
    fs::write(
        nested_dir.join("github.toml"),
        "version = 2\npersistent = true\n\n[rules.\"github.com\"]\n",
    )
    .expect("daemon session file should be written");
    let local_config = inline_config(daemon.directory(), false);

    let rejected = daemon
        .cli()
        .arg("create")
        .arg("--config")
        .arg(local_config)
        .output()
        .expect("inline create command should run");
    assert!(!rejected.status.success());
    let error = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        error.contains("file_only mode"),
        "unexpected error: {error}"
    );
    assert!(error.contains("server-relative-file.toml"));

    let created = daemon
        .cli()
        .arg("create")
        .arg("cladding/github.toml")
        .output()
        .expect("file-backed create command should run");
    assert!(
        created.status.success(),
        "file-backed create failed: {}",
        String::from_utf8_lossy(&created.stderr)
    );
    let create_json = parse_json_stdout(&created.stdout);
    assert_eq!(create_json["persistent"], true);
    assert!(
        create_json["socket"]
            .as_str()
            .unwrap()
            .contains("/proxies/")
    );
    assert!(!String::from_utf8_lossy(&created.stdout).contains("github.toml"));
    let seed = create_json["credential_seed_base64url"]
        .as_str()
        .expect("create JSON should include the session seed");

    let listed = daemon.list();
    let list_json = parse_json_stdout(listed.as_bytes());
    assert_eq!(list_json["sessions"][0]["persistent"], true);
    assert!(!listed.contains(seed), "list must not expose session seeds");
    assert!(
        list_json["sessions"][0]
            .get("credential_seed_base64url")
            .is_none()
    );
    let id = create_json["id"]
        .as_str()
        .expect("create JSON should include ID");
    let stopped = daemon
        .cli()
        .arg("stop")
        .arg(id)
        .output()
        .expect("persistent session should stop");
    assert!(stopped.status.success());
    assert_eq!(
        parse_json_stdout(daemon.list().as_bytes())["sessions"],
        serde_json::json!([])
    );
}

#[test]
fn reload_cli_reports_per_session_results_and_fails_when_any_all_result_fails() {
    let daemon = TestDaemon::start(true);
    let first_config = daemon.session_config_dir.join("first.toml");
    let second_config = daemon.session_config_dir.join("second.toml");
    let policy = |host: &str| format!("version = 2\npersistent = true\n\n[rules.{host:?}]\n");
    fs::write(&first_config, policy("first.example")).expect("first policy should be written");
    fs::write(&second_config, policy("second.example")).expect("second policy should be written");

    let first = daemon
        .cli()
        .arg("create")
        .arg("first.toml")
        .output()
        .expect("first session should be created");
    assert!(first.status.success());
    let first_json = parse_json_stdout(&first.stdout);
    let first_id = first_json["id"]
        .as_str()
        .expect("create JSON should include ID")
        .to_owned();
    let first_seed = first_json["credential_seed_base64url"]
        .as_str()
        .expect("create JSON should include seed")
        .to_owned();
    let second = daemon
        .cli()
        .arg("create")
        .arg("second.toml")
        .output()
        .expect("second session should be created");
    assert!(second.status.success());
    let second_json = parse_json_stdout(&second.stdout);
    let second_id = second_json["id"]
        .as_str()
        .expect("create JSON should include ID")
        .to_owned();
    let second_seed = second_json["credential_seed_base64url"]
        .as_str()
        .expect("create JSON should include seed")
        .to_owned();

    let one = daemon
        .cli()
        .arg("reload")
        .arg(&first_id)
        .output()
        .expect("reload by ID should run");
    assert!(
        one.status.success(),
        "reload failed: {}",
        String::from_utf8_lossy(&one.stderr)
    );
    let one_json = parse_json_stdout(&one.stdout);
    assert_eq!(one_json["results"][0]["status"], "unchanged");
    assert_eq!(one_json["results"][0]["id"], first_id);
    assert!(!String::from_utf8_lossy(&one.stdout).contains(&first_seed));
    assert!(!String::from_utf8_lossy(&one.stdout).contains(&second_seed));

    fs::remove_file(&second_config).expect("second source file should be removed");
    let all = daemon
        .cli()
        .arg("reload")
        .arg("--all")
        .output()
        .expect("reload --all should run");
    assert!(
        !all.status.success(),
        "one failed result should set failure status"
    );
    let all_json = parse_json_stdout(&all.stdout);
    let all_results = all_json["results"]
        .as_array()
        .expect("reload JSON should contain result entries");
    assert_eq!(all_results.len(), 2);
    assert!(
        all_results
            .iter()
            .any(|result| result["status"] == "unchanged")
    );
    let failed = all_results
        .iter()
        .find(|result| result["status"] == "failed")
        .expect("reload JSON should include the failed result");
    assert!(failed["detail"].as_str().unwrap().contains("second.toml"));
    assert!(failed["detail"].as_str().unwrap().contains("not found"));
    assert!(!String::from_utf8_lossy(&all.stdout).contains(&first_seed));
    assert!(!String::from_utf8_lossy(&all.stdout).contains(&second_seed));
    assert!(!String::from_utf8_lossy(&all.stderr).contains(&first_seed));
    assert!(!String::from_utf8_lossy(&all.stderr).contains(&second_seed));

    for id in [first_id, second_id] {
        let stopped = daemon
            .cli()
            .arg("stop")
            .arg(id)
            .output()
            .expect("session should stop");
        assert!(stopped.status.success());
    }
}

#[test]
fn cli_reports_unavailable_control_socket_and_sigterm_releases_lease() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let unavailable = Command::new(env!("CARGO_BIN_EXE_baffle"))
        .arg("--control-socket")
        .arg(directory.path().join("missing.sock"))
        .arg("list")
        .output()
        .expect("list command should run");
    assert!(!unavailable.status.success());
    assert!(
        unavailable.stdout.is_empty(),
        "errors must not write partial JSON"
    );
    assert!(String::from_utf8_lossy(&unavailable.stderr).contains("control socket"));
    assert!(String::from_utf8_lossy(&unavailable.stderr).contains("unavailable"));

    let daemon = TestDaemon::start(false);
    let config = inline_config(daemon.directory(), false);
    let mut create = AttachedCreate::start(&daemon, &config);
    let status = create.signal_and_wait("TERM");
    assert!(status.success(), "SIGTERM should close the lease: {status}");
    let listed = wait_for_session_release(&daemon, &create, &[]);
    assert_eq!(
        parse_json_stdout(listed.as_bytes())["sessions"],
        serde_json::json!([])
    );

    let mut disconnected = AttachedCreate::start(&daemon, &config);
    let sent = Command::new("kill")
        .arg("-KILL")
        .arg(disconnected.child.id().to_string())
        .status()
        .expect("kill command should be available");
    assert!(sent.success(), "could not terminate the CLI process");
    let status = wait_for_exit(&mut disconnected.child);
    assert!(
        !status.success(),
        "SIGKILL should terminate the CLI process"
    );
    let listed = wait_for_session_release(&daemon, &disconnected, &[]);
    assert_eq!(
        parse_json_stdout(listed.as_bytes())["sessions"],
        serde_json::json!([])
    );
}

#[test]
fn ca_init_resolves_daemon_paths_from_the_config_directory() {
    let workspace = tempfile::tempdir().expect("temporary directory should be created");
    let config_directory = workspace.path().join("config");
    let other_working_directory = workspace.path().join("elsewhere");
    fs::create_dir(&config_directory).expect("config directory should be created");
    fs::create_dir(&other_working_directory).expect("other working directory should be created");
    fs::create_dir(config_directory.join("state")).expect("CA directory should be created");
    std::os::unix::fs::symlink(&other_working_directory, config_directory.join("linked"))
        .expect("socket directory symlink should be created");
    let config_path = config_directory.join("daemon.toml");
    fs::write(
        &config_path,
        r#"
[daemon]
control_socket = "linked/control.sock"
socket_dir = "run/proxies"
trusted_operator_uid = 1000

[ca]
certificate = "state/ca.pem"
private_key = "state/ca-key.pem"

[secrets]
directory = "state/secrets"
"#,
    )
    .expect("daemon config should be written");

    let output = Command::new(env!("CARGO_BIN_EXE_baffle"))
        .current_dir(&other_working_directory)
        .args(["ca", "init", "--config"])
        .arg(&config_path)
        .output()
        .expect("CA initialization command should run");
    assert!(
        output.status.success(),
        "CA initialization failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let initialized = parse_json_stdout(&output.stdout);
    assert_eq!(initialized["initialized"], true);
    assert_eq!(
        initialized["certificate"],
        config_directory.join("state/ca.pem").display().to_string()
    );
    assert_eq!(
        initialized["private_key"],
        config_directory
            .join("state/ca-key.pem")
            .display()
            .to_string()
    );
    assert_eq!(initialized["trust_store_installed"], false);
    assert!(config_directory.join("state/ca.pem").is_file());
    assert!(config_directory.join("state/ca-key.pem").is_file());
    assert!(!other_working_directory.join("state/ca.pem").exists());

    let export_path = config_directory.join("state/exported-ca.pem");
    let exported = Command::new(env!("CARGO_BIN_EXE_baffle"))
        .current_dir(&other_working_directory)
        .args(["ca", "export", "--config"])
        .arg(&config_path)
        .arg("--output")
        .arg(&export_path)
        .output()
        .expect("CA export command should run");
    assert!(
        exported.status.success(),
        "CA export failed: {}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let export_json = parse_json_stdout(&exported.stdout);
    assert_eq!(export_json["exported"], true);
    assert_eq!(export_json["output"], export_path.display().to_string());
    assert_eq!(
        fs::read(&export_path).expect("exported certificate should exist"),
        fs::read(config_directory.join("state/ca.pem")).expect("CA certificate should exist")
    );

    let daemon = Command::new(env!("CARGO_BIN_EXE_baffle"))
        .current_dir(&other_working_directory)
        .args(["daemon", "--config"])
        .arg(&config_path)
        .output()
        .expect("daemon command should run");
    assert!(
        !daemon.status.success(),
        "daemon must reject a socket path through a symlink"
    );
    assert!(
        String::from_utf8_lossy(&daemon.stderr)
            .contains("control socket directory path contains a non-directory component"),
        "unexpected daemon error: {}",
        String::from_utf8_lossy(&daemon.stderr)
    );
    assert!(daemon.stdout.is_empty(), "daemon logs must not use stdout");
    assert!(!other_working_directory.join("control.sock").exists());
}

#[test]
fn malformed_server_filename_is_rejected_before_control_io() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let output = Command::new(env!("CARGO_BIN_EXE_baffle"))
        .arg("--control-socket")
        .arg(directory.path().join("missing.sock"))
        .arg("create")
        .arg("../github.toml")
        .output()
        .expect("create command should run");
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "errors must not write partial JSON"
    );
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("session configuration name is invalid"));
    assert!(!error.contains("unavailable"));
}

#[test]
fn stop_reports_stale_ids_and_list_reports_protocol_mismatches() {
    let daemon = TestDaemon::start(false);
    let stale = daemon
        .cli()
        .arg("stop")
        .arg("stale_session_id")
        .output()
        .expect("stop command should run");
    assert!(!stale.status.success());
    assert!(
        stale.stdout.is_empty(),
        "errors must not write partial JSON"
    );
    assert!(String::from_utf8_lossy(&stale.stderr).contains("session not found"));

    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let socket = directory.path().join("version.sock");
    let listener = UnixListener::bind(&socket).expect("fake control socket should bind");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("CLI should connect");
        let mut header = [0; 4];
        stream
            .read_exact(&mut header)
            .expect("request frame header should arrive");
        let mut request = vec![0; u32::from_be_bytes(header) as usize];
        stream
            .read_exact(&mut request)
            .expect("request frame should arrive");
        let response = br#"{"version":9,"ok":true,"result":{"sessions":[]}}"#;
        stream
            .write_all(&(response.len() as u32).to_be_bytes())
            .expect("response frame header should be sent");
        stream
            .write_all(response)
            .expect("response frame should be sent");
    });
    let mismatch = Command::new(env!("CARGO_BIN_EXE_baffle"))
        .arg("--control-socket")
        .arg(socket)
        .arg("list")
        .output()
        .expect("list command should run");
    server.join().expect("fake control server should finish");
    assert!(!mismatch.status.success());
    assert!(
        mismatch.stdout.is_empty(),
        "errors must not write partial JSON"
    );
    let error = String::from_utf8_lossy(&mismatch.stderr);
    assert!(
        error.contains("protocol mismatch"),
        "unexpected error: {error}"
    );
    assert!(error.contains("daemon returned version 9"));
}

#[test]
fn list_stop_and_create_appear_in_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_baffle"))
        .arg("--help")
        .output()
        .expect("help should run");
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).expect("help should be UTF-8");
    for command in ["daemon", "create", "list", "stop", "ca"] {
        assert!(help.contains(command), "help should include {command}");
    }
    assert!(help.contains("--control-socket"));
    assert!(help.contains("/run/baffle/control.sock"));
}
