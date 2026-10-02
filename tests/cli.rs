#![cfg(target_os = "linux")]

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::{
        fs::MetadataExt,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, ChildStdout, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use tempfile::TempDir;

struct TestDaemon {
    child: Child,
    _directory: TempDir,
    control_socket: PathBuf,
    session_config_dir: PathBuf,
}

impl TestDaemon {
    fn start(file_only: bool) -> Self {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let root = directory.path();
        let (certificate_path, private_key_path) = write_test_ca(root);
        let control_socket = root.join("run/control.sock");
        let socket_dir = root.join("proxies");
        let session_config_dir = root.join("sessions");
        fs::create_dir_all(&session_config_dir).expect("session config directory should exist");
        let trusted_uid = fs::metadata(root)
            .expect("temporary directory should have metadata")
            .uid();
        let mut mode = String::new();
        if file_only {
            mode = format!(
                "session_config_dir = \"{}\"\ncreate_mode = \"file_only\"\n",
                session_config_dir.display()
            );
        }
        let config = format!(
            "[daemon]\ncontrol_socket = \"{}\"\nsocket_dir = \"{}\"\ntrusted_operator_uid = {}\n{}\n[ca]\ncertificate = \"{}\"\nprivate_key = \"{}\"\n\n[secrets]\ndirectory = \"{}\"\n",
            control_socket.display(),
            socket_dir.display(),
            trusted_uid,
            mode,
            certificate_path.display(),
            private_key_path.display(),
            root.join("secrets").display(),
        );
        let config_path = root.join("daemon.toml");
        fs::write(&config_path, config).expect("daemon config should be written");

        let child = Command::new(env!("CARGO_BIN_EXE_baffle"))
            .arg("daemon")
            .arg("--config")
            .arg(config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("daemon process should start");

        let mut daemon = Self {
            child,
            _directory: directory,
            control_socket,
            session_config_dir,
        };
        daemon.wait_until_ready();
        daemon
    }

    fn wait_until_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !self.control_socket.exists() {
            if let Some(status) = self
                .child
                .try_wait()
                .expect("daemon status should be readable")
            {
                panic!("daemon exited before binding its control socket: {status}");
            }
            assert!(Instant::now() < deadline, "daemon did not become ready");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn cli(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_baffle"));
        command.arg("--control-socket").arg(&self.control_socket);
        command
    }

    fn list(&self) -> String {
        let output = self
            .cli()
            .arg("list")
            .output()
            .expect("list command should run");
        assert!(
            output.status.success(),
            "list failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("list output should be UTF-8")
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct AttachedCreate {
    child: Child,
    _stdout: BufReader<ChildStdout>,
    id: String,
    socket_path: PathBuf,
}

impl AttachedCreate {
    fn start(daemon: &TestDaemon, config: &Path) -> Self {
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
        let mut socket = String::new();
        stdout
            .read_line(&mut created)
            .expect("create status should be printed");
        stdout
            .read_line(&mut socket)
            .expect("data socket should be printed");
        let id = created
            .split_whitespace()
            .nth(3)
            .expect("create output should include the ID")
            .to_owned();
        let socket_path = PathBuf::from(
            socket
                .strip_prefix("Data socket: ")
                .expect("create output should label its data socket")
                .trim(),
        );
        assert!(
            child
                .try_wait()
                .expect("create status should be readable")
                .is_none(),
            "leased create must stay attached"
        );
        Self {
            child,
            _stdout: stdout,
            id,
            socket_path,
        }
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
    listed
        .lines()
        .any(|line| line.split('\t').next() == Some(session_id))
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

fn write_test_ca(directory: &Path) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;

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
    let config_a = inline_config(daemon._directory.path(), false);
    let config_b = inline_config(daemon._directory.path(), false);

    let mut first = AttachedCreate::start(&daemon, &config_a);
    let mut second = AttachedCreate::start(&daemon, &config_b);
    assert!(first.socket_path.exists());
    assert!(second.socket_path.exists());

    let listed = daemon.list();
    assert!(listed.contains("ID\tSTATUS\tTYPE\tDATA SOCKET"));
    assert!(listed.contains(&first.id));
    assert!(listed.contains(&second.id));
    assert!(listed.contains("\trunning\tleased\t"));
    assert!(listed.contains(&first.socket_path.display().to_string()));
    assert!(listed.contains(&second.socket_path.display().to_string()));

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
    assert!(String::from_utf8_lossy(&stopped.stdout).contains(&first.id));
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
    assert!(
        listed.contains("No active sessions."),
        "all sessions should be released after both CLI processes exit:\n{listed}"
    );
}

#[test]
fn inline_create_accepts_empty_deny_and_unmatched_tunnel_policies() {
    let daemon = TestDaemon::start(false);

    for (name, setting, allowed_status) in [
        ("deny", "", &["403"][..]),
        ("tunnel", "unmatched = \"tunnel\"\n", &["200", "502"][..]),
    ] {
        let path = daemon._directory.path().join(format!("{name}.toml"));
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
        let stdout = String::from_utf8(created.stdout).expect("create output should be UTF-8");
        let mut lines = stdout.lines();
        let created_line = lines.next().expect("create output should include a status");
        let id = created_line
            .split_whitespace()
            .nth(3)
            .expect("create output should include the session ID");
        let socket_path = lines
            .next()
            .and_then(|line| line.strip_prefix("Data socket: "))
            .expect("create output should include the data socket");
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
    let config = inline_config(daemon._directory.path(), false);
    let mut first = AttachedCreate::start(&daemon, &config);
    let mut second = AttachedCreate::start(&daemon, &config);

    let second_status = second.signal_and_wait("INT");
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
    assert!(
        listed.contains("No active sessions."),
        "all sessions should be released after the first CLI exits:\n{listed}"
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

        let response = br#"{"version":1,"ok":true,"result":{"id":"named_session","socket":"/run/baffle/proxies/cladding/github.sock","persistent":true}}"#;
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
    let stdout = String::from_utf8(output.stdout).expect("create output should be UTF-8");
    assert!(stdout.contains("Created persistent session named_session"));
    assert!(stdout.contains("Data socket: /run/baffle/proxies/cladding/github.sock"));
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
    let local_config = inline_config(daemon._directory.path(), false);

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
    let stdout = String::from_utf8(created.stdout).expect("create output should be UTF-8");
    assert!(stdout.contains("Created persistent session"));
    assert!(stdout.contains("Data socket:"));
    assert!(stdout.contains("/proxies/"));
    assert!(!stdout.contains("github.toml"));

    let listed = daemon.list();
    assert!(listed.contains("persistent"));
    let id = stdout
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(3))
        .expect("persistent create should print session ID");
    let stopped = daemon
        .cli()
        .arg("stop")
        .arg(id)
        .output()
        .expect("persistent session should stop");
    assert!(stopped.status.success());
    assert!(daemon.list().contains("No active sessions."));
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
    let first_id = String::from_utf8(first.stdout)
        .expect("create output should be UTF-8")
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(3))
        .expect("create output should include the session ID")
        .to_owned();
    let second = daemon
        .cli()
        .arg("create")
        .arg("second.toml")
        .output()
        .expect("second session should be created");
    assert!(second.status.success());

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
    assert!(String::from_utf8_lossy(&one.stdout).contains("unchanged"));
    assert!(String::from_utf8_lossy(&one.stdout).contains(&first_id));

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
    let output = String::from_utf8_lossy(&all.stdout);
    assert!(
        output.contains("unchanged"),
        "successful result should be printed: {output}"
    );
    assert!(
        output.contains("failed"),
        "failed result should be printed: {output}"
    );
    assert!(
        output.contains("configuration file was not found"),
        "failure reason should be safe and specific: {output}"
    );

    for id in [
        first_id,
        String::from_utf8_lossy(&second.stdout)
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(3))
            .expect("second create should include the session ID")
            .to_owned(),
    ] {
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
    assert!(String::from_utf8_lossy(&unavailable.stderr).contains("control socket"));
    assert!(String::from_utf8_lossy(&unavailable.stderr).contains("unavailable"));

    let daemon = TestDaemon::start(false);
    let config = inline_config(daemon._directory.path(), false);
    let mut create = AttachedCreate::start(&daemon, &config);
    let status = create.signal_and_wait("TERM");
    assert!(status.success(), "SIGTERM should close the lease: {status}");
    let listed = wait_for_session_release(&daemon, &create, &[]);
    assert!(
        listed.contains("No active sessions."),
        "SIGTERM should release all sessions:\n{listed}"
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
    assert!(
        listed.contains("No active sessions."),
        "SIGKILL should release all sessions:\n{listed}"
    );
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
