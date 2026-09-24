use std::process::{Command, Stdio};

#[test]
fn binary_help_lists_daemon_command() {
    let output = Command::new(env!("CARGO_BIN_EXE_baffle"))
        .arg("--help")
        .output()
        .expect("baffle binary should start");

    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).expect("help should be UTF-8");
    assert!(help.contains("daemon"));
}

#[cfg(unix)]
#[test]
fn daemon_starts_and_stops_on_interrupt() {
    use std::{
        fs,
        os::unix::fs::MetadataExt,
        thread,
        time::{Duration, Instant},
    };

    let config_dir = tempfile::tempdir().expect("temporary config directory should be created");
    let config_path = config_dir.path().join("daemon.toml");
    let control_socket = config_dir.path().join("run/control.sock");
    let socket_dir = config_dir.path().join("proxies");
    let trusted_uid = fs::metadata(config_dir.path())
        .expect("temporary directory should have metadata")
        .uid();
    fs::write(
        &config_path,
        format!(
            r#"
[daemon]
control_socket = "{}"
socket_dir = "{}"
trusted_operator_uid = {trusted_uid}

[ca]
certificate = "/tmp/baffle-test/ca.pem"
private_key = "/tmp/baffle-test/ca-key.pem"

[secrets]
directory = "/tmp/baffle-test/secrets"
"#,
            control_socket.display(),
            socket_dir.display(),
        ),
    )
    .expect("temporary config should be written");

    let mut child = Command::new(env!("CARGO_BIN_EXE_baffle"))
        .arg("daemon")
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("daemon process should start");

    thread::sleep(Duration::from_millis(100));
    assert!(
        child
            .try_wait()
            .expect("daemon status should be readable")
            .is_none(),
        "daemon should remain alive after startup"
    );
    assert!(control_socket.exists(), "daemon should bind control socket");

    let signal = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status()
        .expect("the system kill command should be available");
    assert!(signal.success(), "daemon should receive SIGINT");

    let deadline = Instant::now() + Duration::from_secs(5);
    let exit_status = loop {
        if let Some(status) = child.try_wait().expect("daemon status should be readable") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("daemon did not stop after SIGINT");
        }
        thread::sleep(Duration::from_millis(10));
    };

    assert!(
        exit_status.success(),
        "daemon should exit cleanly after SIGINT: {exit_status}"
    );
    assert!(
        !control_socket.exists(),
        "daemon should remove the control socket during shutdown"
    );
}
