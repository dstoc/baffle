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
        fs, thread,
        time::{Duration, Instant},
    };

    let config_dir = tempfile::tempdir().expect("temporary config directory should be created");
    let config_path = config_dir.path().join("daemon.toml");
    fs::write(&config_path, "[daemon]\n").expect("temporary config should be written");

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
}
