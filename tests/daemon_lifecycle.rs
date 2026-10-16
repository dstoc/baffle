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

#[test]
fn ca_init_reports_invalid_daemon_configuration() {
    let directory = tempfile::tempdir().expect("temporary config directory should be created");
    let config_path = directory.path().join("daemon.toml");
    std::fs::write(&config_path, "[daemon]\n").expect("invalid daemon config should be written");

    let output = Command::new(env!("CARGO_BIN_EXE_baffle"))
        .arg("ca")
        .arg("init")
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("CA init command should run");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid daemon configuration at"));
    assert!(stderr.contains(&config_path.display().to_string()));
}

#[cfg(unix)]
#[test]
fn daemon_starts_and_stops_on_interrupt() {
    use std::{
        fs,
        io::{Read, Write},
        os::unix::{fs::MetadataExt, net::UnixStream},
        path::PathBuf,
        thread,
        time::{Duration, Instant},
    };

    let config_dir = tempfile::tempdir().expect("temporary config directory should be created");
    let config_path = config_dir.path().join("daemon.toml");
    let certificate_path = config_dir.path().join("ca.pem");
    let private_key_path = config_dir.path().join("ca-key.pem");
    let control_socket = config_dir.path().join("run/control.sock");
    let socket_directory =
        tempfile::tempdir_in("/tmp").expect("short temporary socket directory should be created");
    let socket_dir = socket_directory.path().join("proxies");
    let daemon_log = config_dir.path().join("daemon.log");
    let daemon_log_file = fs::File::create(&daemon_log).expect("daemon log should be created");
    let trusted_uid = fs::metadata(config_dir.path())
        .expect("temporary directory should have metadata")
        .uid();
    let config = format!(
        r#"
[daemon]
control_socket = "{control_socket}"
socket_dir = "{socket_dir}"
trusted_operator_uid = {trusted_uid}

[ca]
certificate = "{certificate}"
private_key = "{private_key}"

[secrets]
directory = "{secrets}"
"#,
        control_socket = control_socket.display(),
        socket_dir = socket_dir.display(),
        certificate = certificate_path.display(),
        private_key = private_key_path.display(),
        secrets = config_dir.path().join("secrets").display(),
    );
    fs::write(&config_path, config).expect("temporary config should be written");

    let initialize = Command::new(env!("CARGO_BIN_EXE_baffle"))
        .arg("ca")
        .arg("init")
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("CA init command should run");
    assert!(
        initialize.status.success(),
        "CA init should succeed: {}",
        String::from_utf8_lossy(&initialize.stderr)
    );
    let initialize_stdout = String::from_utf8_lossy(&initialize.stdout);
    assert!(initialize_stdout.contains("Created Baffle interception CA"));
    assert!(initialize_stdout.contains(&certificate_path.display().to_string()));
    assert!(initialize_stdout.contains(&private_key_path.display().to_string()));
    let initialize_output = format!(
        "{}{}",
        initialize_stdout,
        String::from_utf8_lossy(&initialize.stderr)
    );
    assert!(!initialize_output.contains("PRIVATE KEY"));

    let exported_certificate = config_dir.path().join("exported-ca.pem");
    let export = Command::new(env!("CARGO_BIN_EXE_baffle"))
        .arg("ca")
        .arg("export")
        .arg("--config")
        .arg(&config_path)
        .arg("--output")
        .arg(&exported_certificate)
        .output()
        .expect("CA export command should run");
    assert!(
        export.status.success(),
        "CA export should work after init: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    assert_eq!(
        fs::read(&exported_certificate).expect("exported CA should be readable"),
        fs::read(&certificate_path).expect("initialized CA should be readable")
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_baffle"))
        .arg("daemon")
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::from(daemon_log_file))
        .spawn()
        .expect("daemon process should start");

    let startup_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if control_socket.exists() {
            break;
        }
        if let Some(status) = child.try_wait().expect("daemon status should be readable") {
            panic!("daemon exited before binding its control socket: {status}");
        }
        assert!(
            Instant::now() < startup_deadline,
            "daemon should bind its control socket before the startup deadline"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        child
            .try_wait()
            .expect("daemon status should be readable")
            .is_none(),
        "daemon should remain alive after startup"
    );
    assert!(control_socket.exists(), "daemon should bind control socket");

    let request = b"version = 1\noperation = \"create\"\n\n[session]\npersistent = true\n\n[[rules]]\nhost = \"shutdown.example.test\"\nmode = \"tunnel\"\n";
    let mut control = UnixStream::connect(&control_socket).expect("control client should connect");
    control
        .write_all(&(request.len() as u32).to_be_bytes())
        .expect("control frame header should be written");
    control
        .write_all(request)
        .expect("control request should be written");
    let mut response_header = [0; 4];
    control
        .read_exact(&mut response_header)
        .expect("control response header should be read");
    let mut response_body = vec![0; u32::from_be_bytes(response_header) as usize];
    control
        .read_exact(&mut response_body)
        .expect("control response should be read");
    let response: serde_json::Value =
        serde_json::from_slice(&response_body).expect("control response should be JSON");
    assert_eq!(
        response["ok"],
        true,
        "daemon rejected a valid create request: {response:?}; daemon log: {}",
        fs::read_to_string(&daemon_log)
            .unwrap_or_else(|error| format!("could not read log: {error}"))
    );
    let proxy_socket = PathBuf::from(
        response["result"]["socket"]
            .as_str()
            .expect("create response should include the proxy socket"),
    );
    drop(control);
    assert!(proxy_socket.exists(), "persistent session should be active");

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
    assert!(
        !proxy_socket.exists(),
        "daemon should remove every session socket during shutdown"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn daemon_starts_with_socket_directory_under_var_run_alias() {
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::Path,
        process::Child,
        thread,
        time::{Duration, Instant},
    };

    if !fs::symlink_metadata("/var/run").is_ok_and(|metadata| metadata.file_type().is_symlink())
        || !fs::read_link("/var/run").is_ok_and(|target| target == Path::new("/run"))
    {
        return;
    }

    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let config_directory = tempfile::tempdir().expect("temporary config directory should exist");
    let socket_root = match tempfile::tempdir_in("/run/lock") {
        Ok(directory) => directory,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied
                    | std::io::ErrorKind::ReadOnlyFilesystem
                    | std::io::ErrorKind::NotFound
            ) =>
        {
            eprintln!("Skipping daemon /var/run startup fixture: {error}");
            return;
        }
        Err(error) => panic!("temporary socket root should be created: {error}"),
    };
    let alias_socket_dir = Path::new("/var/run/lock")
        .join(
            socket_root
                .path()
                .file_name()
                .expect("socket root has a name"),
        )
        .join("proxies");
    let config_path = config_directory.path().join("daemon.toml");
    let control_socket = config_directory.path().join("run/control.sock");
    let certificate_path = config_directory.path().join("ca.pem");
    let private_key_path = config_directory.path().join("ca-key.pem");
    let secrets_directory = config_directory.path().join("secrets");
    fs::create_dir(&secrets_directory).expect("secrets directory should be created");
    fs::set_permissions(&secrets_directory, fs::Permissions::from_mode(0o700))
        .expect("secrets directory should be private");
    let trusted_uid = fs::metadata(config_directory.path())
        .expect("config directory should have metadata")
        .uid();
    fs::write(
        &config_path,
        format!(
            "[daemon]\ncontrol_socket = \"{}\"\nsocket_dir = \"{}\"\ntrusted_operator_uid = {trusted_uid}\n\n[ca]\ncertificate = \"{}\"\nprivate_key = \"{}\"\n\n[secrets]\ndirectory = \"{}\"\n",
            control_socket.display(),
            alias_socket_dir.display(),
            certificate_path.display(),
            private_key_path.display(),
            secrets_directory.display(),
        ),
    )
    .expect("daemon config should be written");

    let initialize = Command::new(env!("CARGO_BIN_EXE_baffle"))
        .arg("ca")
        .arg("init")
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("CA initialization should run");
    assert!(
        initialize.status.success(),
        "CA initialization should succeed: {}",
        String::from_utf8_lossy(&initialize.stderr)
    );

    let daemon_log = config_directory.path().join("daemon.log");
    let daemon_log_file = fs::File::create(&daemon_log).expect("daemon log should be created");
    let child = Command::new(env!("CARGO_BIN_EXE_baffle"))
        .arg("daemon")
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::from(daemon_log_file))
        .spawn()
        .expect("daemon process should start");
    let mut child = ChildGuard(child);

    let startup_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if control_socket.exists() {
            break;
        }
        if let Some(status) = child
            .0
            .try_wait()
            .expect("daemon status should be readable")
        {
            panic!(
                "daemon exited before startup through /var/run: {status}; log: {}",
                fs::read_to_string(&daemon_log).unwrap_or_default()
            );
        }
        assert!(
            Instant::now() < startup_deadline,
            "daemon should start with a socket directory under /var/run"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        socket_root.path().join("proxies").is_dir(),
        "daemon should create its configured socket directory through the alias"
    );
    assert_eq!(
        fs::metadata(socket_root.path().join("proxies"))
            .expect("socket directory should have metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    let signal = Command::new("kill")
        .arg("-INT")
        .arg(child.0.id().to_string())
        .status()
        .expect("kill command should be available");
    assert!(signal.success(), "daemon should receive SIGINT");
    let shutdown_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child
            .0
            .try_wait()
            .expect("daemon status should be readable")
        {
            assert!(status.success(), "daemon should stop cleanly: {status}");
            break;
        }
        assert!(
            Instant::now() < shutdown_deadline,
            "daemon should stop after SIGINT"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !control_socket.exists(),
        "daemon should remove control socket"
    );
}

#[cfg(unix)]
#[test]
fn daemon_does_not_start_when_ca_material_is_missing() {
    use std::fs;

    let config_dir = tempfile::tempdir().expect("temporary config directory should be created");
    let config_path = config_dir.path().join("daemon.toml");
    let config = format!(
        r#"
[daemon]
control_socket = "{control_socket}"
socket_dir = "{socket_dir}"

[ca]
certificate = "{certificate}"
private_key = "{private_key}"

[secrets]
directory = "{secrets}"
"#,
        control_socket = config_dir.path().join("control.sock").display(),
        socket_dir = config_dir.path().join("proxies").display(),
        certificate = config_dir.path().join("missing-ca.pem").display(),
        private_key = config_dir.path().join("missing-key.pem").display(),
        secrets = config_dir.path().join("secrets").display(),
    );
    fs::write(&config_path, config).expect("temporary config should be written");

    let output = Command::new(env!("CARGO_BIN_EXE_baffle"))
        .arg("daemon")
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("daemon process should start");

    assert!(
        !output.status.success(),
        "daemon must reject missing CA files"
    );
}

#[cfg(unix)]
#[test]
fn daemon_validates_file_only_store_before_binding_control_socket() {
    use std::{
        fs,
        os::unix::{
            fs::{MetadataExt, PermissionsExt},
            net::UnixStream,
        },
        thread,
        time::{Duration, Instant},
    };

    let directory = tempfile::tempdir().expect("temporary config directory should be created");
    let config_path = directory.path().join("daemon.toml");
    let certificate_path = directory.path().join("ca.pem");
    let private_key_path = directory.path().join("ca-key.pem");
    let control_socket = directory.path().join("run/control.sock");
    let socket_dir = directory.path().join("proxies");
    let daemon_log = directory.path().join("daemon.log");
    let session_root = directory.path().join("sessions");
    fs::create_dir(&session_root).expect("session root should be created");
    let mut session_config_dir = session_root;
    for _ in 0..200 {
        session_config_dir.push("s");
        fs::create_dir(&session_config_dir).expect("nested session directory should be created");
    }
    fs::set_permissions(&session_config_dir, fs::Permissions::from_mode(0o720))
        .expect("final session directory should have unsafe permissions");

    let trusted_uid = fs::metadata(directory.path())
        .expect("temporary directory should have metadata")
        .uid();
    let config = format!(
        r#"
[daemon]
control_socket = "{control_socket}"
socket_dir = "{socket_dir}"
trusted_operator_uid = {trusted_uid}
create_mode = "file_only"
session_config_dir = "{session_config_dir}"

[ca]
certificate = "{certificate}"
private_key = "{private_key}"

[secrets]
directory = "{secrets}"
"#,
        control_socket = control_socket.display(),
        socket_dir = socket_dir.display(),
        session_config_dir = session_config_dir.display(),
        certificate = certificate_path.display(),
        private_key = private_key_path.display(),
        secrets = directory.path().join("secrets").display(),
    );
    fs::write(&config_path, config).expect("temporary config should be written");

    let initialize = std::process::Command::new(env!("CARGO_BIN_EXE_baffle"))
        .arg("ca")
        .arg("init")
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("CA init command should run");
    assert!(
        initialize.status.success(),
        "CA init should succeed: {}",
        String::from_utf8_lossy(&initialize.stderr)
    );

    let daemon_log_file = fs::File::create(&daemon_log).expect("daemon log should be created");
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_baffle"))
        .arg("daemon")
        .arg("--config")
        .arg(&config_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::from(daemon_log_file))
        .spawn()
        .expect("daemon process should start");

    let startup_deadline = Instant::now() + Duration::from_secs(5);
    let mut connected_during_startup = false;
    let mut socket_path_existed_during_startup = false;
    let exit_status = loop {
        if let Some(status) = child.try_wait().expect("daemon status should be readable") {
            break status;
        }
        socket_path_existed_during_startup |= control_socket.exists();
        if UnixStream::connect(&control_socket).is_ok() {
            connected_during_startup = true;
        }
        if Instant::now() >= startup_deadline {
            let _ = child.kill();
            panic!("daemon did not reject the invalid session directory");
        }
        thread::sleep(Duration::from_millis(1));
    };

    let log = fs::read_to_string(&daemon_log).expect("daemon log should be readable");
    assert!(
        !exit_status.success(),
        "daemon should reject unsafe session directory permissions"
    );
    assert!(
        !socket_path_existed_during_startup,
        "control socket path must not exist during failed startup"
    );
    assert!(
        !connected_during_startup,
        "a client must not connect during failed startup"
    );
    assert!(
        !log.contains("control socket listening"),
        "failed startup must not log listener readiness: {log}"
    );
    assert!(
        log.contains("session configuration directory has unsafe ownership or permissions"),
        "daemon should report the session directory validation error: {log}"
    );
    assert!(
        !control_socket.exists(),
        "failed startup must not leave a control socket"
    );
}
