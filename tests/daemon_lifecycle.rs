use std::process::{Command, Stdio};

use hudsucker::rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};

#[cfg(unix)]
fn write_test_ca(directory: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
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
    std::fs::write(&certificate_path, certificate.pem()).expect("CA certificate should be saved");
    std::fs::write(&private_key_path, key_pair.serialize_pem()).expect("CA key should be saved");
    std::fs::set_permissions(&private_key_path, std::fs::Permissions::from_mode(0o600))
        .expect("CA key permissions should be restricted");
    (certificate_path, private_key_path)
}

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
        io::{Read, Write},
        os::unix::{fs::MetadataExt, net::UnixStream},
        path::PathBuf,
        thread,
        time::{Duration, Instant},
    };

    let config_dir = tempfile::tempdir().expect("temporary config directory should be created");
    let config_path = config_dir.path().join("daemon.toml");
    let (certificate_path, private_key_path) = write_test_ca(config_dir.path());
    let control_socket = config_dir.path().join("run/control.sock");
    let socket_dir = config_dir.path().join("proxies");
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
    assert_eq!(response["ok"], true);
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
