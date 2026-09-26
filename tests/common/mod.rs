//! Shared fixtures for backend-neutral, real-daemon integration tests.

#![cfg(target_os = "linux")]

use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use serde_json::Value;
use tempfile::TempDir;

pub struct DaemonProcess {
    child: Child,
    pub directory: TempDir,
    pub control_socket: PathBuf,
    pub secrets_dir: PathBuf,
    pub ca_certificate: PathBuf,
    pub log_path: PathBuf,
}

impl Drop for DaemonProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl DaemonProcess {
    pub fn start(max_sessions: usize, allowed_secrets: &[&str]) -> Self {
        Self::start_with_upstream_ca(max_sessions, allowed_secrets, None)
    }

    pub fn start_with_upstream_ca(
        max_sessions: usize,
        allowed_secrets: &[&str],
        upstream_ca: Option<&Path>,
    ) -> Self {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let control_socket = directory.path().join("run/control.sock");
        let socket_dir = directory.path().join("proxies");
        let secrets_dir = directory.path().join("secrets");
        fs::create_dir(&secrets_dir).expect("secret directory should be created");
        fs::set_permissions(&secrets_dir, fs::Permissions::from_mode(0o700))
            .expect("secret directory should be private");
        let config_path = directory.path().join("daemon.toml");
        let log_path = directory.path().join("daemon.log");
        let log_file = fs::File::create(&log_path).expect("daemon log file should be created");
        let (certificate_path, private_key_path) = write_test_ca(directory.path());
        let trusted_uid = fs::metadata(directory.path())
            .expect("temporary directory should have metadata")
            .uid();
        let allowed = allowed_secrets
            .iter()
            .map(|name| format!("\"{name}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let config = format!(
            "[daemon]\ncontrol_socket = \"{}\"\nsocket_dir = \"{}\"\ntrusted_operator_uid = {trusted_uid}\nmax_sessions = {max_sessions}\n\n[ca]\ncertificate = \"{}\"\nprivate_key = \"{}\"\n\n[secrets]\ndirectory = \"{}\"\nallowed = [{allowed}]\n",
            control_socket.display(),
            socket_dir.display(),
            certificate_path.display(),
            private_key_path.display(),
            secrets_dir.display(),
        );
        fs::write(&config_path, config).expect("daemon config should be written");
        let mut command = Command::new(env!("CARGO_BIN_EXE_baffle"));
        command
            .arg("daemon")
            .arg("--config")
            .arg(&config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::from(log_file));
        if let Some(upstream_ca) = upstream_ca {
            command.env("BAFFLE_TEST_UPSTREAM_CA", upstream_ca);
        }
        let child = command.spawn().expect("daemon should start");
        let mut daemon = Self {
            child,
            directory,
            control_socket,
            secrets_dir,
            ca_certificate: certificate_path,
            log_path,
        };

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if daemon.control_socket.exists() {
                return daemon;
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
                "daemon should bind its control socket"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn control(&self) -> UnixStream {
        let stream = UnixStream::connect(&self.control_socket)
            .expect("control client should connect to the running daemon");
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .expect("control response timeout should be set");
        stream
    }

    pub fn request(&self, request: &str) -> (Vec<u8>, Value) {
        let mut control = self.control();
        request_on(&mut control, request)
    }

    pub fn create_session(&self, control: &mut UnixStream, request: &str) -> (Vec<u8>, Value) {
        request_on(control, request)
    }

    pub fn write_secret(&self, name: &str, value: &str) -> PathBuf {
        let path = self.secrets_dir.join(name);
        fs::write(&path, value).expect("test secret should be written");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("test secret should be private");
        path
    }
}

pub fn write_test_ca(directory: &Path) -> (PathBuf, PathBuf) {
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

pub fn request_on(control: &mut UnixStream, request: &str) -> (Vec<u8>, Value) {
    let payload = request.as_bytes();
    let length = u32::try_from(payload.len()).expect("control request should fit a frame");
    control
        .write_all(&length.to_be_bytes())
        .expect("control frame header should be written");
    control
        .write_all(payload)
        .expect("control request should be written");
    let mut header = [0; 4];
    control
        .read_exact(&mut header)
        .expect("control response header should be read");
    let length = u32::from_be_bytes(header) as usize;
    assert!(
        length <= 256 * 1024,
        "control response should fit one frame"
    );
    let mut body = vec![0; length];
    control
        .read_exact(&mut body)
        .expect("control response should be read");
    let response = serde_json::from_slice(&body).expect("control response should be JSON");
    (body, response)
}

pub fn socket_from(response: &Value) -> PathBuf {
    PathBuf::from(
        response["result"]["socket"]
            .as_str()
            .expect("create response should contain an assigned Unix socket"),
    )
}
