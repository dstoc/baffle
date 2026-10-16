//! Shared fixtures for backend-neutral, real-daemon integration tests.

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

use serde_json::Value;
use tempfile::TempDir;

mod test_ca;
pub(crate) use test_ca::write_test_ca;

pub struct DaemonProcess {
    child: Child,
    pub directory: TempDir,
    _socket_directory: TempDir,
    pub socket_dir: PathBuf,
    pub control_socket: PathBuf,
    pub secrets_dir: PathBuf,
    pub ca_certificate: PathBuf,
    pub log_path: PathBuf,
    pub session_config_dir: Option<PathBuf>,
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
        Self::start_with_options(max_sessions, allowed_secrets, upstream_ca, false, None)
    }

    pub fn start_with_io_timeout_ms(max_sessions: usize, io_timeout_ms: u64) -> Self {
        Self::start_with_options(max_sessions, &[], None, false, Some(io_timeout_ms))
    }

    pub fn start_file_only_with_upstream_ca(
        max_sessions: usize,
        allowed_secrets: &[&str],
        upstream_ca: Option<&Path>,
    ) -> Self {
        Self::start_with_options(max_sessions, allowed_secrets, upstream_ca, true, None)
    }

    #[allow(dead_code)] // Used by the CLI integration target.
    pub fn start_for_cli(file_only: bool) -> Self {
        Self::start_with_options(64, &[], None, file_only, None)
    }

    #[allow(dead_code)] // Used by the CLI integration target.
    pub fn cli(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_baffle"));
        command.arg("--control-socket").arg(&self.control_socket);
        command
    }

    #[allow(dead_code)] // Used by the CLI integration target.
    pub fn list(&self) -> String {
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

    fn start_with_options(
        max_sessions: usize,
        allowed_secrets: &[&str],
        upstream_ca: Option<&Path>,
        file_only: bool,
        io_timeout_ms: Option<u64>,
    ) -> Self {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let control_socket = directory.path().join("run/control.sock");
        let socket_directory =
            tempfile::tempdir_in("/tmp").expect("short socket directory should be created");
        let socket_dir = socket_directory.path().join("proxies");
        let secrets_dir = directory.path().join("secrets");
        fs::create_dir(&secrets_dir).expect("secret directory should be created");
        fs::set_permissions(&secrets_dir, fs::Permissions::from_mode(0o700))
            .expect("secret directory should be private");
        let session_config_dir = file_only.then(|| directory.path().join("sessions"));
        if let Some(path) = &session_config_dir {
            fs::create_dir(path).expect("session configuration directory should be created");
        }
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
        let file_config = session_config_dir
            .as_ref()
            .map(|path| {
                format!(
                    "create_mode = \"file_only\"\nsession_config_dir = \"{}\"\n",
                    path.display()
                )
            })
            .unwrap_or_default();
        let io_timeout_config = io_timeout_ms
            .map(|timeout_ms| format!("io_timeout_ms = {timeout_ms}\n"))
            .unwrap_or_default();
        let config = format!(
            "[daemon]\ncontrol_socket = \"{}\"\nsocket_dir = \"{}\"\ntrusted_operator_uid = {trusted_uid}\nmax_sessions = {max_sessions}\n{io_timeout_config}{file_config}\n[ca]\ncertificate = \"{}\"\nprivate_key = \"{}\"\n\n[secrets]\ndirectory = \"{}\"\nallowed = [{allowed}]\n",
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
            _socket_directory: socket_directory,
            socket_dir,
            control_socket,
            secrets_dir,
            ca_certificate: certificate_path,
            log_path,
            session_config_dir,
        };

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if daemon.control_socket.exists() {
                let socket_metadata = fs::symlink_metadata(&daemon.control_socket)
                    .expect("control socket should have metadata");
                assert_eq!(socket_metadata.uid(), trusted_uid);
                if socket_metadata.permissions().mode() & 0o777 == 0o600 {
                    assert_eq!(
                        fs::metadata(daemon.control_socket.parent().unwrap())
                            .expect("control directory should have metadata")
                            .permissions()
                            .mode()
                            & 0o777,
                        0o700
                    );
                    return daemon;
                }
            }
            if let Some(status) = daemon
                .child
                .try_wait()
                .expect("daemon status should be readable")
            {
                let log = fs::read_to_string(&daemon.log_path)
                    .unwrap_or_else(|error| format!("failed to read daemon log: {error}"));
                panic!("daemon exited before binding control socket: {status}\n{log}");
            }
            assert!(
                Instant::now() < deadline,
                "daemon should bind and secure its control socket"
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

    pub fn write_session_config(&self, name: &str, contents: &str) -> PathBuf {
        let directory = self
            .session_config_dir
            .as_ref()
            .expect("session configuration directory should be enabled");
        let path = directory.join(name);
        fs::create_dir_all(path.parent().expect("session config should have a parent"))
            .expect("session config parent directories should be created");
        fs::write(&path, contents).expect("session config should be written");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("session config should be private");
        path
    }

    pub fn create_from_file(&self, name: &str) -> (Vec<u8>, Value) {
        self.request(&format!(
            "version = 2\noperation = \"create_from_file\"\nname = {name:?}\n"
        ))
    }
}

pub fn request_on(control: &mut UnixStream, request: &str) -> (Vec<u8>, Value) {
    write_frame(control, request.as_bytes());
    read_response_frame(control)
}

#[allow(dead_code)] // Used by the control protocol integration target.
pub fn request(socket: &Path, request: &str) -> Value {
    let mut control = UnixStream::connect(socket).expect("client should connect");
    control
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout should be set");
    write_frame(&mut control, request.as_bytes());
    read_response(&mut control)
}

pub fn write_frame(control: &mut UnixStream, payload: &[u8]) {
    control
        .write_all(&encode_frame(payload))
        .expect("control frame should be written");
}

pub fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).expect("control request should fit a frame");
    [length.to_be_bytes().as_slice(), payload].concat()
}

#[allow(dead_code)] // Used by the control protocol integration target.
pub fn read_response(control: &mut UnixStream) -> Value {
    read_response_frame(control).1
}

fn read_response_frame(control: &mut UnixStream) -> (Vec<u8>, Value) {
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
