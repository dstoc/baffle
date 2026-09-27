mod daemon;
mod policy;
mod protocol;

const DAEMON_EXAMPLE: &str = r#"
[daemon]
control_socket = "/run/baffle/control.sock"
socket_dir = "/run/baffle/proxies"
trusted_operator_uid = 1000
max_sessions = 64
max_connections_per_session = 128
shutdown_grace_seconds = 5

[ca]
certificate = "/var/lib/baffle/ca.pem"
private_key = "/var/lib/baffle/ca-key.pem"

[secrets]
directory = "/var/lib/baffle/secrets"
"#;

const SESSION_EXAMPLE: &str = r#"
version = 1
operation = "create"

[session]
persistent = false

[[rules]]
host = "crates.io"
mode = "tunnel"
ports = [443]

[[rules]]
host = "api.github.com"
mode = "intercept"
ports = [443]
paths = ["/repos/dstoc/cladding", "/repos/dstoc/cladding/**"]

  [[rules.inject]]
  header = "Authorization"
  secret = "github-api"
  format = "bearer"

[[rules]]
host = "github.com"
mode = "intercept"
ports = [443]
paths = ["/dstoc/cladding.git/**"]

  [[rules.inject]]
  header = "Authorization"
  secret = "github-git"
  format = "basic_password"
  username = "x-access-token"
"#;

const MINIMAL_CREATE: &str = r#"
version = 1
operation = "create"

[session]

[[rules]]
host = "Example.COM."
mode = "intercept"
"#;

fn config_with(rule: &str) -> String {
    format!("version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\n{rule}\n")
}
