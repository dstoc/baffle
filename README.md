# Baffle

Baffle is a policy-controlled HTTPS proxy. A trusted orchestrator creates a
session through a private Unix control socket. Baffle returns a separate Unix
data socket for that session, which the orchestrator gives to its workload.
This gives each workload a dedicated proxy route. Requests sent through its
socket can reach only the exact hosts and ports in the session policy.

Baffle can tunnel HTTPS without inspecting it, or intercept HTTPS to check
request paths and add daemon-managed credentials. It is currently verified on
Linux x86-64 and macOS Apple Silicon.

Sessions default to exact host and port rules. A session can also permit
opaque HTTPS tunnels to DNS hostnames absent from its rules, on port 443 only.
An explicit host rule always governs that hostname, including when the rule
denies a port or path.

## Install

Each [GitHub release](https://github.com/dstoc/baffle/releases/latest)
provides these assets:

- Linux x86-64: `baffle-proxy-v<version>-x86_64-unknown-linux-gnu.tar.gz`
- macOS Apple Silicon: `baffle-proxy-v<version>-aarch64-apple-darwin.tar.gz`
- Both platforms: `SHA256SUMS`

Set `VERSION` to the version shown on the latest release page. The examples
below download the archive and `SHA256SUMS`, then verify the archive before
extracting it. For example, on Linux:

```sh
set -e
VERSION=0.3.0 # set this to the current release version
ARCHIVE="baffle-proxy-v${VERSION}-x86_64-unknown-linux-gnu.tar.gz"
curl -fL -o "$ARCHIVE" "https://github.com/dstoc/baffle/releases/download/v${VERSION}/$ARCHIVE"
curl -fL -o SHA256SUMS "https://github.com/dstoc/baffle/releases/download/v${VERSION}/SHA256SUMS"
CHECKSUM="$(grep " $ARCHIVE$" SHA256SUMS)"
printf '%s\n' "$CHECKSUM" | sha256sum -c -
tar -xzf "$ARCHIVE"
sudo install -m 0755 baffle /usr/local/bin/baffle
baffle --help
```

On macOS Apple Silicon, use the `aarch64-apple-darwin` archive and verify it
with `shasum -a 256 -c -`:

```sh
set -e
VERSION=0.3.0 # set this to the current release version
ARCHIVE="baffle-proxy-v${VERSION}-aarch64-apple-darwin.tar.gz"
curl -fL -o "$ARCHIVE" "https://github.com/dstoc/baffle/releases/download/v${VERSION}/$ARCHIVE"
curl -fL -o SHA256SUMS "https://github.com/dstoc/baffle/releases/download/v${VERSION}/SHA256SUMS"
CHECKSUM="$(grep " $ARCHIVE$" SHA256SUMS)"
printf '%s\n' "$CHECKSUM" | shasum -a 256 -c -
tar -xzf "$ARCHIVE"
mkdir -p "$HOME/.local/bin"
install -m 0755 baffle "$HOME/.local/bin/baffle"
export PATH="$HOME/.local/bin:$PATH"
baffle --help
```

The Linux archive targets GNU/Linux and links to the system GNU C library.
Source builds require Rust 1.96 or newer, CMake, Clang, and libclang. See the
[release guide](docs/releasing.md) for platform build dependencies.

## Quick start

This local example runs Baffle as your current user. The daemon requires an
interception CA even though this tunnel-only session does not use it. The
command creates the CA files locally; it does not install the certificate in
an OS or browser trust store.

In a first terminal, create the daemon and session configuration files:

```sh
set -e
umask 077
export BAFFLE_DIR="$(mktemp -d "/tmp/baffle-quickstart.XXXXXX")"
mkdir -p "$BAFFLE_DIR/proxies" "$BAFFLE_DIR/secrets"
chmod 0700 "$BAFFLE_DIR" "$BAFFLE_DIR/proxies" "$BAFFLE_DIR/secrets"
BAFFLE_UID="$(id -u)"

cat > "$BAFFLE_DIR/daemon.toml" <<EOF
[daemon]
control_socket = "$BAFFLE_DIR/control.sock"
socket_dir = "$BAFFLE_DIR/proxies"
trusted_operator_uid = $BAFFLE_UID
create_mode = "inline"

[ca]
certificate = "$BAFFLE_DIR/ca.pem"
private_key = "$BAFFLE_DIR/ca-key.pem"

[secrets]
directory = "$BAFFLE_DIR/secrets"
EOF

baffle ca init --config "$BAFFLE_DIR/daemon.toml"

cat > "$BAFFLE_DIR/session.toml" <<'EOF'
version = 2
persistent = true
socket_name = "quickstart.sock"

[rules."example.com"]
EOF

echo "Use this directory in the second terminal: $BAFFLE_DIR"
baffle daemon --config "$BAFFLE_DIR/daemon.toml"
```

The minimum session policy is a version and one quoted host rule:

```toml
version = 2

[rules."example.com"]
```

This rule defaults to an opaque HTTPS tunnel because it has no path checks or
managed credentials.

To allow opaque tunnels to DNS hostnames absent from the explicit `rules` map,
add `unmatched = "tunnel"` at the document root. This fallback applies only to
port 443. Omit the setting to keep the default-deny behavior. A hostname in
`rules` always uses its explicit rule, even when that rule denies a request.

The walkthrough adds `persistent = true` and a socket name so `create` returns
and the socket path is predictable.

In a second terminal, set `BAFFLE_DIR` to the path printed above, then create
the session:

```sh
export BAFFLE_DIR="/tmp/baffle-quickstart.<your-suffix>"
baffle create \
  --control-socket "$BAFFLE_DIR/control.sock" \
  --config "$BAFFLE_DIR/session.toml"
```

The command prints a session ID and its assigned data socket:

```text
Created persistent session <session-id> (it remains active after this command exits).
Data socket: <BAFFLE_DIR>/proxies/quickstart.sock
```

The example uses `$BAFFLE_DIR/proxies/quickstart.sock`. By default, a session
is ephemeral: `create` prints a leased-session message and stays open to hold
the lease. The session stops when that command exits.

To send a real HTTPS request, connect a local consumer-side TCP adapter to the
Unix socket. `curl` uses TCP here, so `socat` exposes the socket through a
loopback-only adapter outside Baffle. Baffle itself listens only on Unix
sockets:

```sh
socat TCP-LISTEN:18080,bind=127.0.0.1,reuseaddr,fork \
  UNIX-CONNECT:"$BAFFLE_DIR/proxies/quickstart.sock" &
ADAPTER_PID=$!
curl --noproxy "" --proxy http://127.0.0.1:18080 https://example.com/
kill "$ADAPTER_PID"
```

Stop the persistent session with the ID printed by `create`, then stop the
daemon with Ctrl+C in the first terminal:

```sh
SESSION_ID="paste-session-id-from-create-output"
baffle stop "$SESSION_ID" --control-socket "$BAFFLE_DIR/control.sock"
```

## Security model

- Baffle accepts HTTPS destinations through `CONNECT` and rejects plaintext
  HTTP requests.
- A tunnel rule is opaque. Baffle cannot inspect its paths, add managed
  credentials, or verify the upstream TLS certificate. The client must verify
  the upstream TLS identity.
- Path restrictions and managed credentials require HTTPS interception.
  Interception fails closed if Baffle cannot inspect the connection. Baffle
  adds managed credentials only after it verifies upstream TLS identity and
  the request policy. Baffle forwards upstream responses without filtering
  injected credential values. Only allowlist sites that you trust with those
  credentials, because a site can return them in a response.
- Baffle authorizes exact configured hostnames and ports. It does not filter
  DNS answers or destination IP addresses; apply DNS and network egress
  controls when your deployment needs address restrictions.
- Keep the control socket available only to the trusted operator. Give a
  workload only its assigned data socket. Baffle does not create a sandbox or
  prevent clients from using another network route.

See the [security and deployment guide](docs/security-deployment.md) for the
full threat model, CA setup, socket permissions, and isolation requirements.

## Sessions and reloads

Each session has its own policy and data socket. A rule without `paths` or
`inject` defaults to an opaque tunnel unless it sets `mode = "intercept"`.
Rules with `paths` or `inject` inspect HTTPS requests; Baffle checks the
configured paths or adds the authorized credential. See the
[session configuration reference](docs/configuration.md) and the checked-in
[credential example](examples/session-credentials.toml).

When an operator reloads a daemon-managed session file, new connections use
the validated policy. Existing connections continue with the policy they
already accepted until they close. Reload does not revoke credentials on an
open connection. See the [deployment guide](docs/security-deployment.md) for
safe updates and the [architecture guide](docs/architecture.md) for component
details.

## Documentation

- [Configuration](docs/configuration.md): daemon settings, v2 session files,
  defaults, validation, and policy examples.
- [Security and deployment](docs/security-deployment.md): threat model, CA
  provisioning, secret storage, socket access, and network isolation.
- [Control protocol](docs/control-protocol.md): request framing, response
  schemas, errors, and session leases.
- [Rust client](docs/client.md): typed client API and direct protocol use.
- [Consumer integration](docs/cladding-integration.md): connect a workload to
  its assigned socket, including an external `socat` adapter example.
- [Architecture](docs/architecture.md): request flow and session lifecycle.
- [Integration testing](docs/integration-testing.md): test coverage and the
  privileged Linux namespace test.
- [Release process](docs/releasing.md): versioning, release review, and
  binary packaging.

The [`examples/`](examples/) directory includes daemon and v2 session files.
The archive contains Baffle's MIT license and third-party license notices.

## Development

Build the workspace and run its checks with:

```sh
cargo build --locked
cargo test --locked
cargo fmt --check
```

## License

Baffle's original code is licensed under the MIT License. See [LICENSE](LICENSE).
