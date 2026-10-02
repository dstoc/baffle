# Baffle

Baffle is a policy-controlled HTTPS proxy daemon for Linux x86-64 and macOS
Apple Silicon. One daemon can manage multiple sessions. Each session has its
own policy, Unix data socket, and lifecycle. A required native Apple Silicon CI
check builds Baffle and exercises the control and proxy sockets against a
local HTTPS origin before changes can merge.

Baffle allows traffic only to exact host and port rules by default. A session
can opt into opaque HTTPS tunnels to otherwise-unmatched DNS hostnames on port
443. Explicit host rules remain authoritative. Baffle can also intercept HTTPS
so it can check paths and add daemon-managed credentials.

## Security model and limitations

* **Trust model:** Clients are untrusted and may deliberately try to bypass
  restrictions. Sites on the allowlist are assumed trustworthy. Baffle permits
  only explicitly configured hostnames and ports unless the session enables
  unmatched tunneling; the default port is 443.
* **HTTPS-only:** Clients must use HTTP `CONNECT` to reach HTTPS destinations.
  Baffle rejects plaintext HTTP requests on every port. HTTPS on other
  explicitly configured ports is supported.
* **Path restrictions:** When path restrictions apply, Baffle intercepts HTTPS
  and validates the CONNECT hostname, TLS SNI, and HTTP authority. It checks
  every intercepted request. If required interception fails, Baffle rejects
  the connection instead of opening an opaque tunnel.
* **Credential handling:** Baffle injects daemon-managed credentials only
  into authorized HTTPS requests after successful interception, upstream TLS
  identity verification, and policy checks. It does not inject credentials
  into plaintext requests or opaque tunnels. Baffle forwards upstream
  responses without filtering credential values, so trust allowlisted sites
  with injected credentials.
* **Opaque tunnels:** Explicit tunnel-only rules support destinations without
  path restrictions or credential injection. Baffle cannot inspect tunnel
  contents, prove they carry HTTPS, or verify the upstream certificate; the
  client must verify the upstream TLS identity. The optional unmatched-host
  tunnel policy has the same limits and applies only on port 443.
* **Network limitations:** Baffle does not prevent DNS rebinding or restrict
  resolved destination IP addresses. An allowlisted hostname may resolve to
  an internal or otherwise sensitive address.

Only the trusted operator should access the control socket. Give each client
access only to its assigned Unix data socket. Baffle has no internal per-session
TCP listeners. Deployments that require destination-IP restrictions must still
enforce suitable DNS and network-egress controls.

For CA provisioning, configuration, detailed policy behavior, secret storage,
and isolation requirements, see the [security and deployment guide](docs/security-deployment.md)
and [configuration reference](docs/configuration.md). Baffle does not create
the sandbox or install its CA into client trust stores; the deployment must
arrange those separately.

## Install

The executable is named `baffle`, the Cargo package is named `baffle-proxy`,
and the client library is the separate workspace package `baffle-client`.

Release Please maintains version and changelog pull requests. Each published
release includes Linux x86-64 and Apple Silicon macOS archives. Download the
[Linux x86-64 archive](https://github.com/dstoc/baffle/releases/latest), the
[Apple Silicon macOS archive](https://github.com/dstoc/baffle/releases/latest), and
the [combined checksum file](https://github.com/dstoc/baffle/releases/latest/download/SHA256SUMS)
from the GitHub release page:

- Linux: `baffle-proxy-v<version>-x86_64-unknown-linux-gnu.tar.gz`
- macOS Apple Silicon: `baffle-proxy-v<version>-aarch64-apple-darwin.tar.gz`
- Both archives: [`SHA256SUMS`](https://github.com/dstoc/baffle/releases/latest/download/SHA256SUMS)

Each archive includes Baffle's root `LICENSE`, README, documentation, examples,
and target-specific third-party license and notice texts at
`share/doc/baffle/licenses/THIRD-PARTY-NOTICES.txt`.

```sh
VERSION=vX.Y.Z
tar -xzf "baffle-proxy-${VERSION}-x86_64-unknown-linux-gnu.tar.gz"
sudo install -m 0755 baffle /usr/local/bin/baffle
baffle --help
```

On macOS Apple Silicon, use the `aarch64-apple-darwin` archive and install it in
your user-owned `PATH` directory:

```sh
VERSION=vX.Y.Z
tar -xzf "baffle-proxy-${VERSION}-aarch64-apple-darwin.tar.gz"
mkdir -p "$HOME/.local/bin"
install -m 0755 baffle "$HOME/.local/bin/baffle"
export PATH="$HOME/.local/bin:$PATH"
baffle --help
```

The Linux binary links to the system GNU C library. To build from source on
Linux, install these native dependencies first:

```sh
sudo apt-get install build-essential cmake libclang-dev
cargo install --path . --locked --bin baffle
```

On macOS, install CMake and LLVM with Homebrew, set `LIBCLANG_PATH` to
`$(brew --prefix llvm)/lib`, then build with Rust 1.96 or newer:

```sh
brew install cmake llvm
export LIBCLANG_PATH="$(brew --prefix llvm)/lib"
cargo build --locked --target aarch64-apple-darwin --bin baffle
```

These native packages are needed only when compiling from source. A prebuilt
release binary does not require them at runtime. See the
[release process](docs/releasing.md) for versioning, review, CI, and packaging
instructions.

## Quick start

Create the daemon user, runtime directories, CA, and daemon configuration as
described in the [security and deployment guide](docs/security-deployment.md).
Edit [`examples/daemon.toml`](examples/daemon.toml) for the daemon UID and your
installation paths. The command below uses the Linux paths from that example.
For macOS, use per-user configuration and runtime paths as described in the
[security and deployment guide](docs/security-deployment.md).

```sh
baffle daemon --config /etc/baffle/daemon.toml
```

On Linux, top-level control commands use `/run/baffle/control.sock` by default.
On macOS, they use `$HOME/Library/Caches/Baffle/control.sock`. Use
`--control-socket PATH` to select the path from the daemon configuration:

Create a minimal tunnel session in `github.toml`:

```toml
version = 2

[rules."github.com"]
```

Add `unmatched = "tunnel"` at the document root to permit opaque tunnels to
otherwise-unmatched DNS hostnames on port 443. Omit it to keep the default-deny
policy. An explicit hostname rule always takes precedence.

```sh
# Inline mode: Baffle reads and validates the version 2 session file.
baffle create --config ./github.toml

# File-only mode: Baffle sends this name; the daemon loads it from its
# configured session directory.
baffle create cladding/github.toml

baffle list
baffle stop <session-id>
baffle reload <session-id>
baffle reload --all
```

The control socket is private. Run these commands as the configured
`trusted_operator_uid`, with access to the socket's mode-`0700` parent
directory. An ephemeral create prints its session ID and data-socket path, then
keeps running as the lease owner until Ctrl+C or process termination. A
persistent create prints that it is persistent and returns; stop it with
`baffle stop <session-id>`.

For a file-backed session, update its administrator-managed TOML file and run
`baffle reload <session-id>` to apply the validated configuration to newly
accepted connections. `baffle reload --all` reports each file-backed session
separately and exits unsuccessfully if any reload fails. Reload preserves the
session ID and creator lease. Existing connections keep their policy and
credentials until they close, so reload is not immediate credential
revocation. See the [deployment guide](docs/security-deployment.md) for a
safe update sequence.

The two create forms are exclusive. `--config` names a local file and is
available when the daemon accepts inline creates. The positional name is
relative to the daemon's `session_config_dir`; the client does not read that
file. See [configuration](docs/configuration.md) and the
[control protocol](docs/control-protocol.md) for file ownership and path rules.

The Rust `client` example creates an ephemeral session and sends CONNECT for
`example.com:443`. It confirms the tunnel response and then closes the session;
it does not send a TLS request. For a complete HTTPS request, use the
[Cladding integration](docs/cladding-integration.md). The checked-in Linux
example sets the daemon's session socket directory to `/run/baffle/proxies`.
On macOS, use a private directory under
`$HOME/Library/Caches/Baffle`. See
[`examples/session.toml`](examples/session.toml) for a version 2 session file.

Consumers can connect to the assigned Unix data socket directly. The
[Cladding integration example](docs/cladding-integration.md) uses `socat`
outside Baffle to expose that socket through a local TCP listener. Protect the
socket and listener, and apply the client egress controls described in the
[deployment guide](docs/security-deployment.md).

## How it works

The daemon owns a private Unix control socket and a managed certificate
authority. A trusted orchestrator creates a session over the control socket
and gets the path to that session's Unix data socket. Rama handles proxy
traffic directly on the Baffle-owned Unix listener.

The current implementation gives every session immutable policy generations,
a Rama runtime, credential state, and resource counters. Each accepted
connection keeps the generation active when it was accepted. The runtime authorizes
the configured hostname and port before dialing. Baffle does not filter or pin
DNS answers. The session manager shares the Tokio runtime and CA material. See
the [architecture guide](docs/architecture.md) for component details and data
flows.

Apply the controls described in [Security model and
limitations](#security-model-and-limitations) when your deployment's threat
model requires them.

## Development

Build the workspace and run its checks:

```sh
cargo build --locked
cargo test --locked
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo check --locked --examples
```

Rama is the only supported runtime. Source builds require Rust 1.96 or newer,
CMake, Clang, and libclang. Linux builds use `build-essential` and
`libclang-dev`. macOS builds use Homebrew `cmake` and `llvm`, with
`LIBCLANG_PATH` set to `$(brew --prefix llvm)/lib`. The release workflow
installs these platform-specific dependencies before compiling each binary.

GitHub Actions runs these checks, parses the checked-in TOML examples, runs the
privileged Linux network-namespace integration job, and tests the daemon's Unix
control and proxy sockets on native Apple Silicon macOS. See
[integration testing](docs/integration-testing.md) for test coverage and the
manual namespace test command.

## Documentation

- [Configuration reference](docs/configuration.md): daemon and session TOML,
  defaults, validation, path matching, secrets, and examples.
- [Control protocol](docs/control-protocol.md): version 1 framing, request and
  response schemas, error codes, and session leases.
- [Security and deployment](docs/security-deployment.md): threat model, CA
  provisioning, secret storage, socket access, and network isolation.
- [Architecture](docs/architecture.md): components, request flow, session
  lifecycle, the runtime boundary, policy boundaries, and failure behavior.
- [Rust client](docs/client.md): typed client API and direct protocol use.
- [Cladding integration](docs/cladding-integration.md): a standalone
  `socat` bridge example and integration steps for other consumers.
- [Integration testing](docs/integration-testing.md): automated coverage and
  the privileged namespace test.
- [Benchmark report](docs/benchmarking.md): current Rama benchmark commands and
  historical Hudsucker comparisons.
- [Runtime migration note](docs/runtime-migration.md): the Hudsucker removal,
  Rama-only status, and daemon-facing runtime boundary.
- [Release review](docs/release-review.md): package, dependency, logging,
  error-handling, and credential-protection review.
- [Original v1 proposal (historical)](docs/baffle-proposal.md): product goals,
  security requirements, and the original implementation plan.

## Platform scope

Baffle runs on Linux x86-64 and macOS Apple Silicon. It is a forward proxy. It
does not install its CA into system trust stores, configure client proxy
settings, or create a sandbox. Linux network namespaces are not available on
macOS; deployments on either platform must apply their own client egress and
outbound network controls when the threat model requires them. Baffle accepts
client traffic directly on Unix data sockets and has no internal per-session
TCP listeners. A consumer integrates through the public control protocol or
`baffle-client` crate.

## License

Baffle's original code is licensed under the MIT License. See [LICENSE](LICENSE).
Third-party dependencies remain under their respective licenses. The release
archive includes their license and notice texts at
`share/doc/baffle/licenses/THIRD-PARTY-NOTICES.txt`. It also includes the
CDLA-Permissive-2.0 agreement for the bundled Mozilla root certificate data.
