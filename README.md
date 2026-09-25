# Baffle

Baffle is a Linux daemon that creates independent, policy-controlled HTTPS
proxies on demand. One daemon can manage multiple sessions. Each session has
its own policy, Unix data socket, and lifecycle.

Baffle allows traffic only to exact host and port rules. A rule can tunnel
HTTPS without decrypting it or intercept HTTPS so Baffle can check paths and
add daemon-managed credentials. Baffle denies destinations and requests that
do not match a session policy.

## Security model and limitations

* **Trust model:** Clients are untrusted and may deliberately try to bypass
  restrictions. Sites on the allowlist are assumed trustworthy. Baffle permits
  only explicitly configured hostnames and ports; the default port is 443.
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
  client must verify the upstream TLS identity.
* **Network limitations:** Baffle does not prevent DNS rebinding or restrict
  resolved destination IP addresses. An allowlisted hostname may resolve to
  an internal or otherwise sensitive address.

**Deployment isolation is mandatory.** Sandboxed clients must not reach
Baffle's internal TCP listeners directly. Only the trusted operator should
access the control socket, and clients should receive access only to their
assigned Unix data sockets. Deployments that require destination-IP
restrictions must also enforce suitable DNS and network-egress controls.

For CA provisioning, configuration, detailed policy behavior, secret storage,
and isolation requirements, see the [security and deployment guide](docs/security-deployment.md)
and [configuration reference](docs/configuration.md). Baffle does not create
the sandbox or install its CA into client trust stores; the deployment must
arrange those separately.

## Install

The executable is named `baffle`, the Cargo package is named `baffle-proxy`,
and the client library is the separate workspace package `baffle-client`.

The release workflow builds the Linux x86-64 GNU binary when a `v<version>`
tag matches the version in `Cargo.toml`. Download and unpack the
`baffle-proxy-v<version>-x86_64-unknown-linux-gnu.tar.gz` asset from the
[GitHub releases](https://github.com/dstoc/baffle/releases), then install the
binary in a directory on `PATH`:

```sh
tar -xzf baffle-proxy-v<version>-x86_64-unknown-linux-gnu.tar.gz
sudo install -m 0755 baffle /usr/local/bin/baffle
baffle --help
```

The binary targets Linux x86-64 and links to the system GNU C library. To build
from a checkout with Rust installed, run:

```sh
cargo install --path . --locked --bin baffle
```

## Quick start

Create the daemon user, runtime directories, CA, and daemon configuration as
described in the [security and deployment guide](docs/security-deployment.md).
Edit [`examples/daemon.toml`](examples/daemon.toml) for the daemon UID and your
installation paths. Then start Baffle:

```sh
baffle daemon --config /etc/baffle/daemon.toml
```

The Rust `client` example creates an ephemeral session and sends CONNECT for
`example.com:443`. It confirms the tunnel response and then closes the session;
it does not send a TLS request. For a complete HTTPS request, use the
[Cladding integration](docs/cladding-integration.md). The daemon's session
socket directory defaults to `/run/baffle/proxies` in the example
configuration. See
[`examples/session.toml`](examples/session.toml) for a direct-protocol policy.

For an HTTPS CONNECT session exposed through a local TCP bridge, use the
[Cladding integration example](docs/cladding-integration.md). It uses
`socat`; the Baffle daemon and sandboxed client must have the network and socket
isolation described in the [deployment guide](docs/security-deployment.md).

## How it works

The daemon owns a private Unix control socket and a managed certificate
authority. A trusted orchestrator creates a session over the control socket
and gets the path to that session's Unix data socket. Hudsucker handles HTTP
and HTTPS traffic. A bounded in-process bridge connects the data socket to a
private, pre-bound loopback TCP listener used by Hudsucker.

The current implementation gives every session a separate immutable policy,
Hudsucker runtime, credential state, and resource counters. Hudsucker's default
outbound connectors resolve and dial authorized hostnames; Baffle does not
filter or pin DNS answers. The session manager shares the Tokio runtime and CA
material. See the
[architecture guide](docs/architecture.md) for component details and data
flows.

The deployment must enforce the isolation described in [Security model and
limitations](#security-model-and-limitations).

## Development

Build the workspace and run its checks:

```sh
cargo build --locked
cargo test --locked --no-default-features --features backend-hudsucker
cargo test --locked --no-default-features --features backend-rama
cargo fmt --check
cargo clippy --locked --all-targets --no-default-features --features backend-hudsucker -- -D warnings
cargo clippy --locked --all-targets --no-default-features --features backend-rama -- -D warnings
cargo check --locked --examples --no-default-features --features backend-hudsucker
```

The default feature is `backend-hudsucker`. The experimental Rama feature uses
Rama 0.4.0 with `http-full` and `boring`; it requires Rust 1.96 or newer,
`libclang`, CMake, and a C++ toolchain. See the
[Rama prototype report](docs/rama-prototype.md) for the current security gap
and build measurements.

GitHub Actions runs these checks, parses the checked-in TOML examples, and runs
the privileged Linux network-namespace integration job. See
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
  lifecycle, policy boundaries, failure behavior, and Hudsucker patches.
- [Rust client](docs/client.md): typed client API and direct protocol use.
- [Cladding integration](docs/cladding-integration.md): a standalone
  `socat` bridge example and integration steps for other consumers.
- [Integration testing](docs/integration-testing.md): automated coverage and
  the privileged namespace test.
- [Release review](docs/release-review.md): package, dependency, logging,
  error-handling, and credential-protection review.
- [Authoritative proposal](docs/baffle-proposal.md): product goals, security
  requirements, and the v1 specification.

## Current release scope

Baffle runs on Linux. It is a forward proxy. It does not install its
CA into system trust stores, configure client proxy settings, or create the
network sandbox that isolates its internal TCP listeners. The deployment must
provide that isolation. Baffle does not change Cladding; a consumer integrates
through the public control protocol or `baffle-client` crate.
