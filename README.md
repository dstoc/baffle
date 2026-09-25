# Baffle

Baffle is a Linux daemon that creates independent, policy-controlled HTTP and
HTTPS proxies on demand. One daemon can manage multiple sessions. Each session
has its own policy, Unix data socket, and lifecycle.

Baffle allows traffic only to exact host and port rules. A rule can tunnel
HTTPS without decrypting it or intercept HTTPS so Baffle can check paths and
add daemon-managed credentials. Baffle denies destinations and requests that
do not match a session policy.

The executable is named `baffle`. The Cargo package is named `baffle-proxy`.
The client library is the separate workspace package `baffle-client`.

## Install

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

In another terminal, build and run the Rust example. It creates an ephemeral
session, sends one HTTP request through its Unix data socket, then closes the
lease and removes the session:

```sh
cargo run --locked --example client
```

The example expects the control socket at `/run/baffle/control.sock` and allows
`example.com` on port 80. The daemon's session socket directory defaults to
`/run/baffle/proxies` in the example configuration. See
[`examples/session.toml`](examples/session.toml) for a direct-protocol policy.

For an HTTPS CONNECT session exposed through a local TCP bridge, use the
[Cladding integration example](docs/cladding-integration.md). It uses
`socat`; the Baffle daemon and sandboxed client must have the network and socket
isolation described in the [deployment guide](docs/security-deployment.md).

## How it works

The daemon owns a private Unix control socket and a managed certificate
authority. A trusted client creates a session over the control socket and gets
the path to that session's Unix data socket. Hudsucker handles HTTP and HTTPS
traffic. A bounded in-process bridge connects the data socket to a private,
pre-bound loopback TCP listener used by Hudsucker.

Every session has a separate immutable policy, Hudsucker runtime, DNS-aware
outbound connector, credential state, and resource counters. The session
manager shares the Tokio runtime and CA material. See the
[architecture guide](docs/architecture.md) for component details and data
flows.

**Deployment requirement:** sandboxed clients must not be able to reach
Baffle's internal loopback TCP listeners. Run the daemon in a network
namespace that clients cannot access, or enforce equivalent isolation. Expose
the control socket only to the trusted operator. Expose only an assigned
session socket to its client.

## Development

Build the workspace and run its checks:

```sh
cargo build --locked
cargo test --locked --all-features
cargo test --locked --release --all-features
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo check --locked --examples
```

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

Baffle runs on Linux. It is a forward HTTP/HTTPS proxy. It does not install its
CA into system trust stores, configure client proxy settings, or create the
network sandbox that isolates its internal TCP listeners. The deployment must
provide that isolation. Baffle does not change Cladding; a consumer integrates
through the public control protocol or `baffle-client` crate.
