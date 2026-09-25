# Baffle

Baffle is a Linux daemon that creates independent, policy-controlled HTTPS
proxies on demand. One daemon can manage multiple sessions. Each session has
its own policy, Unix data socket, and lifecycle.

Baffle allows traffic only to exact host and port rules. A rule can tunnel
HTTPS without decrypting it or intercept HTTPS so Baffle can check paths and
add daemon-managed credentials. Baffle denies destinations and requests that
do not match a session policy.

## Security model and limitations

**Approved target policy; implementation follow-ups are pending.** Baffle will
support HTTPS destinations only. A client must use HTTP `CONNECT` to establish
the destination connection. Baffle will reject ordinary forward-proxy requests
outside intercepted TLS, including absolute-form `http://` and `https://`
requests. It will reject plaintext `http://` destinations on every port,
including a request made after a client follows an HTTPS-to-HTTP redirect.
Baffle does not follow redirects itself.

The proxy client is untrusted and may try to evade policy. Baffle assumes that
sites on the hostname allowlist behave legitimately. That trust in an allowed
site does not make the client trusted. A client may send malformed CONNECT data
or split a TLS ClientHello to try to bypass inspection.

Rules default to destination port 443. A CONNECT request must use an authority
with an explicit port, such as `api.example.com:443`; the client should map
the default port from an `https://` origin to `:443`. Port 80 is not reserved:
a configured port can carry TLS if the destination service supports it. Baffle
rejects plaintext HTTP based on the request form or scheme, regardless of the
destination port.

The HTTP request used for `CONNECT` is the proxy protocol. After Baffle
intercepts TLS, it continues to process HTTP/1.1 or HTTP/2 inside that TLS
connection when a rule needs URL-path checks or daemon-managed credential
injection. It checks each request, including requests on a reused HTTP/1.1 or
HTTP/2 connection. TLS SNI must match the CONNECT hostname. Each inner HTTP
authority must match the authorized CONNECT host and port. Baffle injects a
credential only after successful interception and after the configured host,
port, upstream TLS certificate identity, request authority, and path checks
pass. It never injects into a plaintext request, a CONNECT request, a denied
request, or an opaque tunnel.

An explicit `mode = "tunnel"` rule permits an opaque connection and cannot
carry path or injection rules. Baffle cannot prove that the bytes in an opaque
tunnel are TLS, inspect HTTP paths, or verify the upstream certificate. The
client must verify the upstream TLS identity. A rule that requires
interception remains fail-closed: Baffle rejects unsupported payloads or a
failed TLS interception instead of opening an opaque fallback. A malformed or
fragmented ClientHello, unsupported data after CONNECT, or a failed TLS
handshake must close the connection when inspection is required. Such a
fallback would bypass path checks and the credential-injection boundary. If a
client sends its own credentials through a tunnel, Baffle cannot inspect or
constrain those credentials.

Here, “HTTPS-only” defines supported requests at Baffle's proxy interface. It
does not guarantee that every established opaque tunnel carries HTTPS.

The policy authorizes exact configured hostnames and ports. Baffle does not
check the IP addresses returned by DNS. An allowlisted name can
resolve to a private, loopback, link-local, metadata, or other sensitive
address, even when the service presents a valid certificate for that name.
For a threat model that requires address containment, the deployment must
control DNS and apply default-deny network egress rules with a firewall or
network namespace.
Hostname and port rules are sufficient only when those names and the addresses
they can reach are trusted for the workload.

The runtime now leaves DNS and destination-address restrictions to deployment
controls. Existing session policies that contain `private_addresses` fail
validation; remove that field and move any address restrictions to DNS and
network egress policy before upgrading. Until baffle/24 is implemented, the
runtime still accepts explicitly configured plaintext HTTP on tunnel rules and
rejects port 80 for interception and credential-injection rules. It continues
to reject opaque fallback when interception is required. The current behavior
is documented in the
[configuration reference](docs/configuration.md) and [security and deployment
guide](docs/security-deployment.md).

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

Baffle runs on Linux. It is a forward proxy. It does not install its
CA into system trust stores, configure client proxy settings, or create the
network sandbox that isolates its internal TCP listeners. The deployment must
provide that isolation. Baffle does not change Cladding; a consumer integrates
through the public control protocol or `baffle-client` crate.
