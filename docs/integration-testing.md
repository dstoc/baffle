# Integration test suite

The backend matrix runs the same control-protocol, client, daemon-lifecycle,
Unix-socket, tunnel, HTTPS-policy, and secret-injection scenarios against
`backend-hudsucker` and `backend-rama`. Each matrix entry disables default
features and selects exactly one backend.

`.github/workflows/ci.yml` runs formatting, Clippy, debug tests, release tests,
examples, and the privileged namespace fixture. The `checks` job has separate
Hudsucker and Rama results. The exact required check, `Format, lint, and test`,
fails unless both the backend checks and both namespace matrix entries pass.
The `Network namespace isolation` workflow is manually dispatchable and also
has separate backend entries. Its matrix entry records Rama's Rust minimum and
native build packages.

| Area | Shared daemon coverage | Backend-specific coverage |
| --- | --- | --- |
| Client and control protocol | `tests/client.rs` and `tests/control_protocol.rs` run for both features. They cover the typed client, real framed requests, errors, leases, persistence, concurrent independent sessions, and response redaction. | Control and secret-store unit tests inspect internal state. They do not count as daemon parity. |
| Daemon lifecycle | `tests/daemon_lifecycle.rs` runs for both features. It starts the executable and checks startup, graceful shutdown, and missing CA handling. | None. |
| Proxy policy through the daemon | `tests/daemon_proxy.rs` starts the executable, creates sessions over the framed control socket, and uses each assigned Unix socket. It checks authorized and denied hosts and ports, tunnel-only traffic, plaintext HTTP rejection, session separation, lease revocation, capacity errors, daemon-held secret entitlements, credential replacement, path denial, redaction, and inode-safe socket cleanup. | None for these HTTP/1.1 and tunnel scenarios. The local upstream CA is available only in the integration-test build; normal daemon builds retain the default trust roots. |
| Direct proxy runtime | Not counted as end-to-end daemon parity. | `tests/proxy_runtime.rs` remains Hudsucker-only because it uses Hudsucker's HTTP/2 client types and backend-specific runtime details. It tests lower-level CONNECT, TLS, HTTP/2, revocation, limits, and socket guards. Rama has separate runtime unit tests in `src/proxy_runtime/rama.rs`; these test the adapter without launching the daemon. |
| Secret and policy internals | The real-daemon target verifies entitlement, injection, path denial, and control-response redaction with the same fixture values under both features. | `src/control.rs`, `src/secrets.rs`, and each backend runtime have unit tests for internal checks. Unit tests alone do not establish parity. |
| Documentation examples | `tests/documentation.rs` parses the checked-in TOML examples. `cargo check --examples` compiles client examples under both backend selections. | None. |

The only Cargo integration target with a backend gate is `proxy_runtime`, which
requires `backend-hudsucker` for the direct Hudsucker-specific cases described
above. The `client`, `daemon_lifecycle`, and `control_protocol` targets run for
both backends. The three Rust examples also compile for both backends. Unit
tests inside backend adapters remain backend-specific and do not replace the
shared real-daemon target.

The backends use different denial status codes for plaintext forward requests.
Hudsucker returns 403. Rama rejects the non-CONNECT request with 400. Shared
tests accept either denial status and also check that the request does not
reach the upstream.

## Run the backend matrix locally

Use the integration-test build flag to run the local TLS upstream scenario.
It enables a temporary trust anchor only in this test build. The fixture passes
the generated test CA to the child daemon. The production build has no such
hook.

```sh
RUSTFLAGS='--cfg baffle_integration_test' cargo test --locked --no-default-features --features backend-hudsucker
RUSTFLAGS='--cfg baffle_integration_test' cargo test --locked --no-default-features --features backend-rama
cargo clippy --locked --all-targets --no-default-features --features backend-hudsucker -- -D warnings
cargo clippy --locked --all-targets --no-default-features --features backend-rama -- -D warnings
cargo check --locked --examples --no-default-features --features backend-hudsucker
cargo check --locked --examples --no-default-features --features backend-rama
cargo fmt --check
```

Without the `RUSTFLAGS` value, `tests/daemon_proxy.rs` still checks control
protocol entitlement and redaction. It skips the local-origin TLS requests
that need the test trust anchor. The ordinary developer commands in the
README remain unchanged.

## Privileged network namespace integration

The `Network namespace integration` job in `.github/workflows/ci.yml` runs on
GitHub-hosted Ubuntu VMs for both backend features. It builds with
`--no-default-features --features backend-hudsucker` or
`--no-default-features --features backend-rama`, then runs the privileged
fixture as root. The separate `Network namespace isolation` workflow supports
manual dispatch with the same two feature entries.

The fixture creates daemon and client network namespaces joined by a veth pair.
The client uses its assigned Unix data socket to fetch an HTTPS response from
an allowed upstream. A route canary proves that the client can reach the daemon
namespace. A second probe targets the daemon's actual internal TCP listener
through the daemon veth address and requires `ECONNREFUSED`. The checker also
verifies that Baffle's TCP listeners bind only to loopback.

The negative cases remain active. The checker must reject two processes in the
same namespace and a listener bound to `0.0.0.0`. The fixture cleans up
processes and namespaces after a failed assertion.

Run this privileged test locally only when you want to test namespace
creation. It is separate from `cargo test` and requires Linux root access with
permission to create network namespaces and veth devices, Python 3, `iproute2`,
`nsenter`, and OpenSSL. Build one backend, then run the fixture:

```sh
cargo build --locked --bin baffle --no-default-features --features backend-hudsucker
sudo python3 scripts/test-network-namespace-isolation.py --binary target/debug/baffle

cargo build --locked --bin baffle --no-default-features --features backend-rama
sudo python3 scripts/test-network-namespace-isolation.py --binary target/debug/baffle
```

See the Rama matrix entry in `.github/workflows/ci.yml` for its build
prerequisites. The namespace job verifies the topology created by the fixture.
A deployment with a different namespace, mount, route, or socket setup still
needs its own isolation validation.

The standalone Cladding example is [`examples/cladding_socat.rs`](../examples/cladding_socat.rs).
It uses Cladding's existing `socat` bridge to expose the assigned Unix socket
as a local TCP proxy. It does not depend on Cladding code. Use
`cargo run --example cladding_socat -- github.com` to run it.
