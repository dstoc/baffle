# Integration test suite

Rama is the only supported runtime. The normal `cargo test` suite and the CI
workflows build and test it without backend feature flags. The suite keeps
real-daemon and direct-runtime coverage; adapter unit tests do not replace the
daemon and Unix data-socket tests.

`.github/workflows/ci.yml` runs formatting, Clippy, debug tests, release tests,
examples, and the privileged network-namespace fixture. The required status
check remains exactly `Format, lint, and test`. The manually dispatched
`.github/workflows/network-namespace.yml` runs the same privileged fixture.

| Area | Required coverage |
| --- | --- |
| Client and control protocol | `tests/client.rs` and `tests/control_protocol.rs` cover typed client calls, framed requests, errors, leases, persistence, independent sessions, and response redaction. |
| Daemon lifecycle | `tests/daemon_lifecycle.rs` starts the executable and checks startup, graceful shutdown, and missing CA handling. |
| Policy through the daemon | `tests/daemon_proxy.rs` starts the real daemon, provisions sessions over the control socket, and sends traffic through assigned Unix sockets. It checks destination and port policy, tunnel-only traffic, plaintext denial, session separation, lease revocation, capacity, secret entitlements, HTTP/1.1 and HTTP/2 credential isolation, path denial, redaction, and inode-safe cleanup. |
| Direct proxy runtime | `tests/proxy_runtime.rs` checks HTTPS-only admission, exact CONNECT host and port, CONNECT/SNI/HTTP authority binding, fragmented valid ClientHello handling, upstream TLS verification, required interception, explicit tunnel mode, HTTP/1.1 and HTTP/2 reused-connection policy, and resource limits. |
| Shared policy and lifecycle | `src/policy.rs`, `src/control.rs`, `src/secrets.rs`, and `src/proxy_runtime/rama.rs` test canonical paths, session ownership, secret handling, socket cleanup, cancellation, fatal runtime reporting, accepted-socket `TCP_NODELAY`, and bounded shutdown. |
| Documentation examples | `tests/documentation.rs` parses checked-in TOML examples. `cargo check --examples` compiles all Rust examples. |

The runtime admits only CONNECT. Required path or credential interception
fails closed when ClientHello parsing or TLS setup fails. Tests exercise a
fragmented valid ClientHello and verify that the proxy does not fall back to an
opaque tunnel. Intercepted upstream TLS verifies the authorized hostname.
Reused HTTP/1.1 and HTTP/2 connections recheck request authority, path, and
credential rules per request or stream.

## Run checks locally

The integration build flag gives the child daemon a private local-origin CA for
the real-daemon TLS fixture. Production builds do not include this trust-anchor
hook.

```sh
sudo apt-get install build-essential cmake libclang-dev
RUSTFLAGS='--cfg baffle_integration_test' cargo test --locked
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo check --locked --examples
RUSTFLAGS='--cfg baffle_integration_test' cargo test --locked --release
```

Without the `RUSTFLAGS` value, the real-daemon tests still cover control
protocol entitlement and redaction. They skip local-origin TLS requests that
need the test trust anchor. The native packages are required to compile Rama
from source. A prebuilt release binary does not need them at runtime.

## Privileged network namespace integration

The CI namespace job builds the default Rama daemon and runs
`scripts/test-network-namespace-isolation.py` as root. The fixture creates
daemon and client network namespaces joined by a veth pair. The client uses its
assigned Unix data socket to reach an allowed HTTPS upstream. A route canary
proves that the client can reach the daemon namespace. A second probe targets
the daemon's actual internal TCP listener through the daemon veth address and
requires `ECONNREFUSED`. The checker also verifies that Baffle's TCP listeners
bind only to loopback.

The negative cases remain active. The checker rejects two processes in the same
namespace and a listener bound to `0.0.0.0`. The fixture cleans up processes and
namespaces after a failed assertion.

Run this privileged test only when you want to test namespace creation. It is
separate from `cargo test` and requires Linux root access with permission to
create network namespaces and veth devices, Python 3, `iproute2`, `nsenter`, and
OpenSSL.

```sh
sudo apt-get install build-essential cmake libclang-dev iproute2 openssl
cargo build --locked --bin baffle
sudo python3 scripts/test-network-namespace-isolation.py --binary target/debug/baffle
```

The namespace job verifies the topology created by the fixture. A deployment
with a different namespace, mount, route, or socket setup still needs its own
isolation validation.
