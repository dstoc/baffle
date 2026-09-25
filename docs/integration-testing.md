# Integration test suite

The Rust and Python tests run in `.github/workflows/ci.yml` on `ubuntu-latest`. They cover protocol framing, session lifecycle, proxy policy, DNS filtering, credential handling, and runtime cleanup.

| Area | Coverage |
| --- | --- |
| Control protocol and session lifecycle | `tests/control_protocol.rs`, `tests/client.rs`, `tests/daemon_lifecycle.rs`: framing errors, failed provisioning rollback, leases, persistent sessions, independent sessions, capacity, graceful shutdown, and crash recovery. |
| Proxy policy and TLS | `tests/proxy_runtime.rs`: unauthorized destinations, IP literals, private-address exceptions, suffix and port checks, path normalization, redirects, CONNECT payloads, SNI mismatch, HTTP/2 authority and scheme checks, and established connections after revocation. |
| DNS and egress | `src/egress.rs`: mixed and rebinding answers, failed lookups, private address exceptions, and validated address dialing. |
| Secret handling | `src/secrets.rs`, `src/proxy_runtime.rs`, and `src/control.rs`: entitlement checks, redaction, supported authorization formats, host/path/port/scheme/authority boundaries, and WebSocket rejection. |
| Runtime resilience | `src/proxy_runtime.rs`, `src/control.rs`, `tests/daemon_lifecycle.rs`: connection and provisioning limits, I/O timeouts, task failures, bounded shutdown, and socket cleanup. |

The unit suite injects DNS answers and peer credentials to make rebinding and unauthorized-user checks deterministic. The Linux process tests exercise the assembled daemon and Unix sockets.

## Privileged network namespace integration

GitHub Actions runs `Network namespace isolation` on every pull request and push to `main`. To start it manually, open **Actions → Network namespace isolation → Run workflow**, or run `gh workflow run network-namespace.yml --ref <branch>`. The job runs on a GitHub-hosted `ubuntu-latest` VM, installs `iproute2`, builds Baffle, and runs the privileged fixture as root.

The fixture creates daemon and client network namespaces joined by a veth pair. It starts Baffle with a persistent proxy session and its internal TCP listener. The client process uses the assigned Unix socket to fetch a response from the session's allowed upstream. A separate listener on the daemon's veth address proves that the client can route to the daemon namespace. The client then tries the daemon's veth address at Baffle's actual internal listener port; the connection must be refused. This probe does not use the client's loopback address.

The checker runs against the real Baffle and client PIDs. It verifies that their network namespace identities differ and that Baffle's TCP listeners bind only to loopback. The fixture also confirms that the checker fails when both PIDs are in one namespace and when a test listener binds to `0.0.0.0`. It removes its processes and temporary namespaces in cleanup, including after a failed assertion.

This CI result verifies the topology created by the fixture. A deployment with a different namespace, mount, routing, or socket setup still needs its own isolation validation.

Run the privileged fixture locally only when you want to test namespace creation. It is not part of `cargo test`, `cargo test --all-features`, or the routine development checks. Build the daemon, then run:

```sh
cargo build --bin baffle
sudo python3 scripts/test-network-namespace-isolation.py --binary target/debug/baffle
```

The local command requires Linux, root with permission to create network namespaces and veth devices, Python 3, `iproute2` (`ip` and `ss`), `nsenter`, and OpenSSL. It builds no Rust code itself and does not need `socat`.

The standalone Cladding example is [`examples/cladding_socat.rs`](../examples/cladding_socat.rs). It creates a Baffle session and uses Cladding's existing `socat` bridge from a local TCP proxy endpoint to the assigned Unix socket. It does not depend on Cladding code. Use `cargo run --example cladding_socat -- github.com` to run it. Use `examples/measure_sessions.rs` with an idle Linux daemon to measure create latency, concurrent session creation, and idle-session RSS. The observed values for this run are in [performance observations](performance-observations.md); the example does not enforce a performance target.
