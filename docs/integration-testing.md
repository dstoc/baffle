# Integration test suite

The integration tests run as part of `cargo test --all-features` in `.github/workflows/ci.yml` on `ubuntu-latest`. Unit tests add table-driven cases for validation, policy, DNS filtering, secret handling, and failure propagation.

| Area | Coverage |
| --- | --- |
| Control protocol and session lifecycle | `tests/control_protocol.rs`, `tests/client.rs`, `tests/daemon_lifecycle.rs`: framing errors, failed provisioning rollback, leases, persistent sessions, independent sessions, capacity, graceful shutdown, and crash recovery. |
| Proxy policy and TLS | `tests/proxy_runtime.rs`: unauthorized destinations, IP literals, private-address exceptions, suffix and port checks, path normalization, redirects, CONNECT payloads, SNI mismatch, HTTP/2 authority and scheme checks, and established connections after revocation. |
| DNS and egress | `src/egress.rs`: mixed and rebinding answers, failed lookups, private address exceptions, and validated address dialing. |
| Secret handling | `src/secrets.rs`, `src/proxy_runtime.rs`, and `src/control.rs`: entitlement checks, redaction, supported authorization formats, host/path/port/scheme/authority boundaries, and WebSocket rejection. |
| Runtime resilience | `src/proxy_runtime.rs`, `src/control.rs`, `tests/daemon_lifecycle.rs`: connection and provisioning limits, I/O timeouts, task failures, bounded shutdown, and socket cleanup. |

The unit suite injects DNS answers and peer credentials to make rebinding and unauthorized-user checks deterministic. The Linux process tests exercise the assembled daemon and Unix sockets.

Run the deployment confinement check as root after starting Baffle with at least one active session and a sandbox client:

```sh
sudo scripts/check-network-namespace-isolation.py "$BAFFLE_PID" "$SANDBOX_CLIENT_PID"
```

The check requires `nsenter`, `ss`, and Python 3. It confirms that Baffle and the client use different network namespaces, finds the TCP listeners owned by the Baffle process, verifies that they bind only to loopback, and attempts to connect to each listener from the client's namespace. A timeout is an inconclusive result and fails the check. Requests through the assigned Unix socket bridge must still work as part of the deployment smoke test.

The automated suite does not create network namespaces. This runner could not perform the deployment check because `unshare --net true` failed with `Operation not permitted`; run the command above in the intended deployment environment to record its result.

Use `cargo run --example cladding_socat -- github.com` for the standalone Cladding bridge example. Use `examples/measure_sessions.rs` with an idle Linux daemon to measure create latency, concurrent session creation, and idle-session RSS. The observed values for this run are in [performance observations](performance-observations.md); the example does not enforce a performance target.
