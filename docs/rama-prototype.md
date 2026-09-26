# Rama backend evaluation

## Result

This is a working experimental backend, not a migration decision. Hudsucker
remains the default. The Rama feature starts independent tunnel-only and
interception-required sessions through Baffle's existing Unix-to-loopback-TCP
bridge. Live tests cover HTTP/1.1, multiple HTTP/2 streams on one intercepted
TLS connection, test-credential injection, upstream certificate verification,
ClientHello fragmentation, resource limits, failure reporting, and shutdown.

The two backend selections compile and test independently. CI runs formatting,
Clippy, debug tests, and release tests for both feature selections. Rama still
adds native build requirements and custom TLS/session plumbing. The evidence
does not support changing the default backend.

## Rama integration and security

The adapter retains Baffle's CONNECT parser, exact configured host and port
authorization, policy, secret storage, Unix socket guard, and bridge. It
accepts CONNECT only; plaintext forward HTTP is rejected before any upstream
dial. Tunnel-only rules relay opaque bytes and do not enter the interception
middleware. Interception-required rules fail closed on non-TLS input,
incomplete or stalled ClientHello data, SNI mismatch, upstream TLS errors, and
decrypted HTTP authority mismatch.

The runtime peeks the ClientHello with
`PeekTimeoutPolicy::FailClosed`. It checks SNI against the authorized CONNECT
host. It now derives Rama's `TlsConnectorData` from that inspected ClientHello
so the upstream connection preserves the offered TLS settings and ALPN. This
was required for live HTTP/2: passing `None` to `TlsMitmRelay::handshake`
dropped ALPN, so the intercepted client could not negotiate HTTP/2. The
runtime overrides the upstream verification name with the authorized CONNECT
host, enables `ServerVerifyMode::Auto`, and explicitly disables key logging.

Rama's public `TlsMitmEgressServerAuth` API exposes verification controls, and
`TlsMitmRelay` exposes key-log controls. The adapter also needs to build
connector data from the inspected ClientHello to preserve protocol negotiation.
The daemon's configured CA key remains in `ManagedCa`; the runtime converts it
to BoringSSL key material for Rama's issuer.

The live HTTP/2 test negotiates `h2` with the client and origin, then sends
four concurrent streams over one TLS connection. Two allowed requests reach
the origin with the daemon test credential replacing attacker-provided
Authorization headers. A forbidden path receives 403. An HTTP authority that
does not match CONNECT receives 400. Neither denied request reaches the
origin. Shared policy tests also cover explicit TLS port 80 and default port
443 behavior.

The fragmented ClientHello test uses a valid Rustls handshake. Its IO wrapper
writes one byte, waits 75 ms, then writes the remainder. The client trusts
both the Baffle CA and the test origin CA. The proxy either completes
inspection and denies the forbidden path or rejects TLS; an opaque tunnel
would reach the origin and fail the test.

The lifecycle tests cover two independent sessions, graceful shutdown with an
active tunnel, cancelled shutdown with active tunnel and intercepted requests,
bridge and loopback connection limits, startup refusal on an occupied socket
path, and proxy/bridge task failure events. The existing inode-safe socket
guard removes the session path only when its device and inode still match.

## Native Unix socket assessment

Rama 0.4.0 provides `rama-unix::server::UnixListener`. Its `bind_path` helper
removes an existing path before binding. Its cleanup guard unconditionally
calls `remove_file` on that path when dropped. It does not preserve Baffle's
inode-safe unlink behavior, and it does not set Baffle's private socket
permissions. That helper cannot replace Baffle's listener safely.

Rama's `bind_socket` and `from_tokio_unix_listener` constructors disable
automatic path cleanup. A future integration could pre-bind through Baffle's
safe guard and hand the listener to Rama, while retaining Baffle's own path
guard and connection semaphore. Rama's convenience `serve` loop spawns a task
per accepted connection; a replacement would still need explicit admission
limits and lifecycle supervision. The current bridge remains the lower-risk
choice. These findings come from the pinned crate source at
`rama-unix-0.4.0/src/server/listener.rs`; no native listener change was made.

## Reproduction and measurements

Measurements were taken in the `baffle` repository on `ld-cladding` with
Rust 1.98.1 and Cargo 1.98.1. Each clean measurement followed `cargo clean`.
The incremental measurement repeated the same build immediately. Binary sizes
are for `target/{debug,release}/baffle`.

| Check | Hudsucker | Rama |
| --- | ---: | ---: |
| Workspace debug tests | Passed: 101 | Passed: 61 |
| Workspace release tests | Passed: 101 | Passed: 61 |
| Clean / incremental debug build | 18.51 / 0.14 s | 46.96 / 0.17 s |
| Clean / incremental release build | 32.72 / 0.14 s | 69.46 / 0.18 s |
| Debug / release binary size | 172,000,024 / 14,505,040 bytes | 312,003,680 / 18,165,256 bytes |
| Normal dependency graph entries | 253 | 359 |

The Rama graph adds 106 normal dependency entries. Count them with:

```sh
cargo tree --locked --no-default-features --features backend-hudsucker -e normal --prefix none | sort -u | wc -l
cargo tree --locked --no-default-features --features backend-rama -e normal --prefix none | sort -u | wc -l
```

Reproduce the clean and incremental builds with:

```sh
cargo clean
cargo build --locked --no-default-features --features backend-hudsucker
cargo build --locked --no-default-features --features backend-hudsucker
cargo clean
cargo build --locked --release --no-default-features --features backend-hudsucker
cargo build --locked --release --no-default-features --features backend-hudsucker

cargo clean
cargo build --locked --no-default-features --features backend-rama
cargo build --locked --no-default-features --features backend-rama
cargo clean
cargo build --locked --release --no-default-features --features backend-rama
cargo build --locked --release --no-default-features --features backend-rama
```

Both backend test commands, both Clippy commands, formatting, Hudsucker
example compilation, and all four network namespace checker tests passed.
The corresponding checks are:

```sh
cargo test --locked --no-default-features --features backend-hudsucker
cargo clippy --locked --all-targets --no-default-features --features backend-hudsucker -- -D warnings
cargo test --locked --release --no-default-features --features backend-hudsucker
cargo test --locked --no-default-features --features backend-rama
cargo clippy --locked --all-targets --no-default-features --features backend-rama -- -D warnings
cargo test --locked --release --no-default-features --features backend-rama
cargo fmt --all -- --check
cargo check --locked --examples --no-default-features --features backend-hudsucker
python3 -m unittest discover -s scripts -p 'test_*.py'
```

Rama 0.4.0 declares Rust 1.96 as its minimum version and is selected with
`http-full` and `boring`. The BoringSSL bindings compile native sources with
CMake and a C++ compiler. Rama's DNS feature uses bindgen and requires
`libclang-dev`. This runner used CMake 3.31.6 and C++ 14.2.0. Ordinary
Hudsucker-only builds do not compile Rama and do not need these Rama-specific
native packages. CI installs them only for the Rama matrix entry. Rama's
normal dependency graph includes `rama-dns`, `rama-tls-boring`,
`rama-boring`, and `rama-boring-sys`; the Hudsucker selection does not compile
Rama, and the Rama selection does not compile Hudsucker.

## Backend comparison

| Option | Evidence in this repository | Maintenance impact |
| --- | --- | --- |
| Vendored Hudsucker 0.25.0 | Default backend. The Hudsucker suite covers HTTP/1.1, HTTP/2, TLS authority, paths, credentials, and lifecycle. Local changes are listed in [`vendor/hudsucker/PATCHES.md`](../vendor/hudsucker/PATCHES.md). | A small local fork must be reviewed when rebasing. Existing handlers and TLS hooks already match Baffle's policy and lifecycle. |
| Rama 0.4.0 | Optional backend. Live tests cover HTTP/1.1 and HTTP/2 interception, tunnel-only traffic, credentials, TLS verification, ClientHello handling, resource limits, and cancellation. | Adds 106 normal dependency entries, a Rust 1.96 MSRV, bindgen/libclang, CMake, native BoringSSL, and custom CONNECT, TLS, middleware, limits, and lifecycle code. Its clean debug and release builds are about 2.5x and 2.1x slower. The release binary is about 3.66 MB larger. |
| Upstream Hudsucker 0.25.0 with a smaller patch | Source review in [`docs/architecture.md`](architecture.md#hudsucker-integration-and-local-patch) found no upstream hook for Baffle's intercept/tunnel/reject decision, CONNECT-bound TLS context, or per-request HTTP authority binding. This option was not built or measured. | It could reduce the local fork if upstream adds equivalent hooks. Current APIs and tests do not support replacing the required local patch safely. |

Both backends bind one runtime per session and keep lifecycle reporting in
Baffle's session manager. Rama binds the loopback TCP listener and Unix bridge,
then supervises separate proxy and bridge tasks. Shutdown closes Unix ingress,
cancels the proxy, drains active connections until the grace period, and then
aborts remaining tasks. Dropping a Rama runtime also cancels and aborts its
child tasks, so cancellation of the caller does not detach a live proxy.
Hudsucker delegates proxy accept and graceful shutdown to its `Proxy` builder;
Baffle supervises that task and the bridge with the same per-session shutdown
boundary. Both backends use Baffle's inode-safe Unix socket guard.

Rama can support Baffle's core proxy policy. It replaces some Hudsucker-specific
integration with Baffle-owned CONNECT parsing, ClientHello inspection, request
middleware, CA conversion, and task supervision. That is a working path, but
it adds native build costs and more adapter code. Keep Hudsucker as the default
while this prototype receives review and further maintenance evaluation.
