# Rama backend evaluation

## Result

This is a partial experimental prototype, not a migration decision.
Hudsucker remains the default backend. Rama now binds a loopback listener,
keeps the existing Unix-to-TCP bridge, and proxies intercepted HTTPS and
explicit tunnel-only sessions. End-to-end tests cover path authorization,
daemon-held test-credential injection, upstream hostname and expiration
verification, fail-closed ClientHello handling, and concurrent independent
sessions.

The prototype is not ready for migration or final acceptance. Rama HTTP/2
policy and the full lifecycle/resource-limit matrix remain untested. The
concurrent-session test verifies that stopping the tunnel session leaves the
interception session usable; separate tests cover the bridge's configured
connection limit and session-level failure event.

The backend flags are mutually exclusive. `backend-hudsucker` is the default.
`backend-rama` selects Rama 0.4.0 with the `http-full` and `boring` features.
The daemon uses a shared runtime error and event type for either adapter.

## Rama 0.4.0 API findings

The pinned Rama release exposes public controls for upstream TLS verification
and key logging. `TlsMitmEgressServerAuth` can select
`ServerVerifyMode::Auto`; `TlsMitmRelay` can set
`KeyLogIntent::Disabled`. These APIs remove the need for a separate
connector solely to enable chain and hostname verification. The defaults are
unsafe for Baffle: upstream verification is disabled, and an inherited
`SSLKEYLOGFILE` can enable key logging. The adapter must set both controls
explicitly and bind the verification name to the authorized CONNECT target.
See the [Rama Boring TLS API](https://docs.rs/rama-tls-boring/0.4.0/rama_tls_boring/proxy/mitm/struct.TlsMitmEgressServerAuth.html)
and [TLS relay API](https://docs.rs/rama-tls-boring/0.4.0/rama_tls_boring/proxy/mitm/struct.TlsMitmRelay.html).

Rama's ClientHello peeker accepts a timeout policy. A partial plausible hello
can fail closed with `PeekTimeoutPolicy::FailClosed`. A definitive non-TLS or
malformed prefix instead returns no ClientHello, so an interception-required
path must reject that result. It must not connect the peeker's fallback to a
raw tunnel. A live-proxy test covers both a non-TLS prefix and an incomplete
ClientHello that stalls until timeout. The primitive tests remain useful for
pinning Rama's timeout behavior, but the runtime tests now verify these cases
through an actual session. See the [ClientHello peeker
API](https://docs.rs/rama/0.4.0/rama/tls/server/struct.PeekTlsClientHelloService.html).

The runtime binds CONNECT and Host to Baffle's exact configured host and port,
checks SNI against that CONNECT host, and checks each decrypted HTTP authority
against the same destination. Interception-required requests never fall back
to raw forwarding. Explicit tunnel rules carry opaque bytes without running
the request middleware or injecting credentials. The shared policy uses a
backend-neutral request view, and Rama middleware applies its canonical path
checks before forwarding each HTTP/1.1 request. Baffle's configured CA
certificate and signing key are loaded into daemon-owned `ManagedCa` state and
converted to Rama's BoringSSL types for the relay.

Live-proxy tests reject expired and hostname-mismatched upstream certificates,
non-TLS bytes, an incomplete ClientHello that times out, and SNI or decrypted
HTTP authority mismatches. The allow-path test proves the origin receives the
daemon test credential in place of an attacker-supplied Authorization header,
then rejects a disallowed path on the same TLS connection. The two-session
test sends opaque bytes through a tunnel-only session, shuts it down, then
completes an intercepted HTTPS request through the still-running session.
There is not yet an HTTP/2 client regression. The bridge admission limit and
session failure event are tested directly, and the shutdown test verifies
socket removal while an existing tunnel stream is still draining.

The existing Unix-to-loopback-TCP bridge remains in use for Rama. Its
admission semaphore and socket permissions match the Hudsucker design. Rama
native Unix sockets were not tested, so they cannot yet replace the bridge
safely.

## Reproduction and measurements

Measurements below were taken in the `baffle` repository with Rust 1.98.1 and
Cargo 1.98.1 on the `ld-cladding` runner after implementing the Rama runtime
and middleware. Clean build means `cargo clean` followed by the listed build.
Incremental build means an immediate repeat. Binary sizes are for
`target/{debug,release}/baffle`.

| Check | Hudsucker | Rama |
| --- | ---: | ---: |
| `cargo test --locked --no-default-features --features backend-*` | Passed: 98 tests | Passed: 38 tests, including 32 Rama unit tests |
| Clean debug build | 18.68 s | 46.75 s |
| Incremental debug build | 0.15 s | 0.17 s |
| Clean release build | 32.60 s | 69.83 s |
| Incremental release build | 0.15 s | 0.29 s |
| Debug / release binary | 172,000,024 / 14,505,040 bytes | 312,000,528 / 18,190,304 bytes |
| Normal dependency graph entries | 253 | 359 |

Count dependency entries with:

```sh
cargo tree --locked --no-default-features --features backend-hudsucker -e normal --prefix none | sort -u | wc -l
cargo tree --locked --no-default-features --features backend-rama -e normal --prefix none | sort -u | wc -l
```

Both backend test commands and Clippy checks passed. Formatting, Hudsucker
example compilation, and the four network namespace checker tests passed in
this run. CI retains debug and release test jobs for each backend:

```sh
cargo test --locked --no-default-features --features backend-hudsucker
cargo clippy --locked --all-targets --no-default-features --features backend-hudsucker -- -D warnings
cargo fmt --all -- --check
cargo check --locked --examples --no-default-features --features backend-hudsucker
cargo test --locked --release --no-default-features --features backend-hudsucker
cargo test --locked --no-default-features --features backend-rama
cargo clippy --locked --all-targets --no-default-features --features backend-rama -- -D warnings
cargo test --locked --release --no-default-features --features backend-rama
python3 -m unittest discover -s scripts -p 'test_*.py'
```

The runner now has `build-essential` 12.12, CMake 3.31.6, and `libclang-dev`
1:19.0-63. Rama 0.4.0 declares Rust 1.96 as its minimum version. Its selected
DNS feature uses bindgen, and its BoringSSL binding builds native code. CI
installs `libclang-dev`, CMake, and a C++ toolchain for the Rama matrix entry.
Hudsucker-only developers do not need those packages when they use the default
feature. The first Rama-only compile also exposed that `rcgen::Issuer::from_ca_cert_pem`
requires rcgen's `x509-parser` feature. Cargo enables that feature explicitly
so the CA module compiles without Hudsucker's transitive feature selection.

The Rama-selected workspace test command passes 38 tests, including 32 Rama
unit tests. The live tests cover allowed and denied HTTP/1.1 requests on one
intercepted connection, secret injection, upstream trust and hostname checks,
non-TLS and incomplete ClientHello failures, SNI and HTTP authority mismatches,
explicit opaque tunnelling, an unsupported CONNECT body, session failure
reporting, connection admission, and independent shutdown. HTTP/2 streams and
resource exhaustion beyond the bridge admission limit remain untested.

The dependency graph count includes each unique crate name and version in the
normal dependency tree. The Rama graph adds 106 entries and includes
`rama-dns`, `rama-tls-boring`, `rama-boring`, and `rama-boring-sys`. The Boring
bindings compile native BoringSSL sources with CMake. Rama's Rust 1.96 MSRV,
bindgen/libclang, C++ toolchain, and custom policy/TLS integration remain extra
maintenance costs. Rama's clean debug and release builds took about 2.5 and
2.1 times as long as Hudsucker's. Its release binary is 3.7 MB larger. The
Rama tree contains `rama` without `hudsucker`; the Hudsucker tree contains the
vendored `hudsucker` without `rama`.

## Comparison and maintenance cost

| Option | Evidence from this repository | Maintenance impact |
| --- | --- | --- |
| Vendored Hudsucker 0.25.0 | Default backend. Existing unit, integration, HTTP/2, lifecycle, TLS authority, path, secret, and bridge tests pass. The local changes are listed in [`vendor/hudsucker/PATCHES.md`](../vendor/hudsucker/PATCHES.md). | Keeps a small local fork and requires review when rebasing Hudsucker. Its handlers, TLS hooks, bridge lifecycle, and Baffle policy already work together. |
| Rama 0.4.0 | Optional backend with end-to-end HTTP/1.1 interception and tunnel tests. It uses verified upstream TLS, disabled key logging, fail-closed peeking, Baffle's shared policy, and configured CA material. HTTP/2 is not tested. | Adds 106 dependency entries, a Rust 1.96 MSRV, bindgen/libclang, CMake, native BoringSSL, and custom request middleware and TLS session plumbing. |
| Upstream Hudsucker 0.25.0 with a smaller patch | The repository review records that upstream does not expose Baffle's explicit intercept/tunnel/reject result, CONNECT-bound TLS context, or inner HTTP authority binding. See [`docs/architecture.md`](architecture.md#hudsucker-integration-and-local-patch). | Could reduce the local fork if upstream adds equivalent hooks. It is not safe to replace the current vendor patch based on the existing API. |

The current evidence does not support changing Baffle's default to Rama. It
does show a working, independently selectable prototype and a viable
integration path. Keep Hudsucker as the default while Rama's HTTP/2 coverage
and remaining authority, resource, and failure cases are addressed. This run
does not change the assessment of upstream Hudsucker.

## Remaining prototype work

Add HTTP/2 tests that send multiple streams over one intercepted connection
and verify each stream receives the same authority, path, and credential
checks. Add stalled-session shutdown and broader connection/resource-limit and
task-failure tests, then rerun the two-backend test and Clippy matrix. Evaluate
Rama's native Unix sockets separately with the existing network namespace and
internal-listener protections in place; do not replace the current bridge
based on API availability alone. Compare the middleware and certificate
integration cost against the local Hudsucker patch and an upstream Hudsucker
version with equivalent policy hooks.
