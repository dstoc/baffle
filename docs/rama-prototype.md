# Rama backend evaluation

## Result

This is an incomplete prototype, not a migration decision. Hudsucker remains
the default backend. The Rama feature currently rejects every session before
it opens a listener. This preserves fail-closed behavior while the security
integration is incomplete.

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
raw tunnel. The new tests exercise the pinned API's fragmented-input timeout,
the no-ClientHello result, and construction of the explicit TLS settings. They
test Rama primitives; they do not send proxy traffic. See the [ClientHello
peeker API](https://docs.rs/rama/0.4.0/rama/tls/server/struct.PeekTlsClientHelloService.html).

The runtime adapter still returns `backend_unavailable` before it binds a
listener. It does not start even an opaque tunnel. `SessionPolicy` also uses
Hudsucker's Hyper HTTP types, so Rama cannot yet apply Baffle's path and
credential checks to its requests. The Rama path still needs a shared request
policy interface, an issuer built from Baffle's configured CA without exposing
its private key, CONNECT/SNI/decrypted-authority binding, and a runtime that
supervises connections and shutdown. No Rama requests, HTTP/2 streams,
credentials, session cancellation, or independent shutdown have been tested.

The existing Unix-to-loopback-TCP bridge remains part of the Hudsucker
runtime. Rama native Unix sockets were not tested, so they cannot yet replace
that bridge safely.

## Reproduction and measurements

Measurements below were taken in the `baffle` repository with Rust 1.98.1 and
Cargo 1.98.1 on the `ld-cladding` runner. Clean build means `cargo clean`
followed by the listed build. Incremental build means an immediate repeat.
Binary sizes are for the release executable.

| Check | Hudsucker | Rama |
| --- | ---: | ---: |
| `cargo test --locked --no-default-features --features backend-*` | Passed: 98 tests | Passed: 35 tests; no proxy traffic exercised |
| Clean debug build | 22.97 s | 58.49 s |
| Incremental debug build | 0.17 s | 0.19 s |
| Clean release build | 40.87 s | 73.14 s |
| Debug / release binary | 171,948,416 / 14,505,656 bytes | 87,161,472 / 6,083,296 bytes |
| Normal dependency graph entries | 253 | 359 |

Count dependency entries with:

```sh
cargo tree --locked --no-default-features --features backend-hudsucker -e normal --prefix none | sort -u | wc -l
cargo tree --locked --no-default-features --features backend-rama -e normal --prefix none | sort -u | wc -l
```

The Hudsucker test, Clippy, formatting, examples, and release test commands
passed. The Rama test, Clippy, and release test commands also passed:

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

The Rama suite now has 35 passing tests, including three adapter-level checks
for the public TLS controls and ClientHello peeker. These tests do not send
proxy traffic. `ProxyRuntime::start` returns `backend_unavailable` before it
binds a listener, so the suite verifies the fail-closed placeholder and the
availability of relevant Rama primitives. It does not verify Rama request
handling, upstream certificate validation, path enforcement, credentials, or
lifecycle behavior.

The dependency graph count includes each unique crate name and version in the
normal dependency tree. The Rama graph adds 106 entries and includes
`rama-dns`, `rama-tls-boring`, `rama-boring`, and `rama-boring-sys`. The Boring
bindings include BoringSSL native sources and use CMake. Rama's HTTP feature
set therefore costs more than adding a single proxy crate. In this run, the
Rama clean debug and release builds took about 2.5 and 1.8 times as long as the
Hudsucker builds. Its release binary was smaller, but the build-time and size
results do not offset the missing runtime and security integration.
The Rama tree contains `rama` without `hudsucker`; the Hudsucker tree contains
the vendored `hudsucker` without `rama`.

## Comparison and maintenance cost

| Option | Evidence from this repository | Maintenance impact |
| --- | --- | --- |
| Vendored Hudsucker 0.25.0 | Default backend. Existing unit, integration, HTTP/2, lifecycle, TLS authority, path, secret, and bridge tests pass. The local changes are listed in [`vendor/hudsucker/PATCHES.md`](../vendor/hudsucker/PATCHES.md). | Keeps a small local fork and requires review when rebasing Hudsucker. Its handlers, TLS hooks, bridge lifecycle, and Baffle policy already work together. |
| Rama 0.4.0 | Optional dependency and primitive-level tests are selected. The runtime rejects startup. Public APIs exist for verified upstream TLS, disabled key logging, and fail-closed ClientHello peeking; Baffle's trust and authority checks are not integrated or tested. | Adds a larger dependency graph, Rust 1.96 MSRV, bindgen/libclang, CMake, and native BoringSSL. Baffle would need custom policy middleware, authority propagation, fail-closed TLS decisions, and lifecycle supervision. |
| Upstream Hudsucker 0.25.0 with a smaller patch | The repository review records that upstream does not expose Baffle's explicit intercept/tunnel/reject result, CONNECT-bound TLS context, or inner HTTP authority binding. See [`docs/architecture.md`](architecture.md#hudsucker-integration-and-local-patch). | Could reduce the local fork if upstream adds equivalent hooks. It is not safe to replace the current vendor patch based on the existing API. |

The current evidence does not support a migration to Rama. It also does not
show that an upstream Hudsucker patch is available. Keep the existing backend
until a Rama adapter passes the missing trust, authority, fragmented
ClientHello, HTTP/2 stream, resource-limit, failure-propagation, and independent
shutdown tests.

## Next prototype step

Build one Rama session behind the existing bridge. Set `ServerVerifyMode::Auto`
with the authorized CONNECT target as the verification identity, set
`KeyLogIntent::Disabled`, and use a no-forwarding fallback for mandatory
interception. First make `SessionPolicy` backend-neutral and load the existing
configured CA into Rama's issuer while keeping the key inside daemon-owned
state. Then add tests for CONNECT/SNI/HTTP authority mismatches, valid, invalid
and expired upstream certificates, fragmented ClientHello input, unsupported
CONNECT payloads, and per-request HTTP/1.1 and HTTP/2 policy. Add the second
independently configured session only after those checks pass. Repeat the
build and binary measurements after Rama handles real proxy traffic.
