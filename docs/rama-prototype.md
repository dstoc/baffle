# Rama backend evaluation

## Result

This is a failed prototype, not a migration decision. Hudsucker remains the
default backend. The Rama feature currently rejects every session before it
opens a listener. This preserves the fail-closed behavior while the security
integration is incomplete.

The backend flags are mutually exclusive. `backend-hudsucker` is the default.
`backend-rama` selects Rama 0.4.0 with the `http-full` and `boring` features.
The daemon uses a shared runtime error and event type for either adapter.

## Why the prototype stops

Baffle's current handler binds the CONNECT authority to TLS SNI and each
decrypted HTTP authority. It also rejects unsupported TLS payloads when a
rule requires interception. Those checks live in the vendored Hudsucker
integration and do not transfer to Rama automatically.

Rama provides HTTP/1.1 and HTTP/2 MITM examples backed by BoringSSL. Its
documented `TlsMitmRelay` flow disables upstream certificate verification.
That flow cannot enforce Baffle's certificate and hostname trust requirement
without a custom verified egress connector. The Rama adapter does not yet
implement that connector, the CONNECT/SNI/HTTP authority binding, or
fail-closed handling for fragmented ClientHello messages and unsupported
CONNECT payloads. See the [Rama MITM documentation](https://docs.rs/crate/rama/0.4.0/source/docs/book/src/proxies/mitm.md)
and the [Rama Boring TLS README](https://docs.rs/crate/rama-tls-boring/0.4.0/source/README.md).

The current `SessionPolicy` also uses Hudsucker's Hyper HTTP types. A shared
request-policy contract and a Rama adapter for that contract are still
required before both backends can use the same path and credential checks.

The adapter therefore returns `backend_unavailable` for every session. It
does not start an opaque tunnel. No Rama traffic, credential injection, HTTP/2
stream policy, session cancellation, or independent shutdown was exercised.
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
| `cargo test --locked --no-default-features --features backend-*` | Passed: 98 tests | Passed: 32 tests; no proxy traffic exercised |
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
```

The runner now has `build-essential` 12.12, CMake 3.31.6, and `libclang-dev`
1:19.0-63. Rama 0.4.0 declares Rust 1.96 as its minimum version. Its selected
DNS feature uses bindgen, and its BoringSSL binding builds native code. CI
installs `libclang-dev`, CMake, and a C++ toolchain for the Rama matrix entry.
Hudsucker-only developers do not need those packages when they use the default
feature. The first Rama-only compile also exposed that `rcgen::Issuer::from_ca_cert_pem`
requires rcgen's `x509-parser` feature. Cargo enables that feature explicitly
so the CA module compiles without Hudsucker's transitive feature selection.

The 32 passing Rama tests exercise shared daemon/configuration code and the
scaffold. They do not send proxy traffic. `ProxyRuntime::start` returns
`backend_unavailable` before it binds a listener, so this result verifies the
fail-closed placeholder only; it does not verify Rama request handling, TLS,
path enforcement, credentials, or lifecycle behavior.

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
| Rama 0.4.0 | Optional dependency and compile-time API probe are selected. The runtime rejects startup. Rama offers MITM building blocks, but Baffle's trust and authority checks are not integrated or tested. | Adds a larger dependency graph, Rust 1.96 MSRV, bindgen/libclang, CMake, and native BoringSSL. Baffle would need custom policy middleware, verified upstream TLS, authority propagation, fail-closed TLS decisions, and lifecycle supervision. |
| Upstream Hudsucker 0.25.0 with a smaller patch | The repository review records that upstream does not expose Baffle's explicit intercept/tunnel/reject result, CONNECT-bound TLS context, or inner HTTP authority binding. See [`docs/architecture.md`](architecture.md#hudsucker-integration-and-local-patch). | Could reduce the local fork if upstream adds equivalent hooks. It is not safe to replace the current vendor patch based on the existing API. |

The current evidence does not support a migration to Rama. It also does not
show that an upstream Hudsucker patch is available. Keep the existing backend
until a Rama adapter passes the missing trust, authority, fragmented
ClientHello, HTTP/2 stream, resource-limit, failure-propagation, and independent
shutdown tests.

## Next prototype step

Build one Rama session behind the existing bridge with a custom egress
connector that verifies certificates and hostnames. Before enabling any
request path, add tests for CONNECT/SNI/HTTP authority mismatches, invalid and
expired certificates, fragmented ClientHello input, and unsupported CONNECT
payloads. Add the second independently configured session only after those
checks pass. The native-tool measurements are now available; repeat them after
the adapter can build and exercise real proxy traffic.
