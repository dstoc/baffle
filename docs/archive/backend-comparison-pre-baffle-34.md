# Archived backend comparison (pre-baffle/34)

This is a static record of the Hudsucker/Rama source comparison before the
baffle/34 migration. Hudsucker is no longer shipped or built. The feature flags,
vendored tree, and code-count script described below have been removed, so the
commands are historical and do not run against the current source. Current
benchmark scripts and runtime requirements are documented separately.

## Scope and revisions

This report compares Baffle at commit `ed3946099491931542fc1c71416596bcb3636c9a`, which contains both feature-selected backends. Hudsucker was the default at that revision. Rama was pinned to version `0.4.0` in `Cargo.toml` and `Cargo.lock` (crate checksum `3803b2144b39cfe1e7ef9ad32c20f7335cc573d6d5739bd7b460fc9444b8e85b`). The report captures the review evidence before the migration; it does not describe current backend support.

The vendored dependency at that revision was Hudsucker 0.25.0. Its packaged source recorded upstream Git revision `631fa972a4eb1428c52de2ebeab700bc39ea380c` in `.cargo_vcs_info.json`; its patch inventory was removed with the vendored tree.

## Measurement method

The repeatable source counter used for this report was a small Python script with unit tests. It counted Rust code lines and reported comment and blank lines separately. It treated all lines inside a Rust string literal as code, removed comments and blank lines from code LOC, and separated code inside `#[cfg(test)]` items from production code. The counter was removed during baffle/34 because it measured the retired backend matrix.

The script uses explicit Rust file lists. It excludes examples, docs, external fixtures, generated files, build output, non-Rust files, and any Rust file outside those lists. It includes all five root `tests/*.rs` files as test code. `Cargo.toml` requires `backend-hudsucker` for `client`, `control_protocol`, `daemon_lifecycle`, and `proxy_runtime`; the auto-discovered `tests/documentation.rs` target runs with either backend. The Hudsucker feature gate does not prove every assertion in those four targets is intrinsically Hudsucker-specific. Inline tests are assigned by their `cfg(test)` feature and source file.

For `src/ca.rs`, the counter assigns each `#[cfg(feature = ...)]` attribute and the Rust item it gates to that backend. It counts the remaining CA loader, certificate validation, permission checks, and public-certificate export once in the shared category. The CA test module is Hudsucker-gated because it also tests Hudsucker's proxy CA handles. The counter separates the shared validation helpers and four CA validation cases from the Hudsucker cache and TLS cases. The shared cases are still counted once, with a note that they need a Rama test configuration if Rama is selected alone.

The vendor count includes only `vendor/hudsucker/src/**/*.rs`. It reports the full upstream and vendored dependency source separately from Baffle code. The patch comparison uses the 0.25.0 crate source at the revision above. It excludes vendor examples, tests, docs, and manifests from the source LOC comparison. The vendor patch changes no upstream test code.

The source counter and comparative Cargo commands were removed with the
feature matrix. The reported values below are retained as a snapshot of the
specified commit.

## Pre-migration source counts

Code LOC excludes comments and blank lines. Test LOC includes inline Rust test items and the listed root integration-test files. Function and module counts are source declarations counted by the script; they are not cyclomatic-complexity scores.

| Baffle first-party category (vendor changes excluded) | Production Rust code LOC | Test Rust code LOC | Functions | Modules |
| --- | ---: | ---: | ---: | ---: |
| Backend-neutral Baffle core | 2,249 | 788 | 109 | 9 |
| Shared adapters and policy abstractions | 613 | 920 | 30 | 2 |
| Hudsucker adapter/runtime, including Hudsucker CA code | 747 | 3,090 | 35 | 0 |
| Rama adapter/runtime, including Rama CA code | 877 | 1,303 | 30 | 0 |
| **Total first-party Rust** | **4,486** | **6,101** | **204** | **11** |

The 613 shared source LOC include `src/proxy_runtime.rs`, the shared `SessionPolicy` in `src/policy.rs`, and 131 common CA LOC from `src/ca.rs`. The common CA code loads the signing key, validates the certificate and key, checks private-key permissions, and exports the public certificate. The Hudsucker row includes 30 CA LOC for `SharedCaAuthority`, its certificate cache, and `for_proxy`. The Rama row includes 20 CA LOC for loading BoringSSL `X509`/`PKey` material and `for_rama_proxy`. These backend-only lines are no longer included in the shared total.

`RequestFacts` maps Rama requests into the shared policy; Hudsucker uses its own request adapter. The 920 shared-category test LOC include 826 Hudsucker-gated policy/control tests and 94 LOC for common CA validation helpers and cases. The CA validation tests are Hudsucker-gated today because they share a module with Hudsucker TLS tests. The 3,090 Hudsucker test LOC include 660 adapter tests, 127 Hudsucker-specific CA tests, and 2,303 Hudsucker-gated external integration tests. The 699 backend-neutral unit-test LOC run with either feature selection, as do 89 external documentation-test LOC.

CA source allocation from the same counter:

| `src/ca.rs` production ownership | Rust code LOC | Functions |
| --- | ---: | ---: |
| Common CA loading, validation, and export | 131 | 7 |
| Hudsucker signing handle and cache | 30 | 2 |
| Rama BoringSSL material and accessor | 20 | 1 |

Test LOC by current ownership:

| Test group | Rust test code LOC | What it covers now |
| --- | ---: | --- |
| Backend-neutral unit tests | 699 | Shared configuration, daemon, client, control, telemetry, and secret tests that compile in both feature selections. |
| Backend-neutral external documentation tests | 89 | TOML and documentation examples checked with either feature selection. |
| Hudsucker adapter unit tests | 660 | Hudsucker handler, TLS, and adapter-specific behavior. |
| Hudsucker-gated external integration tests | 2,303 | Four root test targets currently gated to Hudsucker in `Cargo.toml`. |
| Hudsucker-specific CA runtime unit tests | 127 | Shared Hudsucker CA cache, proxy-builder, trust, and hostname behavior. |
| Hudsucker-specific shared-policy/control unit tests | 826 | Shared-file tests that use Hudsucker request or runtime types. |
| Shared CA validation unit tests (currently Hudsucker-gated) | 94 | Common CA validation helpers and four validation cases; port or ungate them for Rama-only. |
| Rama-specific unit tests | 1,303 | Rama parser, TLS, HTTP middleware, bridge, and runtime behavior. |

The 2,303 Hudsucker-gated integration LOC are not automatically removable. baffle/28 reports both-backend daemon coverage, including namespace checks, passing at `0037d9d4c0c3d7a3490d2e2220bdc9647e118109`. baffle/29 reports shared live-proxy security coverage, including its privileged namespace job, passing at `aad8c2d2192b0ec430ebd273aeca33008b37e281`. That later revision also moves Rama's upstream dial until after SNI validation. These are post-baseline parity evidence; neither commit is included in the `ed39460` LOC measurement. baffle/30 has not posted measured runtime/build results yet.

### Vendored Hudsucker, separate from Baffle-authored code

| Measurement | Value |
| --- | ---: |
| Hudsucker 0.25.0 upstream source code LOC | 2,045 |
| Vendored Hudsucker source code LOC | 2,085 |
| Source files changed relative to exact upstream | 3 |
| Textual patch lines added / removed | 102 / 55 |
| Baffle test code added to the vendor tree | 0 LOC |

The textual patch counts include changed comments and attributes; they are not added to the Baffle-authored LOC totals. The 2,085 vendored source LOC are dependency source, not code maintained by Baffle authors. Baffle-specific maintenance is the 102 added and 55 removed patch lines, plus the need to review those changes when rebasing the vendor tree.

## Side-by-side decision view

| Dimension | Hudsucker | Rama |
| --- | --- | --- |
| Measured Baffle adapter and tests | 747 production LOC, including 30 Hudsucker CA LOC; 3,090 test LOC, including 127 CA tests and the 2,303 LOC Hudsucker-gated external suite. | 877 production LOC, including 20 Rama CA LOC; 1,303 Rama unit-test LOC. |
| Dependency source and local patch | Uses Hudsucker 0.25.0. The vendored source is 2,085 LOC versus 2,045 LOC in the exact upstream source. Three source files differ by 102 added and 55 removed textual lines. | No Hudsucker source or patch in the Rama feature selection. Rama's adapter row includes its BoringSSL CA conversion. |
| Structure and security control flow | 35 adapter and CA functions. Hudsucker owns most HTTP, CONNECT, and TLS machinery; Baffle's adapter configures hooks, binds authorities, injects secrets, and supervises the library and bridge. | 30 adapter and CA functions. Baffle owns the CONNECT parser, ClientHello inspection, BoringSSL configuration, HTTP policy middleware, and proxy task supervision. |
| Shared abstractions and duplication | Both use 613 shared production LOC and 920 shared-category test LOC, including common CA loading/validation and Hudsucker-gated policy/control tests. Hudsucker-specific request handling is in its adapter. | Both use the same 613 shared production LOC. Rama maps requests to `RequestFacts`. Each runtime currently duplicates the Unix bridge, socket guard, copy helpers, and lifecycle supervision. |
| Native dependencies and build | 253 normal dependency entries. No Rama-specific native toolchain. Dependency upgrades must rebase and retest the local strict-interception and authority patch. | 359 normal dependency entries, including Rama DNS and BoringSSL packages. Requires Rust 1.96+, CMake, C++, and libclang. Native setup increases clean-build and CI requirements. |
| Single-backend work removable | If Hudsucker is selected, remove Rama's 877 adapter/CA LOC, 1,303 Rama test LOC, Rama feature dependencies, native setup, and matrix entry. Keep Hudsucker's patch until equivalent hooks ship upstream. | If Rama is selected, remove Hudsucker's 747 adapter/CA LOC, 660 adapter-test LOC, 127 Hudsucker CA test LOC, Hudsucker dependency, and vendor subtree. Port or share the 2,303 LOC external suite and preserve the 94 LOC common CA validation tests and any shared-policy checks still needed. |

The 2,249 core LOC, 613 shared source LOC, and 788 backend-neutral test LOC (699 unit plus 89 documentation-test LOC) are common costs, not duplicated additions to both backends. The 826 Hudsucker-gated policy/control test LOC need review against Rama tests. The 94 common CA validation test LOC need a Rama test configuration if Rama becomes the only backend.

## Single-backend estimates

These estimates start from the pinned dual-backend source and test counts. They retain all 613 LOC of shared source in both estimates. This is a conservative upper bound because a single-backend build could remove some dual-backend selection code. The estimates do not claim that every line of test code can be deleted safely.

| Counterfactual | Estimated Baffle production Rust code LOC | Test Rust code LOC for comparable coverage | Assumptions and removable work |
| --- | ---: | ---: | --- |
| Hudsucker only | 3,609 estimated LOC (measured category sum) | 4,798 measured LOC | Keep the core, all shared code, Hudsucker adapter, Hudsucker tests, and current external suite. Remove Rama's 877 adapter/CA LOC and 1,303 Rama test LOC. Remove Rama from the optional dependency graph and CI matrix, including Rama's native build setup. Keep the current Hudsucker vendor patch unless upstream supplies and tests equivalent hooks. |
| Rama only | 3,739 estimated upper-bound LOC (measured category sum) | 4,488–5,314 estimated LOC | Keep the core, all shared code, and Rama adapter. Retain the 788 backend-neutral and 1,303 Rama test LOC. Port or share the 2,303 LOC external integration suite and port the 94 LOC common CA validation tests. The lower estimate assumes Rama's existing tests or the shared parity suite cover the 826 LOC of Hudsucker-gated policy/control checks; the upper estimate also ports those 826 LOC. Remove Hudsucker's 747 adapter/CA LOC, 660 adapter-test LOC, 127 Hudsucker CA test LOC, vendor patch, and dependency/CI entry after equivalent coverage is in place. |

For Rama-only, the current runnable test source is 2,091 LOC (788 backend-neutral plus 1,303 Rama-specific). It does not include the 94 LOC of common CA validation tests because their module is Hudsucker-gated, or the Hudsucker-gated external suite. The 4,488–5,314 range estimates maintained test source after porting the common CA cases and external suite. It is not a measured Rama test suite.

Neither estimate turns the shared policy or CA code into two independent copies. The 613 LOC are included once in each scenario because both backends use them now. A future single-backend refactor can remove the other backend's `cfg` branches and some boundary code, but its reduction should be measured after the necessary security tests pass. These estimates do not include runtime labor savings.

## Dependency and native build costs

| Feature selection | Optional direct dependencies | Native build requirements | Normal dependency graph |
| --- | --- | --- | ---: |
| `backend-hudsucker` | `hudsucker = 0.25.0` with `http2`; `rcgen = 0.14.10` with `x509-parser` | No Rama-specific CMake, BoringSSL, or libclang build. | 253 entries |
| `backend-rama` | `rama = 0.4.0` with `http-full` and `boring`; `rcgen = 0.14.10` with `x509-parser` | Rust 1.96 minimum; CMake, a C++ toolchain, and libclang for BoringSSL/bindgen. CI installs `build-essential`, `cmake`, and `libclang-dev`. | 359 entries |

Rama adds 106 normal graph entries over Hudsucker in this lockfile. Its selected graph includes `rama-dns`, `rama-tls-boring`, `rama-boring`, and `rama-boring-sys`. This adds native compiler and generated-binding setup to clean builds and dependency upgrades. Hudsucker instead carries a local fork that must be rebased and reviewed against upstream. Both choices require ongoing dependency and CVE review; this comparison does not assign hours or claim measured labor savings.

The original baseline verification on `ld-cladding` used Python 3.13.5, Rust 1.98.1, and Cargo 1.98.1. It passed the counter and Python tests, formatting check, and both backend test commands (98 Hudsucker tests and 46 Rama tests). This report revision ran `python3 -m unittest discover -s scripts` (11 tests) and the counter against the pinned source and upstream Hudsucker tree. It does not rerun the Rust backend suites because it changes only the measurement script and report. The four external integration targets remain Hudsucker-gated at the measured commit.

If Hudsucker adds the required hooks upstream, Baffle could use an upstream release and remove its local vendor delta. The needed hooks are: a CONNECT-time `Intercept`/`Tunnel`/`Reject` decision; CONNECT authority in TLS policy and intercepted request context; and a per-request authority check that preserves fail-closed behavior. Hudsucker 0.25.0 does not provide those hooks. The `HttpHandler` callback is not enough to reject every unsupported CONNECT payload without the current internal changes. Until an upstream release provides equivalent behavior and the Baffle tests pass, an upstream-only dependency is not a safe replacement. If upstream accepts the hooks, Baffle's local vendor patch can drop to zero added/deleted source lines; no such release was available for this measurement.

## Structure and async control flow

The source counter found 35 line-anchored function declarations in the Hudsucker adapter and CA code, and 30 in the Rama adapter and CA code. These counts do not show that the larger code group is more complex. They also do not include dependency code in the Hudsucker count. Baffle delegates most protocol handling to Hudsucker's 2,045 LOC upstream source; the three-file patch alters its CONNECT flow. Rama implements more of the proxy state machine in Baffle.

The main async paths are:

- **Hudsucker:** `ProxyRuntime::start_with_metrics` builds one proxy and starts the bridge. A supervisor `select!` joins the proxy and bridge, cancels the other task on exit, reports the result, and force-aborts both after the shutdown grace period. The TLS parser, interception handshake, HTTP/1.1 and HTTP/2 serving, and upstream client are mostly in `vendor/hudsucker/src/proxy/internal.rs`.
- **Rama:** `run_proxy` accepts connections and tracks them in a `JoinSet`. `handle_client` parses and authorizes CONNECT, dials the approved destination, peeks the ClientHello, validates SNI, creates BoringSSL TLS settings, and serves decrypted requests through `RamaPolicyService`. The runtime separately supervises the proxy and bridge tasks. `Drop` cancels and aborts both child tasks.

No cyclomatic or cognitive score is reported. Those tools do not reliably describe macro-based Tokio scheduling, delegated library internals, or the lifecycle paths above as one comparable unit. Code review shows that Rama carries more Baffle-owned protocol and TLS orchestration. Hudsucker shifts that work into an upstream library, but its patch must continue to preserve the security hooks.

Both adapters duplicate `UnixSocketGuard`, `bind_unix_listener`, `run_bridge`, connection admission, timed bidirectional copying, and parts of session supervision. This is real dual-backend maintenance code. The duplication must be reviewed in both files when changing socket permissions, inode checks, cancellation, limits, or timeouts. A shared transport layer could reduce drift later, but would need tests for task ownership, inode-safe cleanup, drain order, and forced shutdown before it replaces either copy.

## Security and lifecycle responsibility map

| Responsibility | Hudsucker backend | Rama backend | Shared seam, test burden, or divergence risk |
| --- | --- | --- | --- |
| CONNECT admission | Patched Hudsucker calls `PolicyHandler::handle_request` before dispatch. `connect_should_intercept` chooses interception for intercept rules and never selects tunnel on cancellation or invalid policy. | `read_connect_request` parses bounded HTTP/1.1 CONNECT in `handle_client`; `authorize_connect_authority` runs before dialing. | Both use `SessionPolicy`. They have different parsers and response paths, so malformed request behavior needs differential tests. |
| CONNECT, SNI, and HTTP authority binding | The patch carries CONNECT authority through `HttpContext`; `should_intercept_tls` checks SNI; `authorize_proxy_request` checks each decrypted request against the saved CONNECT authority. | `handle_client` retains the parsed authority, checks ClientHello SNI, and passes the CONNECT host to `RamaPolicyService`, which checks each HTTP request. | The security invariant is shared, but each adapter converts native request/TLS types. Conflicting identity cases must run through both live proxies. |
| Upstream TLS verification | Hudsucker uses its Rustls upstream client and Baffle's AWS-LC provider selection. Its normal certificate-chain and hostname verification remains enabled. | Rama builds `TlsClientConfig` from the inspected ClientHello, sets the approved CONNECT hostname, uses `ServerVerifyMode::Auto`, and disables key logging on both connector and MITM relay. | Different TLS stacks and trust configuration create behavior and CVE-review differences. Verify ALPN, chain, hostname, and key logging in both paths. |
| Strict interception failure | The vendor patch rejects unknown CONNECT payloads and failed TLS interception instead of falling back to an opaque tunnel when inspection is required. Baffle selects opaque tunneling only for an explicit tunnel rule at CONNECT admission. | ClientHello peeking uses `PeekTimeoutPolicy::FailClosed`; non-TLS, incomplete, stalled, mismatched-SNI, or failed TLS closes after interception is selected. At measured commit `ed39460`, Rama opens the approved upstream TCP socket before the SNI check, but does not relay TLS bytes before the check. The later baffle/29 revision `aad8c2d2192b0ec430ebd273aeca33008b37e281` moves the dial after SNI validation. | The failure point and CONNECT response timing differ. The baffle/29 live-proxy security checks passed at that later revision, including malformed CONNECT, SNI binding, fragmented ClientHello, tunnel-only behavior, and upstream certificate rejection. |
| HTTP/1.1 and HTTP/2 request paths | `HttpHandler::handle_request` runs for requests; the handler checks URI/Host authority, HTTPS scheme, and canonical path before forwarding or injection. Hudsucker serves HTTP/2. | `RamaPolicyService::serve` maps each decrypted request to `RequestFacts`, authorizes and canonicalizes its path, then calls the inner service. | Request checks must remain per request or per HTTP/2 stream, including reused HTTP/1.1 connections. baffle/28 daemon coverage passed both backend jobs at `0037d9d4c0c3d7a3490d2e2220bdc9647e118109`; baffle/29 live-proxy security checks passed at `aad8c2d2192b0ec430ebd273aeca33008b37e281`. |
| Credential injection and redaction | `inject_headers` validates the output header and secret, formats raw/Bearer/Basic values, and replaces client-supplied headers only after policy checks. `SecretValue` redacts its `Debug` output. | `apply_header_injections` applies the same formats and replacement order after shared authorization; logs do not include secret values. | Formatting and replacement code is duplicated. Shared fixtures should prove denied requests and concurrent streams cannot leak credentials. |
| Tunnel isolation | Only an explicit tunnel rule selects `TlsInterception::Tunnel`; unsupported or failed interception does not become a tunnel. | Only an authorized `RuleMode::Tunnel` reaches `handle_tunnel`; it opens the approved CONNECT destination and copies opaque bytes without application credentials. | Tunnels intentionally do not inspect paths or verify upstream TLS. Tests must confirm no injection occurs on tunnel-only rules. |
| Cancellation and shutdown | Baffle cancels the Hudsucker graceful-shutdown future and bridge ingress, waits for a bounded grace period, then aborts tracked tasks. | Baffle stops bridge ingress and proxy accept, joins connection tasks, and aborts the proxy and bridge on timeout or runtime drop. | Different task trees make cancellation and partial-startup paths easy to diverge. baffle/28's daemon coverage, including both namespace jobs, passed at its reported revision. |
| Unix bridging and socket cleanup | Baffle binds a private loopback listener and mode-`0600` Unix socket. An inode/device guard avoids unlinking a replacement path. | Uses the same intended permissions, bridge limits, and inode/device cleanup guard in its adapter. | Guard, bridge, and copy code are duplicated in both runtime files. baffle/28's privileged namespace job passed; socket replacement, symlink, connection-limit, and cleanup tests should remain shared where practical. |

## Maintenance trade-offs and follow-up evidence

The pre-migration review identified duplicated Unix bridge and socket-guard
code. baffle/34 removed the Hudsucker implementation and its copy of that
code. Rama now owns the bridge and inode-safe cleanup behind the
daemon-facing runtime boundary. See `docs/architecture.md` for the current
ownership and future replacement point.
