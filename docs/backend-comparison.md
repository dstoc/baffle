# Baffle backend size, complexity, and maintenance comparison

## Scope and revisions

This report compares Baffle at commit `ed3946099491931542fc1c71416596bcb3636c9a`, which contains both feature-selected backends. Hudsucker is still the default. Rama is pinned to version `0.4.0` in `Cargo.toml` and `Cargo.lock` (crate checksum `3803b2144b39cfe1e7ef9ad32c20f7335cc573d6d5739bd7b460fc9444b8e85b`). The report does not recommend a backend change or authorize removal of either implementation.

The vendored dependency is Hudsucker 0.25.0. Its packaged source records upstream Git revision `631fa972a4eb1428c52de2ebeab700bc39ea380c` in `.cargo_vcs_info.json`. The vendor patch inventory is in [`vendor/hudsucker/PATCHES.md`](../vendor/hudsucker/PATCHES.md).

## Measurement method

[`scripts/measure_backend_code.py`](../scripts/measure_backend_code.py) is the repeatable source counter. This runner did not have `tokei` or `cloc`, so the repository includes a small Python counter and unit tests instead. It needs only Python 3. It counts Rust code lines and reports comment and blank lines separately. It treats all lines inside a Rust string literal as code, removes comments and blank lines from code LOC, and separates code inside `#[cfg(test)]` items from production code.

The script uses explicit Rust file lists. It excludes examples, docs, external fixtures, generated files, build output, non-Rust files, and any Rust file outside those lists. It includes all five root `tests/*.rs` files as test code. `Cargo.toml` requires `backend-hudsucker` for `client`, `control_protocol`, `daemon_lifecycle`, and `proxy_runtime`; the auto-discovered `tests/documentation.rs` target runs with either backend. The Hudsucker feature gate does not prove every assertion in those four targets is intrinsically Hudsucker-specific. Inline tests are assigned by their `cfg(test)` feature and source file.

The vendor count includes only `vendor/hudsucker/src/**/*.rs`. It reports the full upstream and vendored dependency source separately from Baffle code. The patch comparison uses the 0.25.0 crate source at the revision above. It excludes vendor examples, tests, docs, and manifests from the source LOC comparison. The vendor patch changes no upstream test code.

Reproduce the report counts from the Baffle repository root:

```sh
python3 -m unittest discover -s scripts -p 'test_measure_backend_code.py'
python3 scripts/measure_backend_code.py \
  --revision ed3946099491931542fc1c71416596bcb3636c9a \
  --upstream-hudsucker-src "$(find "$HOME/.cargo/registry/src" -path '*/hudsucker-0.25.0/src' -type d -print -quit)" \
  --format markdown

cargo tree --locked --offline --no-default-features --features backend-hudsucker -e normal --prefix none | sort -u | wc -l
cargo tree --locked --offline --no-default-features --features backend-rama -e normal --prefix none | sort -u | wc -l
```

The first command tests the counter. The script pins source inputs to the specified Git revision, so it produces the same counts after this report and script are added. The dependency commands count unique normal dependency graph entries, not source files. To compare the Hudsucker vendor patch, the upstream source path must point to the exact 0.25.0 package whose `.cargo_vcs_info.json` contains the recorded revision.

## Current dual-backend measurements

Code LOC excludes comments and blank lines. Test LOC includes inline Rust test items and the listed root integration-test files. Function and module counts are source declarations counted by the script; they are not cyclomatic-complexity scores.

| Baffle first-party category (vendor changes excluded) | Production Rust code LOC | Test Rust code LOC | Functions | Modules |
| --- | ---: | ---: | ---: | ---: |
| Backend-neutral Baffle core | 2,249 | 788 | 109 | 9 |
| Shared adapters and policy abstractions | 663 | 1,047 | 33 | 2 |
| Hudsucker adapter/runtime | 717 | 2,963 | 33 | 0 |
| Rama adapter/runtime | 857 | 1,303 | 29 | 0 |
| **Total first-party Rust** | **4,486** | **6,101** | **204** | **11** |

The 663 shared source LOC are counted once. They include `src/proxy_runtime.rs`, the shared `SessionPolicy` in `src/policy.rs`, and the shared CA manager plus backend-specific CA material in `src/ca.rs`. `RequestFacts` maps Rama requests into the shared policy; Hudsucker uses its own request adapter. `ManagedCa::load` and `for_rama_proxy` convert the daemon CA to Rama's BoringSSL `X509` and `PKey` types. These are part of the current dual-backend cost. Some feature-conditioned parts can go in a single-backend build; the counter does not assign those lines to both adapters or subtract them from the estimates below. The 1,047 test LOC attributed to this category are Hudsucker-gated tests in shared files, not cross-backend tests. The 699 backend-neutral unit-test LOC run with either feature selection, as do 89 external documentation-test LOC.

Test LOC by current ownership:

| Test group | Rust test code LOC | What it covers now |
| --- | ---: | --- |
| Backend-neutral unit tests | 699 | Shared configuration, daemon, client, control, telemetry, and secret tests that compile in both feature selections. |
| Backend-neutral external documentation tests | 89 | TOML and documentation examples checked with either feature selection. |
| Hudsucker adapter unit tests | 660 | Hudsucker handler, TLS, and adapter-specific behavior. |
| Hudsucker-gated external integration tests | 2,303 | Four root test targets currently gated to Hudsucker in `Cargo.toml`. |
| Hudsucker-specific shared-policy/CA/control unit tests | 1,047 | Tests in shared files that use Hudsucker request, CA, or runtime types. |
| Rama-specific unit tests | 1,303 | Rama parser, TLS, HTTP middleware, bridge, and runtime behavior. |

The report does not label the 2,303 Hudsucker-gated integration LOC as removable. An in-progress #29 issue update reports a shared live-proxy test pass for both features, covering malformed CONNECT, SNI binding, one-byte ClientHello fragmentation, tunnel-only behavior, and upstream certificate rejection. That update also reports moving Rama's upstream dial until after SNI validation. It does not identify a shared commit, and those changes are not in the `ed39460` source measured here. Treat that update as pending integration evidence. #28's namespace work and #30's runtime/build measurements remain in progress.

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
| Measured Baffle adapter and tests | 717 production LOC; 2,963 test LOC, including the 2,303 LOC Hudsucker-gated external suite. | 857 production LOC; 1,303 Rama unit-test LOC. |
| Dependency source and local patch | Uses Hudsucker 0.25.0. The vendored source is 2,085 LOC versus 2,045 LOC in the exact upstream source. Three source files differ by 102 added and 55 removed textual lines. | No Hudsucker source or patch in the Rama feature selection. The 857 adapter LOC do not include Rama's BoringSSL CA conversion, which is counted once in the shared 663 LOC. |
| Structure and security control flow | 33 adapter functions. Hudsucker owns most HTTP, CONNECT, and TLS machinery; Baffle's adapter configures hooks, binds authorities, injects secrets, and supervises the library and bridge. | 29 adapter functions. Baffle owns the CONNECT parser, ClientHello inspection, BoringSSL configuration, HTTP policy middleware, and proxy task supervision. |
| Shared abstractions and duplication | Both use the same `SessionPolicy`, daemon CA source, runtime interface, and secret store. Hudsucker-specific request handling is in its adapter. | Both use the same shared components. Rama maps requests to `RequestFacts`; its CA adapter converts the shared CA to BoringSSL objects. Each runtime currently duplicates the Unix bridge, socket guard, copy helpers, and lifecycle supervision. |
| Native dependencies and build | 253 normal dependency entries. No Rama-specific native toolchain. Dependency upgrades must rebase and retest the local strict-interception and authority patch. | 359 normal dependency entries, including Rama DNS and BoringSSL packages. Requires Rust 1.96+, CMake, C++, and libclang. Native setup increases clean-build and CI requirements. |
| Single-backend work removable | If Hudsucker is selected, remove Rama's 857 adapter LOC, 1,303 Rama test LOC, Rama feature dependencies, native setup, and matrix entry. Keep Hudsucker's patch until equivalent hooks ship upstream. | If Rama is selected, remove Hudsucker's 717 adapter LOC, 660 adapter-test LOC, Hudsucker dependency and vendor subtree. Port or share the 2,303 LOC external suite and preserve any shared-policy checks still needed; do not delete coverage solely because it is Hudsucker-gated. |

The 2,249 core LOC, 663 shared source LOC, and 788 backend-neutral test LOC (699 unit plus 89 documentation-test LOC) are common costs, not duplicated additions to both backends. The 1,047 tests in shared source files currently depend on Hudsucker types and must be reviewed separately if Rama becomes the only backend.

## Single-backend estimates

These estimates start from the pinned dual-backend source and test counts. They retain all 663 LOC of shared source in both estimates. That is a conservative upper bound because a single-backend build could remove some dual-backend selection and conversion code. The estimates do not claim that every line of test code can be deleted safely.

| Counterfactual | Estimated Baffle production Rust code LOC | Test Rust code LOC for comparable coverage | Assumptions and removable work |
| --- | ---: | ---: | --- |
| Hudsucker only | 3,629 measured LOC | 4,798 measured LOC | Keep the core, all shared code, Hudsucker adapter, Hudsucker tests, and current external suite. Remove Rama's 857 adapter LOC and 1,303 Rama test LOC. Remove Rama from the optional dependency graph and CI matrix, including Rama's native build setup. Keep the current Hudsucker vendor patch unless upstream supplies and tests equivalent hooks. |
| Rama only | 3,769 measured upper-bound LOC | 4,394–5,441 estimated LOC | Keep the core, all shared code, and Rama adapter. Retain the 788 common and 1,303 Rama test LOC. Port or share the 2,303 LOC Hudsucker-gated external integration suite to preserve its coverage. The lower test estimate assumes current Rama tests cover all shared policy/CA/control invariants; the upper estimate re-expresses the 1,047 LOC Hudsucker-gated shared-file tests as well. Remove the Hudsucker adapter (717 LOC), Hudsucker-only adapter tests (660 LOC), Hudsucker vendor patch, and Hudsucker dependency/CI entry after equivalent coverage is in place. |

For Rama-only, the current runnable test source is 2,091 LOC (788 common plus 1,303 Rama-specific). That is not an equivalent-coverage estimate because the external integration suite is Hudsucker-gated today. The 4,394–5,441 range is an estimate of maintained test source after porting or replacing those checks. It is not a measured Rama test suite.

Neither estimate turns the shared policy or CA code into two independent copies. The 663 LOC are included once in each scenario because both backends use them now. A future single-backend refactor can remove the other backend's `cfg` branches and some boundary code, but its reduction should be measured after the necessary security tests pass. These estimates do not include runtime labor savings.

## Dependency and native build costs

| Feature selection | Optional direct dependencies | Native build requirements | Normal dependency graph |
| --- | --- | --- | ---: |
| `backend-hudsucker` | `hudsucker = 0.25.0` with `http2`; `rcgen = 0.14.10` with `x509-parser` | No Rama-specific CMake, BoringSSL, or libclang build. | 253 entries |
| `backend-rama` | `rama = 0.4.0` with `http-full` and `boring`; `rcgen = 0.14.10` with `x509-parser` | Rust 1.96 minimum; CMake, a C++ toolchain, and libclang for BoringSSL/bindgen. CI installs `build-essential`, `cmake`, and `libclang-dev`. | 359 entries |

Rama adds 106 normal graph entries over Hudsucker in this lockfile. Its selected graph includes `rama-dns`, `rama-tls-boring`, `rama-boring`, and `rama-boring-sys`. This adds native compiler and generated-binding setup to clean builds and dependency upgrades. Hudsucker instead carries a local fork that must be rebased and reviewed against upstream. Both choices require ongoing dependency and CVE review; this comparison does not assign hours or claim measured labor savings.

The measurements ran on `ld-cladding` with Python 3.13.5, Rust 1.98.1, and Cargo 1.98.1. The counter's four unit tests, the full Python script test suite (eight tests), formatting check, and both backend test commands passed on the working branch. The Hudsucker test command ran 98 tests; the Rama command ran 46. These runs do not establish backend parity: the four external integration targets remain Hudsucker-gated at the measured commit.

If Hudsucker adds the required hooks upstream, Baffle could use an upstream release and remove its local vendor delta. The needed hooks are: a CONNECT-time `Intercept`/`Tunnel`/`Reject` decision; CONNECT authority in TLS policy and intercepted request context; and a per-request authority check that preserves fail-closed behavior. Hudsucker 0.25.0 does not provide those hooks. The `HttpHandler` callback is not enough to reject every unsupported CONNECT payload without the current internal changes. Until an upstream release provides equivalent behavior and the Baffle tests pass, an upstream-only dependency is not a safe replacement. If upstream accepts the hooks, Baffle's local vendor patch can drop to zero added/deleted source lines; no such release was available for this measurement.

## Structure and async control flow

The source counter found 33 line-anchored function declarations in the Hudsucker adapter and 29 in the Rama adapter. These counts do not show that the larger file is more complex. They also do not include dependency code in the Hudsucker count. Baffle delegates most protocol handling to Hudsucker's 2,045 LOC upstream source; the three-file patch alters its CONNECT flow. Rama implements more of the proxy state machine in Baffle.

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
| Strict interception failure | The vendor patch rejects unknown CONNECT payloads and failed TLS interception instead of falling back to an opaque tunnel when inspection is required. Baffle selects opaque tunneling only for an explicit tunnel rule at CONNECT admission. | ClientHello peeking uses `PeekTimeoutPolicy::FailClosed`; non-TLS, incomplete, stalled, mismatched-SNI, or failed TLS closes after interception is selected. At `ed39460`, Rama opens the approved upstream TCP socket before the SNI check, but does not relay TLS bytes before the check. The in-progress #29 update reports moving the dial after SNI validation; that code is not in this measured tree. | The failure point and CONNECT response timing differ. #29 reports passing fragmented ClientHello and other live-proxy cases in its working tree, but the shared tested revision is not recorded yet. |
| HTTP/1.1 and HTTP/2 request paths | `HttpHandler::handle_request` runs for requests; the handler checks URI/Host authority, HTTPS scheme, and canonical path before forwarding or injection. Hudsucker serves HTTP/2. | `RamaPolicyService::serve` maps each decrypted request to `RequestFacts`, authorizes and canonicalizes its path, then calls the inner service. | Request checks must remain per request or per HTTP/2 stream, including reused HTTP/1.1 connections. #28/#29 have not yet reported parity outcomes. |
| Credential injection and redaction | `inject_headers` validates the output header and secret, formats raw/Bearer/Basic values, and replaces client-supplied headers only after policy checks. `SecretValue` redacts its `Debug` output. | `apply_header_injections` applies the same formats and replacement order after shared authorization; logs do not include secret values. | Formatting and replacement code is duplicated. Shared fixtures should prove denied requests and concurrent streams cannot leak credentials. |
| Tunnel isolation | Only an explicit tunnel rule selects `TlsInterception::Tunnel`; unsupported or failed interception does not become a tunnel. | Only an authorized `RuleMode::Tunnel` reaches `handle_tunnel`; it opens the approved CONNECT destination and copies opaque bytes without application credentials. | Tunnels intentionally do not inspect paths or verify upstream TLS. Tests must confirm no injection occurs on tunnel-only rules. |
| Cancellation and shutdown | Baffle cancels the Hudsucker graceful-shutdown future and bridge ingress, waits for a bounded grace period, then aborts tracked tasks. | Baffle stops bridge ingress and proxy accept, joins connection tasks, and aborts the proxy and bridge on timeout or runtime drop. | Different task trees make cancellation and partial-startup paths easy to diverge. Both implementations own this integration burden. |
| Unix bridging and socket cleanup | Baffle binds a private loopback listener and mode-`0600` Unix socket. An inode/device guard avoids unlinking a replacement path. | Uses the same intended permissions, bridge limits, and inode/device cleanup guard in its adapter. | Guard, bridge, and copy code are duplicated in both runtime files. Socket replacement, symlink, connection-limit, and cleanup tests should be shared. |

## Maintenance trade-offs and follow-up evidence

Hudsucker keeps the Baffle adapter smaller and delegates protocol machinery to a mature upstream library. Its current cost is the 157-line textual vendor diff, which must be compared with each upgrade and re-tested for CONNECT admission, authority binding, fail-closed interception, HTTP/2, and upstream TLS verification. Upstreaming those hooks would remove the fork-specific diff but would still require dependency upgrades and CVE reviews.


Concrete maintenance work that can reduce cost without changing the default:

- Complete #28 and #29, then share or port the real-daemon, HTTP/2, fragmented ClientHello, authority, credential, and socket-lifecycle fixtures. Record any tests that remain backend-specific.
- Integrate and record the exact tested revision from #29 before treating its live-proxy results or its SNI-before-dial change as part of the measured source.
- Use #30's build and runtime measurements when available. #30 has started a repeatable harness but has not posted results yet.
- Keep the Hudsucker vendor diff limited to strict interception and authority binding. Revisit the upstream-only option only after the required hooks are released and the same security tests pass.
- Consider extracting the duplicate bridge and socket guard after the backend parity tests exercise their cancellation and cleanup behavior.
- Keep Hudsucker's default feature and both backend implementations unchanged until a separate decision is reviewed.
