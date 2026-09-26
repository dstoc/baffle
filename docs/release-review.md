# Release review record

Reviewed on 2026-09-26 against the repository and current GitHub Actions
workflows.

## Package and CI

- Cargo package: `baffle-proxy`; executable: `baffle`; client library package:
  `baffle-client`.
- `Cargo.lock` is committed. CI and the release workflow build with
  `--locked` so a build cannot silently change dependency resolution.
- The release workflow accepts a `v<version>` tag only when it matches the
  `baffle-proxy` package version. It builds the release binary for
  `x86_64-unknown-linux-gnu`, packages the binary and documentation, and
  publishes a SHA-256 checksum with the GitHub release. Before packaging, it
  requires a non-empty top-level `LICENSE` file and Cargo license metadata.
  It includes `LICENSE` in the release archive. The root `LICENSE` applies the
  MIT License to Baffle's original code, and `baffle-proxy` declares the `MIT`
  SPDX identifier. Third-party dependencies retain their own license terms.
  The archive also includes the CDLA-Permissive-2.0 agreement for the Mozilla
  root certificate data from `webpki-root-certs`.
- The package targets Linux x86-64 with the GNU C library. Other Linux
  architectures and static linking are not included in this release job.

## Dependency and runtime review

- Rama 0.4.0 is the only proxy runtime. It uses the `http-full` and `boring`
  features and requires Rust 1.96 or newer, CMake, a C++ toolchain, and
  `libclang-dev` to build from source. CI and release jobs install these native
  prerequisites. Prebuilt release binaries do not require them at runtime.
- Baffle authorizes the exact hostname and port before dialing, but does not
  filter DNS answers or pin destination addresses. Deployment DNS and network
  egress controls own address restrictions. Retain fail-closed interception,
  CONNECT/TLS/HTTP identity checks, and normal upstream TLS verification.
- The daemon-facing runtime boundary is documented in `docs/architecture.md`.
  It keeps policy, CA ownership, secrets, the control protocol, and session
  lifecycle independent of Rama networking types.
- CI and release builds use the committed lock file with `--locked`. This keeps
  dependency resolution reproducible; it does not check dependencies against
  security advisories. No automated RustSec advisory scan is configured in the
  repository or CI. baffle/38 tracks adding that release-readiness check.

## Logging and error handling

- The binary defaults to the `baffle_proxy=info` tracing filter. Baffle's
  request decision events include a session ID, method, destination authority,
  decision, and counters. They omit paths, queries, request headers, bodies,
  and resolved credentials.
- Control protocol errors use stable codes and safe messages. Session setup
  errors sent to clients do not include policy or credential data. Internal
  errors use a class in daemon logs.
- The secret type redacts its `Debug` output. Secret files and CA signing keys
  are validated before use. Existing tests cover file permissions, entitlement
  checks, redaction, host/path boundaries, and injection rules.
- Runtime lifecycle and transport errors are logged without request paths,
  headers, bodies, or resolved credentials. Keep logs access-controlled and
  review custom `RUST_LOG` filters.

## Deployment security gate

- The Baffle policy is not a firewall. Sandboxed clients must have no direct
  path to external networks.
- Internal Rama listeners bind to loopback in Baffle's network namespace.
  Sandboxed clients must not share that namespace or otherwise reach those
  listeners.
- `.github/workflows/ci.yml` runs the privileged Linux namespace fixture on
  pull requests and main-branch pushes. The separate
  `.github/workflows/network-namespace.yml` workflow runs the same fixture only
  when manually dispatched. Operators must validate their actual deployment
  topology as well.
- Only the trusted operator may access the control socket. Expose only the
  assigned mode-`0600` session socket to each client. Never expose the CA
  private key or secret directory to a sandbox.

## Release-readiness actions

- **Dependency advisories:** Add an automated RustSec scan and define how
  maintainers handle its findings. Tracked in baffle/38.
