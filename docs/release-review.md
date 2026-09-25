# Release review record

Reviewed on 2026-09-25 for the initial Linux release work.

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
  It includes `LICENSE` in the release archive. The project owner must approve
  the terms recorded in both places.
- The package targets Linux x86-64 with the GNU C library. Other Linux
  architectures and static linking are not included in this release job.

## Dependency and Hudsucker review

- `hudsucker` is pinned to exactly `0.25.0` and patched to
  `vendor/hudsucker`. `vendor/hudsucker/PATCHES.md` records the fail-closed
  CONNECT and TLS hooks, validated outbound address hooks, their security
  rationale, and the upstreaming plan.
- Baffle relies on the vendored connector and resolver hooks for outbound
  HTTP, CONNECT, and WebSocket connections. Keep the local diff narrow and
  repeat egress, interception, CONNECT, HTTP/2, and WebSocket coverage before
  changing the pinned version.
- The dependency versions used by CI and releases come from the committed lock
  file. This repository does not currently run an automated RustSec advisory
  scan; maintainers should add one before adopting a security patch cadence.

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
- Hudsucker emits authority and transport error metadata. Keep logs
  access-controlled and review custom `RUST_LOG` filters.

## Deployment security gate

- The Baffle policy is not a firewall. Sandboxed clients must have no direct
  path to external networks.
- Internal Hudsucker listeners bind to loopback in Baffle's network namespace.
  Sandboxed clients must not share that namespace or otherwise reach those
  listeners.
- The privileged Linux namespace fixture runs in a separate CI workflow on
  pull requests and main-branch pushes. Operators must validate their actual
  deployment topology as well.
- Only the trusted operator may access the control socket. Expose only the
  assigned mode-`0600` session socket to each client. Never expose the CA
  private key or secret directory to a sandbox.

## Maintainer follow-up

The repository has no top-level `LICENSE` file and the Cargo package metadata
does not declare a license. The release workflow stops until the project owner
selects and records the distribution terms in both places. No license has been
inferred from the vendored Hudsucker crate.
