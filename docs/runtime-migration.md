# Runtime migration note

baffle/34 made Rama 0.4.0 Baffle's only supported proxy runtime after baffle/33
enabled and verified `TCP_NODELAY` on accepted client sockets. The change
removed the Hudsucker adapter, vendored source, Cargo patch, backend feature
switches, backend-specific policy and CA branches, and dual-backend CI and
benchmark code. The normal Cargo build and test commands now use Rama.

The daemon-facing boundary remains in `src/proxy_runtime.rs`. It provisions an
opaque session handle, returns only after listeners are bound, exposes the
bound listener address and Unix socket path, reports runtime exit events, and
supports cancellation with bounded shutdown. The private Rama implementation
owns TLS and HTTP processing, the Unix-to-TCP bridge, socket cleanup, and task
supervision. The daemon retains ownership of policy, session leases, CA
material, credentials, and the control protocol.

Rama is the only runtime implemented and supported in this repository. The
daemon-facing boundary keeps Baffle's lifecycle and policy types outside the
Rama module; the repository has no second implementation or backend selector.
An alternative runtime, if added later, would need to preserve the existing
Unix socket, fail-closed interception, upstream TLS verification, and session
lifecycle behavior. No backend selector is persisted in TOML or exposed through
the control protocol.

Historical Baffle-authored code and performance comparisons remain in the
[archived backend comparison](backend-comparison.md) and
[benchmark report](benchmarking.md). Historical Hudsucker values and commands
describe the pre-migration source; the current benchmark scripts run Rama only.
