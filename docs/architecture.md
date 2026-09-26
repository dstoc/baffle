# Architecture

**Current runtime architecture.** Baffle accepts HTTPS destinations through
CONNECT and rejects ordinary forward-proxy requests. baffle/25 removed
application-level destination-IP filtering; deployment egress controls own
address restrictions. Fail-closed interception and identity binding remain
required.

Baffle runs one Tokio daemon process. The daemon owns the control listener,
session registry, CA signing key, secret store, shared CA handle, and runtime.
Each proxy session has an independent policy, feature-selected backend,
credential state, data socket, and counters.

## Components

| Component | Source | Responsibility |
| --- | --- | --- |
| CLI and daemon entry point | `src/main.rs`, `src/cli.rs`, `src/daemon.rs` | Parse `daemon` and `ca export` commands, load configuration, start the control server, and handle Ctrl-C. |
| Configuration | `src/config.rs` | Parse strict daemon and session TOML, normalize exact host rules, and reject invalid policy before provisioning. |
| Control server and session manager | `src/control.rs` | Authenticate Unix peers, frame requests and responses, create/list/stop sessions, track leases, enforce limits, and remove sockets. |
| Proxy runtime and bridge | `src/proxy_runtime.rs`, `src/proxy_runtime/hudsucker.rs`, `src/proxy_runtime/rama.rs` | Select one feature-gated backend runtime. Each adapter binds its private loopback TCP listener and Unix data socket, applies connection limits and timeouts, and supervises failures. |
| Shared policy and backend adapters | `src/policy.rs`, `src/proxy_runtime/hudsucker.rs`, `src/proxy_runtime/rama.rs` | Apply exact destination, port, mode, canonical path, TLS identity, and header-injection rules through backend-specific request hooks. |
| CA manager | `src/ca.rs` | Validate CA files, provide signing material to the selected backend, and export only the public certificate. |
| Secret store | `src/secrets.rs` | Authorize symbolic secret names, validate private files, and keep values inside the owning session. |
| Rust client | `crates/baffle-client` | Provide typed asynchronous `create`, `list`, and `stop` operations for consumers. |

## Control flow

The control flow is:

1. The trusted orchestrator connects to the private Unix control socket.
2. Baffle checks the peer UID with Linux `SO_PEERCRED` before reading a frame.
3. Baffle reads one bounded TOML request and validates its protocol version,
   schema, and policy.
4. For `create`, Baffle checks secret entitlements and files before it starts a
   proxy. It reserves capacity, creates a session ID, pre-binds a loopback TCP
   listener, binds a Unix data socket, and starts the feature-selected proxy
   runtime plus its stream bridge.
5. Baffle returns the session ID, data socket path, and persistence setting in
   one JSON response.

The request and response formats are specified in the
[control protocol](control-protocol.md).

## Data flow and policy boundaries

The client's application connects to the session's Unix data socket and sends
standard HTTP proxy traffic. The bridge streams bytes to the session's
pre-bound `127.0.0.1` TCP listener. The selected adapter handles CONNECT,
interception, and upstream traffic. Hudsucker delegates protocol handling to
the vendored Hudsucker library. Rama parses CONNECT, inspects ClientHello, and
serves intercepted HTTP through Rama middleware. The bridge does not buffer
complete requests or responses.

Before forwarding, the policy handler checks the exact host and destination
port. Only CONNECT can establish an outbound destination. It checks paths for
each request carried inside a successfully intercepted TLS connection. It
checks the CONNECT authority against TLS SNI and each decrypted request
authority. Only after an intercepted request passes all checks can the handler
add its configured headers. Both backends use the shared session policy. Each
adapter maps its request and TLS context to that policy before forwarding.

For HTTPS, `tunnel` rules permit an opaque CONNECT tunnel only when no path
restriction or credential injection requires inspection. `intercept` rules
require supported TLS negotiation and a matching SNI. The current code closes
unsupported CONNECT payloads, missing or mismatched SNI, malformed, incomplete,
or stalled ClientHello data, and TLS interception failures; it does not select
an opaque fallback tunnel. A client must not force an opaque tunnel for a rule
that needs inspection. Baffle treats proxy clients as untrusted and assumes
allowlisted sites behave legitimately.

The policy authorizes the exact hostname and port before the selected backend
dials the destination. Baffle does not classify DNS answers, filter addresses,
or pin a resolved address. An allowed hostname can resolve to a private,
loopback, link-local, metadata, or other sensitive address. A valid certificate
verifies the hostname's TLS identity; it does not make the address safe.
Deployment DNS policy and default-deny network egress rules must restrict
reachable addresses when the threat model requires it. Redirects return to the
client; a new request is evaluated against policy again.

These rules protect traffic that reaches Baffle. They do not stop a sandboxed
process from making a direct network connection. Deployment must force client
egress through the assigned proxy and must isolate Baffle's internal loopback
listeners as described in the [security guide](security-deployment.md).

## Request admission boundary

The policy accepts HTTPS destinations through CONNECT. It rejects ordinary
forward-proxy requests outside intercepted TLS, including absolute-form
`http://` and `https://` requests. HTTP/1.1 and HTTP/2 inside successfully
intercepted TLS remain available for path checks and credential injection. A
rule that requires those checks remains fail-closed. Check each request on
reused h1/h2 connections against the CONNECT authority, TLS identity, and path
policy before forwarding or injecting a credential. Reject plaintext based on
request form or scheme on every port; a configured TLS service on port 80 is
valid.

An explicit tunnel rule remains opaque. Baffle authorizes its configured host
and port, but cannot prove that tunneled bytes are TLS, inspect paths, or
verify the upstream certificate. The client must verify TLS identity. The
runtime has no DNS-answer restrictions; deployment DNS and network egress
controls must block sensitive addresses when the threat model requires it.

## Session lifecycle

The default session is ephemeral. The control connection that created it stays
open as a lease. Closing the connection, including when the client exits,
removes the session and its data socket. `baffle-client::Session` owns this
connection and releases it when closed or dropped.

With `persistent = true`, the daemon releases the create connection after its
response. The session continues until a `stop` request or daemon shutdown.
`list` returns metadata for sessions owned by the authenticated UID. A `stop`
request can stop only a session owned by that UID.

Each session has its own runtime task and immutable policy. A runtime failure
stops and removes that session. It does not stop other sessions. Shutdown first
stops new control requests, asks each runtime to drain for the configured
grace period, then aborts work that did not stop in time and removes socket
paths.

The session registry enforces `max_sessions`. The control server limits
parallel creation with `max_provisioning_requests`. The bridge enforces
`max_connections_per_session`, `connection_timeout_ms`, and `io_timeout_ms`.

## Backend selection and adapters

Cargo requires exactly one backend feature. `backend-hudsucker` is the default;
`backend-rama` is experimental. `src/proxy_runtime.rs` selects the adapter and
exposes the same runtime interface to the daemon. `src/policy.rs` owns the
shared host, port, SNI, authority, and path rules. `src/ca.rs` keeps the daemon
CA as the source of truth and provides backend-specific signing material.

The Rama adapter accepts CONNECT only. It authorizes the CONNECT authority
before dialing, keeps explicit tunnel rules opaque, and fails closed when an
interception-required TLS handshake or authority check fails. It preserves the
approved CONNECT hostname for upstream TLS verification and disables TLS key
logging. It uses Rama's BoringSSL TLS backend. Both adapter files currently
contain their own Unix bridge, connection limits, socket guard, and lifecycle
supervisor.

## Hudsucker integration and local patch

Baffle pins Hudsucker to version `0.25.0` in `Cargo.toml` and patches crates.io
to the reviewed source in `vendor/hudsucker`. Baffle uses Hudsucker for HTTP
proxying, CONNECT handling, TLS interception, certificate generation, and
protocol upgrades.

The local patch adds policy hooks for CONNECT and TLS decisions, validates
CONNECT/TLS host identity, makes unsupported requested interception fail
closed, and binds each intercepted HTTP authority to its CONNECT authority.
The address-filtering TCP connector and resolver hooks were removed in
baffle/25. Hudsucker's default outbound connectors resolve and dial the
authorized hostname. The current Rustls client continues to validate upstream
certificates and hostnames.

The security rationale, exact upstream gaps, and patch inventory are recorded in
[`vendor/hudsucker/PATCHES.md`](../vendor/hudsucker/PATCHES.md). Keep the
vendor diff limited to those checks. Review the diff and rerun CONNECT, SNI,
HTTP/2, and WebSocket tests before changing Hudsucker. Keep the
fail-closed-interception and authority-binding changes until an upstream
release provides those guarantees and Baffle tests verify them. See the patch
inventory for the per-change replacement criteria.

## Failures and logging

Invalid client requests receive a safe stable protocol error. Internal setup
failures receive `internal_error`; the daemon logs an error class rather than
the policy body or credentials. Proxy denials return a denial response and
increment session/process counters. Upstream and bridge failures are logged as
structured events and are isolated to their session when possible.

Logs include lifecycle IDs, host/port decision metadata, counters, and error
classes. Baffle does not log request paths, queries, headers, credentials, or
bodies. Use the default `baffle_proxy=info` filter in production. Review any
custom dependency logging filters before enabling them.
