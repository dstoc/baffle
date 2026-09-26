# Architecture

**Current runtime architecture.** Rama is Baffle's only supported proxy
runtime. Baffle accepts HTTPS destinations through CONNECT and rejects ordinary
forward-proxy requests. It does not filter destination IP addresses; deployment
DNS and egress controls own address restrictions. Required interception remains
fail-closed, with CONNECT, TLS, and HTTP identities bound to the authorized
destination.

Baffle runs one Tokio daemon process. The daemon owns the control listener,
session registry, CA signing key, secret store, shared CA handle, and runtime.
Each proxy session has an independent policy, Rama runtime,
credential state, data socket, and counters.

## Components

| Component | Source | Responsibility |
| --- | --- | --- |
| CLI and daemon entry point | `src/main.rs`, `src/cli.rs`, `src/daemon.rs` | Parse `daemon` and `ca export` commands, load configuration, start the control server, and handle Ctrl-C. |
| Configuration | `src/config.rs`, `src/config/{daemon,policy,protocol,session}.rs` | Parse strict daemon and session TOML, normalize exact host rules, and reject invalid policy before provisioning. |
| Control server and session manager | `src/control.rs` | Authenticate Unix peers, frame requests and responses, create/list/stop sessions, track leases, enforce limits, and remove sockets. |
| Proxy runtime | `src/proxy_runtime.rs`, `src/proxy_runtime/rama.rs` | Expose the opaque session lifecycle to the daemon. Baffle binds the Unix data socket and Rama handles accepted Unix streams with connection limits, timeouts, and supervised tasks. |
| Policy and Rama adapter | `src/policy.rs`, `src/proxy_runtime/rama.rs` | Map Rama requests to shared request facts and apply exact destination, port, mode, canonical path, TLS identity, and header-injection rules. |
| CA manager | `src/ca.rs` | Validate CA files, retain daemon-owned signing material, provide cloned handles to the runtime, and export only the public certificate. |
| Secret store | `src/secrets.rs` | Authorize symbolic secret names, validate private files, and keep values inside the owning session. |
| Rust client | `crates/baffle-client` | Provide typed asynchronous `create`, `list`, and `stop` operations for consumers. |

## Control flow

The control flow is:

1. The trusted orchestrator connects to the private Unix control socket.
2. Baffle checks the peer UID with Linux `SO_PEERCRED` before reading a frame.
3. Baffle reads one bounded TOML request and validates its protocol version,
   schema, and policy.
4. For `create`, Baffle checks secret entitlements and files before it starts a
   proxy. It reserves capacity, creates a session ID, and starts the proxy
   runtime. The runtime binds its Unix data socket and accepts connections
   directly on it.
5. Baffle returns the session ID, data socket path, and persistence setting in
   one JSON response.

The request and response formats are specified in the
[control protocol](control-protocol.md).

## Data flow and policy boundaries

The client's application connects to the session's Unix data socket and sends
standard HTTP proxy traffic. The Rama runtime handles CONNECT, interception,
and upstream traffic directly from that Unix stream. It inspects ClientHello
and serves intercepted HTTP through Rama middleware. TCP is used only for
connections from Baffle to authorized HTTPS origins.

Before forwarding, the policy handler checks the exact host and destination
port. Only CONNECT can establish an outbound destination. It checks paths for
each request carried inside a successfully intercepted TLS connection. It
checks the CONNECT authority against TLS SNI and each decrypted request
authority. Only after an intercepted request passes all checks can the handler
add its configured headers. The Rama adapter maps its request and TLS context
to shared request facts before applying the session policy.

For HTTPS, `tunnel` rules permit an opaque CONNECT tunnel only when no path
restriction or credential injection requires inspection. `intercept` rules
require supported TLS negotiation and a matching SNI. The current code closes
unsupported CONNECT payloads, missing or mismatched SNI, malformed, incomplete,
or stalled ClientHello data, and TLS interception failures; it does not select
an opaque fallback tunnel. A client must not force an opaque tunnel for a rule
that needs inspection. Baffle treats proxy clients as untrusted and assumes
allowlisted sites behave legitimately.

The policy authorizes the exact hostname and port before the runtime dials the
destination. Baffle does not classify DNS answers, filter addresses,
or pin a resolved address. An allowed hostname can resolve to a private,
loopback, link-local, metadata, or other sensitive address. A valid certificate
verifies the hostname's TLS identity; it does not make the address safe.
Deployment DNS policy and default-deny network egress rules must restrict
reachable addresses when the threat model requires it. Redirects return to the
client; a new request is evaluated against policy again.

These rules protect traffic that reaches Baffle. They do not stop a sandboxed
process from making a direct network connection. Deployment must force client
egress through the assigned proxy as described in the
[security guide](security-deployment.md).

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
parallel creation with `max_provisioning_requests`. Each Unix listener enforces
`max_connections_per_session`; `io_timeout_ms` bounds stalled client and
tunnel operations. The legacy `connection_timeout_ms` setting is accepted for
configuration compatibility and has no runtime effect.

## Proxy runtime boundary

`src/proxy_runtime.rs` is the daemon-facing runtime boundary. Its opaque
`ProxyRuntime` handle covers session startup, readiness through successful
return after binding, the Unix socket path, runtime exit events, cancellation,
and bounded shutdown. The daemon and control protocol use Baffle-owned session,
policy, CA, secret, and metrics types; they do not use Rama networking or
request types.

The private `src/proxy_runtime/rama.rs` module owns Rama-specific TLS and HTTP
processing, direct Unix-stream ingress, and inode-safe socket cleanup. It
accepts CONNECT only, authorizes the CONNECT authority before dialing,
preserves explicit tunnel-only behavior, and fails closed when required TLS
interception or authority checks fail. It verifies upstream TLS against the
approved CONNECT hostname, disables TLS key logging, and adapts Unix streams to
Rama's TLS relay interface.

Rama is the only runtime implementation. This boundary keeps Rama networking
types out of daemon and control-protocol code. No backend selector is exposed
in daemon configuration or the control protocol. See the [runtime migration
note](runtime-migration.md) for the completed removal of Hudsucker.

## Failures and logging

Invalid client requests receive a safe stable protocol error. Internal setup
failures receive `internal_error`; the daemon logs an error class rather than
the policy body or credentials. Proxy denials return a denial response and
increment session/process counters. Upstream failures are logged as structured
events and are isolated to their session when possible.

Logs include lifecycle IDs, host/port decision metadata, counters, and error
classes. Baffle does not log request paths, queries, headers, credentials, or
bodies. Use the default `baffle_proxy=info` filter in production. Review any
custom dependency logging filters before enabling them.
