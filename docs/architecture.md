# Architecture

**Current runtime architecture.** This page describes protections that remain
in the implementation until baffle/24 and baffle/25 land. In the target model,
ordinary plaintext HTTP is rejected and DNS/IP filtering moves to deployment
egress controls. The fail-closed interception behavior described below stays
in the target model.

Baffle runs one Tokio daemon process. The daemon owns the control listener,
session registry, CA signing key, secret store, shared CA handle, and runtime.
Each proxy session has an independent policy, Hudsucker instance, outbound
connector, data socket, and counters.

## Components

| Component | Source | Responsibility |
| --- | --- | --- |
| CLI and daemon entry point | `src/main.rs`, `src/cli.rs`, `src/daemon.rs` | Parse `daemon` and `ca export` commands, load configuration, start the control server, and handle Ctrl-C. |
| Configuration | `src/config.rs` | Parse strict daemon and session TOML, normalize exact host rules, and reject invalid policy before provisioning. |
| Control server and session manager | `src/control.rs` | Authenticate Unix peers, frame requests and responses, create/list/stop sessions, track leases, enforce limits, and remove sockets. |
| Proxy runtime and bridge | `src/proxy_runtime.rs` | Start one Hudsucker proxy, bind a private loopback TCP listener and Unix data socket, bridge streams with limits and timeouts, and supervise failures. |
| Policy handler | `src/policy.rs`, `src/proxy_runtime.rs` | Check destination authority, port, mode, canonical path, TLS identity, and header-injection conditions. |
| Egress connector | `src/egress.rs` | Resolve permitted names, filter non-public addresses, and connect only to validated destination IPs. |
| CA manager | `src/ca.rs` | Validate CA files, share signing state with proxy instances, and export only the public certificate. |
| Secret store | `src/secrets.rs` | Authorize symbolic secret names, validate private files, and keep values inside the owning session. |
| Rust client | `crates/baffle-client` | Provide typed asynchronous `create`, `list`, and `stop` operations for consumers. |

## Control flow

The control flow is:

1. The trusted client connects to the private Unix control socket.
2. Baffle checks the peer UID with Linux `SO_PEERCRED` before reading a frame.
3. Baffle reads one bounded TOML request and validates its protocol version,
   schema, and policy.
4. For `create`, Baffle checks secret entitlements and files before it starts a
   proxy. It reserves capacity, creates a session ID, pre-binds a loopback TCP
   listener, binds a Unix data socket, and starts the Hudsucker proxy plus
   stream bridge.
5. Baffle returns the session ID, data socket path, and persistence setting in
   one JSON response.

The request and response formats are specified in the
[control protocol](control-protocol.md).

## Data flow and policy boundaries

The client's application connects to the session's Unix data socket and sends
standard HTTP proxy traffic. The bridge streams bytes to the session's
pre-bound `127.0.0.1` TCP listener. Hudsucker handles HTTP, CONNECT, TLS
interception, and upstream proxy behavior. The bridge does not buffer complete
requests or responses.

Before forwarding, the policy handler checks the exact host and destination
port. It checks paths for plaintext HTTP and for each request carried inside a
successfully intercepted TLS connection. It checks the CONNECT authority
against TLS SNI and each decrypted request authority. Only after an intercepted
request passes all checks can the handler add its configured headers.

For HTTPS, `tunnel` rules permit an opaque CONNECT tunnel only when no path
restriction or credential injection requires inspection. `intercept` rules
require supported TLS negotiation and a matching SNI. Unsupported CONNECT
payloads, missing or mismatched SNI, and TLS interception failures close the
connection; they do not select an opaque fallback tunnel.

The outbound connector resolves the requested host and filters the complete
answer set before dialing. Public addresses are eligible. A non-public answer
is eligible only if the exact host rule lists that IP address. Hudsucker uses
the validated address connector for HTTP, CONNECT tunnels, and its supported
upgrade paths. Redirects return to the client; a new request is evaluated
against policy again.

These rules protect traffic that reaches Baffle. They do not stop a sandboxed
process from making a direct network connection. Deployment must force client
egress through the assigned proxy and must isolate Baffle's internal loopback
listeners as described in the [security guide](security-deployment.md).

## Approved target boundary

The target policy accepts HTTPS destinations through CONNECT. It rejects
ordinary forward-proxy requests outside intercepted TLS, including plaintext
`http://` destinations. HTTP/1.1 and HTTP/2 inside successfully intercepted TLS
remain available for path checks and credential injection. A rule that
requires those checks remains fail-closed.

An explicit tunnel rule remains opaque. Baffle authorizes its configured host
and port, but cannot prove that tunneled bytes are TLS, inspect paths, or
verify the upstream certificate. The client must verify TLS identity. The
target policy also removes Baffle's DNS-answer restrictions; deployment DNS
and network egress controls must block sensitive addresses where the threat
model requires it. Until baffle/24 and baffle/25 are implemented, the current
runtime behavior described above still applies.

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

## Hudsucker integration and local patch

Baffle pins Hudsucker to version `0.25.0` in `Cargo.toml` and patches crates.io
to the reviewed source in `vendor/hudsucker`. Baffle uses Hudsucker for HTTP
proxying, CONNECT handling, TLS interception, certificate generation, and
protocol upgrades.

The local patch adds policy hooks for CONNECT and TLS decisions, validates
CONNECT/TLS host identity, makes unsupported requested interception fail
closed, and adds outbound connector and resolver hooks. The connector hooks
cover HTTP, CONNECT tunnels, and WebSocket connections. The resolver hook
supplies the addresses that the outbound HTTP client dials. These hooks let
Baffle enforce the same session egress policy on each Hudsucker connection
path.

The security rationale, patch inventory, and upstreaming plan are recorded in
[`vendor/hudsucker/PATCHES.md`](../vendor/hudsucker/PATCHES.md). Keep the
vendor diff limited to those checks and hooks. Review the diff and rerun
egress, CONNECT, SNI, HTTP/2, and WebSocket tests before changing Hudsucker.
Upstream the checked connector, resolver, and fail-closed interception hooks
through Hudsucker's public builder API. Remove the local copy only after an
upstream release provides the same guarantees and Baffle tests verify them.

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
