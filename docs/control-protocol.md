# Control protocol

The control protocol is a local Unix-domain socket protocol. Each connection
carries one request and one response. Requests are UTF-8 TOML. Responses are
UTF-8 JSON. Both payloads use the same four-byte unsigned big-endian length
prefix.

Protocol version 1 is the only supported version. A client selects its
version by setting `version = 1` in each request. Baffle does not perform a
separate capability handshake or negotiate a version range. It returns
`unsupported_version` when the request has a valid integer version other than
1. The integer version field is a 16-bit unsigned value. A missing, malformed,
or out-of-range field is `invalid_request`.

## Frame format

Each frame has this layout:

```text
4-byte unsigned big-endian payload length | payload bytes
```

The request payload must contain 1 to 262,144 bytes. Baffle rejects a larger
length before reading the payload. A zero-length frame, invalid UTF-8, partial
header, or partial payload is rejected. Request frame reads use
`daemon.control_read_timeout_ms`, which defaults to 5,000 milliseconds.

A response is one length-prefixed JSON object. The client reads its four-byte
length, then that many bytes. The protocol does not define a maximum response
size; a client should still impose an implementation limit.

## Authentication and authorization

Baffle checks the Linux `SO_PEERCRED` UID before it reads a request. The UID
must equal `daemon.trusted_operator_uid`. Run the daemon as that UID. The
control socket's parent and the session socket directory must be owned by that
UID with mode `0700` or stricter. Baffle sets the control socket and each
session data socket to mode `0600`.

The UID is the protocol's client identity. Baffle does not authenticate a
process name or executable. The trusted UID is authorized to create sessions
using the daemon's configured secret allowlist, list its own sessions, and
stop its own sessions.

Secret access uses a daemon-owned allowlist:

```toml
[secrets]
directory = "/var/lib/baffle/secrets"
allowed = ["github-api", "github-git"]
```

The allowlist defaults to empty. A client cannot grant itself access or send a
secret value or filesystem path. Before a create request provisions a
session, Baffle checks each name against the allowlist and validates its
private file. Secret files must be regular, owned by the trusted UID,
readable by that UID, and inaccessible to group and other users. Missing,
inaccessible, and unentitled secrets produce the same `secret_unavailable`
error. Resolved values do not appear in responses or diagnostics.

## Requests

Every request includes a version and operation. Unknown fields are invalid.
The request tables and policy fields are defined in the
[configuration reference](configuration.md).

Create an ephemeral session:

```toml
version = 1
operation = "create"

[session]
persistent = false

[[rules]]
host = "example.com"
mode = "tunnel"
ports = [443]
```

The checked-in [`examples/session.toml`](../examples/session.toml) is parsed
by a CI test. A create request requires a `session` table and at least one
rule. `persistent` defaults to false. Each rule defaults to HTTPS port 443.

Stop an owned session:

```toml
version = 1
operation = "stop"
session_id = "session_example_01"
```

The session ID is an opaque non-empty string of at most 128 ASCII letters,
digits, hyphens, and underscores.

List sessions owned by the authenticated UID:

```toml
version = 1
operation = "list"
```

The examples in [`examples/protocol`](../examples/protocol/) include checked
list and stop request files. `create` requests are limited by
`daemon.max_provisioning_requests` (default 8 concurrent requests) and
`daemon.max_sessions` (default 64 active sessions).

## Responses

Every response contains the protocol `version` and a boolean `ok` field. A
successful response has a `result` object.

Create response:

```json
{"version":1,"ok":true,"result":{"id":"session_example_01","socket":"/run/baffle/proxies/session_example_01.sock","persistent":false}}
```

List response:

```json
{"version":1,"ok":true,"result":{"sessions":[{"id":"session_example_01","socket":"/run/baffle/proxies/session_example_01.sock","persistent":false,"state":"running"}]}}
```

Each list entry contains `id`, `socket`, `persistent`, and `state`. It does
not expose policy contents or credentials. `stop` returns
`{"stopped":true}` in `result` after it removes the named session.

An error response has `ok = false` and an `error` object with a stable code
and safe message:

```json
{"version":1,"ok":false,"error":{"code":"invalid_request","message":"request is invalid"}}
```

The message does not include request data. Clients should branch on the code,
not the message.

| Code | Meaning |
| --- | --- |
| `unauthorized` | The peer UID does not match the configured operator, or peer credentials could not be read. |
| `invalid_request` | The frame is empty, not UTF-8, malformed TOML, has a missing or malformed field, or has an unsupported field. |
| `unsupported_version` | The request has a 16-bit unsigned protocol version other than 1. |
| `frame_too_large` | The request payload exceeds 262,144 bytes. |
| `truncated_frame` | The frame header or payload ended before the declared length. |
| `read_timeout` | The client did not complete a frame read before the configured timeout. |
| `busy` | The concurrent session provisioning limit is full. |
| `session_limit` | The configured active session limit is full. |
| `session_not_found` | The session does not exist or is not owned by the authenticated UID. |
| `secret_unavailable` | A requested secret is missing, inaccessible, or not entitled to the authenticated UID. |
| `internal_error` | The daemon could not complete the request. |
| `shutting_down` | The daemon is shutting down and does not accept new sessions. |

## Leases and session lifecycle

After it returns the response for an ephemeral `create`, Baffle keeps that
control connection open as the session lease. The client must keep the
connection open while it uses the data socket. Closing the connection removes
the session and its socket. Any extra client bytes after the one request
violate the protocol and close the lease.

For a persistent create, Baffle closes the control connection after the
response. The session remains active until an owned `stop` request or daemon
shutdown. A `list` or `stop` request always uses a separate connection.

The Rust `baffle-client` crate implements framing and keeps ephemeral leases
inside its `Session` handle. See the [client guide](client.md) for code
examples. The [Cladding guide](cladding-integration.md) shows a consumer
holding the lease while it runs a workload.

## Direct client sequence

To create a session without the Rust crate:

1. Connect to the control Unix socket as the trusted UID.
2. Write a create request as a length-prefixed UTF-8 TOML frame.
3. Read one length-prefixed UTF-8 JSON response.
4. Connect the workload to the returned `result.socket` path.
5. Keep the create connection open while the workload runs.
6. Close the create connection to release an ephemeral session.

For a persistent session, close the create connection after step 3, then send
a separate `stop` request with the returned ID when the session is no longer
needed. See [configuration](configuration.md) for host, port, path, and
credential rules and [security and deployment](security-deployment.md) for
socket permissions and namespace isolation.

During daemon shutdown, Baffle stops accepting control requests, drains
sessions for `shutdown_grace_seconds`, aborts tasks that exceed the grace
period, and removes their socket paths.
