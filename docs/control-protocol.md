# Control protocol

The control protocol uses one request and one response on each Unix connection.
The client sends one UTF-8 TOML request. Baffle sends one UTF-8 JSON response.
Both payloads use a four-byte unsigned big-endian length prefix.

## Frames

The request payload must be between 1 byte and 256 KiB. Baffle rejects a larger
length before it reads the payload. A partial header or payload is rejected. A
request read that exceeds `daemon.control_read_timeout_ms` is rejected. The
default read timeout is 5,000 milliseconds.

Baffle closes the connection after its response, except for an ephemeral
`create` request. That connection remains open as the session lease. Any client
data after the request violates the one-request rule and closes the lease.
Closing the lease connection removes the ephemeral session.

## Authentication

Baffle checks the Linux `SO_PEERCRED` UID before it reads a request. The UID
must match `daemon.trusted_operator_uid`. The daemon process, trusted UID, and
owner of the private control socket directory must be the same account. Baffle
creates missing control directories with mode `0700`, requires existing
directories to have mode `0700` or stricter, and sets the socket mode to
`0600`.

## Requests

Every request must include `version = 1`. Baffle rejects a missing version and
any version other than 1. Unknown fields and malformed TOML are invalid
requests.

Create a session:

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

Stop a session:

```toml
version = 1
operation = "stop"
session_id = "session-id"
```

List sessions:

```toml
version = 1
operation = "list"
```

`create` requests are subject to `daemon.max_provisioning_requests`, which
defaults to 8 concurrent requests. The session registry also enforces
`daemon.max_sessions`.

## Responses

Every response has `version` and `ok` fields. A successful response contains a
`result` object:

```json
{"version":1,"ok":true,"result":{"id":"...","socket":"...sock","persistent":false}}
```

`list` returns the session metadata array in `result.sessions`. `stop` returns
`result.stopped = true` after it removes the named session.

An error response contains a stable code and a safe message. The message does
not include request data:

```json
{"version":1,"ok":false,"error":{"code":"invalid_request","message":"request is invalid"}}
```

Stable error codes are:

| Code | Meaning |
| --- | --- |
| `unauthorized` | The peer UID does not match the configured operator. |
| `invalid_request` | The frame is empty, not UTF-8, malformed TOML, or has invalid fields. |
| `unsupported_version` | The requested protocol version is not supported. |
| `frame_too_large` | The request frame exceeds 256 KiB. |
| `truncated_frame` | The header or payload ended before the declared length. |
| `read_timeout` | The client did not complete the request before the configured timeout. |
| `busy` | The concurrent provisioning limit is full. |
| `session_limit` | The configured maximum number of sessions is full. |
| `session_not_found` | `stop` named an unknown session. |
| `internal_error` | The daemon could not complete the request. |
