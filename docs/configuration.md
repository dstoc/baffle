# Configuration reference

This page describes the current configuration. Destinations must use HTTPS
through CONNECT. Baffle does not filter destination IP addresses; use
deployment DNS and network egress controls when address restrictions are
required. Existing session policies that contain the removed
`private_addresses` field fail validation.

Baffle reads one daemon TOML file at startup. A client sends a separate session
TOML document in each `create` request. Both schemas reject unknown fields.
TOML values are parsed as written; Baffle does not expand environment
variables. Use absolute file paths for service deployments.

The checked-in examples are [`examples/daemon.toml`](../examples/daemon.toml),
[`examples/session.toml`](../examples/session.toml),
[`examples/session-credentials.toml`](../examples/session-credentials.toml),
and [`examples/session-port-80-tls.toml`](../examples/session-port-80-tls.toml).
CI parses these files with Baffle's configuration types.

## Daemon configuration

The daemon document must contain `[daemon]`, `[ca]`, and `[secrets]` tables.
The `control_socket`, `socket_dir`, `trusted_operator_uid`, CA paths, and
secret directory are required.

```toml
[daemon]
control_socket = "/run/baffle/control.sock"
socket_dir = "/run/baffle/proxies"
trusted_operator_uid = 1000
max_sessions = 64
max_connections_per_session = 128
shutdown_grace_seconds = 5
control_read_timeout_ms = 5000
max_provisioning_requests = 8
connection_timeout_ms = 5000
io_timeout_ms = 30000

[ca]
certificate = "/var/lib/baffle/ca.pem"
private_key = "/var/lib/baffle/ca-key.pem"

[secrets]
directory = "/var/lib/baffle/secrets"
allowed = ["example-api"]
```

| Field | Type | Default | Meaning and validation |
| --- | --- | --- | --- |
| `daemon.control_socket` | path | required | Private Unix control socket. Its parent directory must be owned by `trusted_operator_uid` and have mode `0700` or stricter. |
| `daemon.socket_dir` | path | required | Directory for per-session Unix sockets. It must be owned by `trusted_operator_uid` and have mode `0700` or stricter. |
| `daemon.trusted_operator_uid` | unsigned 32-bit integer | required | Linux UID accepted on the control socket and used as the owner for private runtime and secret files. Run Baffle as this UID. |
| `daemon.max_sessions` | positive integer | `64` | Maximum active sessions. Zero is invalid. |
| `daemon.max_connections_per_session` | positive integer | `128` | Maximum concurrent client connections accepted by one session bridge. Excess connections are closed. Zero is invalid. |
| `daemon.shutdown_grace_seconds` | integer | `5` | Grace period for each session during shutdown. Zero requests immediate forced shutdown. |
| `daemon.control_read_timeout_ms` | positive integer | `5000` | Timeout for control request frame reads. Zero is invalid. |
| `daemon.max_provisioning_requests` | positive integer | `8` | Maximum concurrent session creation requests. Additional requests receive `busy`. Zero is invalid. |
| `daemon.connection_timeout_ms` | positive integer | `5000` | Maximum time to connect from a data socket bridge to its internal Hudsucker listener. Zero is invalid. |
| `daemon.io_timeout_ms` | positive integer | `30000` | Maximum idle time for bridge reads, writes, and half-closes. A bridge closes when either direction makes no progress for this period. Zero is invalid. |
| `ca.certificate` | path | required | One current PEM CA certificate with `CA:TRUE` and `keyCertSign`. |
| `ca.private_key` | path | required | Matching PEM private key. It must be a regular, non-symlink file. Only the owner may access it, and the owner must have read permission. Use mode `0400` or `0600`. |
| `secrets.directory` | path | required | Private directory containing secret files. It must be a real directory owned by the trusted UID, with mode `0700` or stricter. |
| `secrets.allowed` | array of strings | `[]` | Secret identifiers that the trusted operator may reference from session rules. Identifiers are unique and have the format described below. |

The CA certificate and private key must match. The daemon checks certificate
validity and signing use at startup. The secret store is checked when a
session references a secret.

The daemon creates missing control and socket directories with mode `0700`.
Existing target directories must have the required owner and permissions.
It creates the control socket and each session socket with mode `0600`.
See the [security guide](security-deployment.md) for ownership and sandbox
access requirements.

## Session configuration

Every create request uses this shape:

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

`version` must be `1`. `session` is required. `persistent` defaults to
`false`. At least one `[[rules]]` entry is required. A create request has one
rule per exact host; duplicate normalized hosts are invalid.

| Rule field | Type | Default | Meaning and validation |
| --- | --- | --- | --- |
| `host` | string | required | Exact ASCII DNS hostname. Baffle lowercases it and removes one final dot. Wildcards and IP literals are rejected. |
| `mode` | string | required | `tunnel` or `intercept`. A tunnel passes authorized CONNECT traffic without TLS decryption. Intercept mode requires TLS inspection for CONNECT. |
| `ports` | array of integers | `[443]` | Non-empty, unique destination ports from 1 through 65535. Non-default ports must be listed explicitly. Port 80 is allowed when configured and may carry TLS. |
| `paths` | array of strings | `[]` | Exact URL paths or recursive path patterns. Baffle checks paths on each request inside intercepted TLS. A path-restricted rule cannot tunnel CONNECT. |
| `inject` | array of tables | `[]` | Daemon-managed HTTP header injections. Only intercept rules can inject credentials. |

`tunnel` rules cannot inject headers. A configured TLS service on port 80 can
use either mode when the rule's other checks permit it. Port alone does not
identify the protocol. Paths and credential injection require successful
interception.

## Host, port, and path rules

Baffle accepts destination requests through CONNECT only. It rejects outer
forward-proxy requests with absolute-form `http://` or `https://` targets.
Inside intercepted TLS, each HTTP/1.1 or HTTP/2 request must use the HTTPS
scheme and match the CONNECT authority and TLS identity. Plaintext HTTP is
rejected on every port based on request form and scheme. Port 80 is not
reserved; a TLS service on that port can use CONNECT when the rule lists port
80. An opaque tunnel does not let Baffle prove that its bytes are TLS.

Baffle does not classify DNS answers, filter destination addresses, or pin an
address. Use deployment DNS policy and default-deny network egress rules when
the deployment requires address containment.

This HTTPS rule uses the default destination port:

```toml
version = 1
operation = "create"

[session]
persistent = false

[[rules]]
host = "api.example.com"
mode = "intercept"
ports = [443]
paths = ["/v1/**"]
```

An explicitly configured TLS service on port 80 can use interception, path
checks, and credential injection:

```toml
version = 1
operation = "create"

[session]
persistent = false

[[rules]]
host = "api.example.com"
mode = "intercept"
ports = [80]
paths = ["/v1/**"]

  [[rules.inject]]
  header = "Authorization"
  secret = "example-api"
  format = "bearer"
```

This rule does not authorize plaintext HTTP. The client must send HTTPS through
CONNECT, including an explicit `api.example.com:80` CONNECT authority.

The session schema rejects the removed `private_addresses` field. Apply any
required DNS or address restrictions through deployment controls.

Host matching is exact after lowercasing and removal of one trailing dot.
`example.com` does not match `api.example.com`. Wildcards are not supported.
Each request must use a permitted destination port. Hudsucker's default
connectors resolve and dial the authorized hostname. Baffle does not limit the
DNS answer set or the resulting destination IP address.

Paths are case-sensitive and match the URL path without its query string.
Queries are forwarded unchanged. A path entry must start with `/` and cannot
contain a query, fragment, backslash, or unsupported `*` character.

- `/repos/acme/tool` matches only that path.
- `/repos/acme/tool/**` matches `/repos/acme/tool/` and its descendants. It
  does not match `/repos/acme/tool` itself.
- Add both patterns when both the root and descendants are allowed.

Baffle canonicalizes each configured path and request path before matching.
It decodes percent-encoded unreserved characters, uses uppercase hex for
remaining valid escapes, and rejects malformed escapes, encoded slash or
backslash, encoded percent signs, repeated slashes, dot segments, and invalid
path characters. It forwards the same canonical path that it authorized.
Overlapping patterns within a rule are invalid.

An HTTPS rule with paths must use `intercept`. Baffle rejects a CONNECT request
for a path-restricted tunnel because the CONNECT request does not identify the
later URL path. On an intercepted connection, Baffle checks the CONNECT
authority, TLS SNI, HTTP authority, port, and each request path. It repeats
the HTTP authority and path checks for each request on reused HTTP/1.1 and
HTTP/2 connections. A malformed or fragmented ClientHello, unsupported
post-CONNECT data, or failed TLS interception closes the connection when
inspection is required. A client cannot trigger an opaque fallback by
splitting ClientHello data.

## Credential references

A rule can add daemon-managed headers after an intercepted HTTPS request
passes its authority, port, and path checks:

```toml
[[rules]]
host = "api.example.com"
mode = "intercept"
ports = [443]
paths = ["/v1/**"]

  [[rules.inject]]
  header = "Authorization"
  secret = "example-api"
  format = "bearer"
```

Each `[[rules.inject]]` table has these fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `header` | string | Valid HTTP header name. Baffle rejects hop-by-hop and routing-critical headers such as `Host`, `Connection`, `Content-Length`, `Proxy-Authorization`, and `Upgrade`. |
| `secret` | string | Symbolic name from `secrets.allowed`. This is not the secret value or a path. |
| `format` | string | `raw`, `bearer`, or `basic_password`. |
| `username` | string | Required only for `basic_password`. Must be printable ASCII without a colon. |

The secret name must be 1 to 64 ASCII letters, digits, dots, underscores, or
hyphens. It must start with a letter or digit, end with a letter or digit, and
must not contain `..`. In the secret directory, create a file with that exact
name. The file must be regular, owned by the trusted UID, readable by that
UID, and inaccessible to group and other users. It cannot have execute or
special permission bits. Values are limited to 64 KiB, must be UTF-8, cannot
be empty or contain control characters, and may end with one line ending.

`raw` injects the value as-is. `bearer` creates `Bearer <value>`.
`basic_password` creates HTTP Basic credentials from `username` and the secret
as the password. Baffle removes a client-supplied header with the same name,
then adds the daemon-managed value. It never injects into plaintext HTTP,
CONNECT, tunnelled HTTPS, or an unsupported protocol upgrade.

The daemon checks every secret entitlement and file before it creates a
session. Missing, inaccessible, and unentitled secret references return the
same safe protocol error.

## Validation examples

This rule authorizes one exact hostname and port. It does not restrict the
address returned by DNS. Apply any required restriction through deployment
DNS and network egress policy:

```toml
version = 1
operation = "create"

[session]

[[rules]]
host = "internal.example"
mode = "tunnel"
ports = [8443]
```

For migration, remove `private_addresses` from every session rule before
upgrading. The strict schema rejects that field. Move intended internal-service
restrictions to deployment DNS and network egress policy. Use default-deny
egress rules when the threat model requires address containment.

For all protocol operations and response schemas, see the
[control protocol reference](control-protocol.md).
