# Configuration reference

**Current runtime reference.** The strict session schema no longer accepts
`private_addresses`. Existing policies that contain that field fail
validation; remove it and move any intended address restrictions to deployment
DNS and network egress policy before upgrading. The HTTPS-only request change
is tracked separately in baffle/24. Until baffle/24 lands, port-80 behavior is
as described below.

Baffle reads one daemon TOML file at startup. A client sends a separate session
TOML document in each `create` request. Both schemas reject unknown fields.
TOML values are parsed as written; Baffle does not expand environment
variables. Use absolute file paths for service deployments.

The checked-in examples are [`examples/daemon.toml`](../examples/daemon.toml),
[`examples/session.toml`](../examples/session.toml), and
[`examples/session-credentials.toml`](../examples/session-credentials.toml).
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
| `mode` | string | required | `tunnel` or `intercept`. A tunnel passes authorized HTTPS CONNECT traffic without TLS decryption. Intercept mode requires TLS inspection for HTTPS CONNECT. |
| `ports` | array of integers | `[443]` | Non-empty, unique destination ports from 1 through 65535. The current runtime does not allow port 80 with `intercept`; the target policy permits TLS on any configured port, including port 80, and does not reserve a port based on its number. |
| `paths` | array of strings | `[]` | Exact URL paths or recursive path patterns. When present, Baffle checks paths on plaintext HTTP and on intercepted HTTPS requests. A path-restricted rule cannot tunnel HTTPS CONNECT. |
| `inject` | array of tables | `[]` | Daemon-managed HTTP header injections. Only intercept rules can inject credentials. |

`tunnel` rules cannot inject headers. In the current runtime, a rule that
injects headers or uses `intercept` cannot include port 80. A tunnel rule may
use port 80 for plaintext HTTP, with host, port, and configured path checks.
baffle/24 will reject plaintext by request form or scheme on every port. A
configured TLS service on port 80 will remain valid when the rule's other
checks permit it. Port alone does not identify the protocol.

## Host, port, and path rules

In the current runtime, a rule may explicitly allow plaintext HTTP on port 80
when it uses `mode = "tunnel"`. The current runtime also forbids port 80 on
`intercept` and injection rules. baffle/24 will reject plaintext HTTP based on
the request form or scheme, regardless of port. A configured TLS service on
port 80 will remain valid when the rule's other checks permit it.

Baffle authorizes the exact hostname and port before outbound dialing. It does
not classify DNS answers, filter destination addresses, or pin an address.
An allowlisted name may resolve to private, loopback, link-local, metadata, or
another sensitive address. A valid certificate for that name does not make
the address safe. Use deployment DNS policy and default-deny network egress
rules when the deployment requires address containment.

This session shape has no address exceptions:

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

This is the current session schema. A policy from an earlier Baffle version
that contains `private_addresses` fails strict validation. Remove the field
before upgrading and apply any required DNS or address restrictions through
deployment controls.

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
for a path-restricted rule because the CONNECT request does not identify the
later URL path. On an intercepted connection, Baffle checks the CONNECT
authority, TLS SNI, HTTP authority, port, and each request path. It repeats
the HTTP authority and path checks for each request on reused HTTP/1.1 and
HTTP/2 connections. The approved target policy also requires a malformed or
fragmented ClientHello, unsupported post-CONNECT data, or failed TLS
interception to close the connection when inspection is required. A client
must not trigger an opaque fallback by splitting ClientHello data. Inspection
never falls back to a tunnel.

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
