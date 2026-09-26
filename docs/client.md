# Rust client and direct protocol use

The `baffle-client` package provides a typed asynchronous client for the v1
Unix control protocol. It depends on Tokio, Serde, JSON, and TOML. It does not
depend on Baffle's proxy runtime. The daemon package also re-exports it as
`baffle_proxy::client`.

## Use the Rust client

Create a client with the daemon control-socket path. Keep an ephemeral
`Session` in the trusted orchestrator while the associated workload runs. The
handle contains the proxy ID and data-socket path. Dropping it closes the
control connection and releases the session lease. A persistent session does
not keep that connection open; call `stop` with its ID to remove it.

```rust
use baffle_client::{Client, HostRule, SessionConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
let client = Client::new("/run/baffle/control.sock");
let policy = SessionConfig::new().with_rule(HostRule::tunnel("crates.io"));
let session = client.create(policy).await?;

// Make the session data socket available to the workload. Keep `session`
// alive until the workload exits, then drop it or call `session.close()`.
println!("proxy {} uses {}", session.id(), session.socket_path().display());
Ok(())
}
```

The [client example](../examples/client.rs) sends CONNECT for
`example.com:443`, reads the tunnel response, and closes the lease. It does not
send a TLS request. Use an HTTP proxy client that establishes HTTPS with
CONNECT. An `http://` proxy URL can describe the local proxy endpoint; it does
not permit an `http://` origin.

When the daemon uses `create_mode = "file_only"`, create a session by naming
an administrator-managed TOML file:

```rust
let session = client.create_from_file("cladding/github.toml").await?;
```

The daemon resolves this relative name beneath `daemon.session_config_dir`.
The returned `Session` keeps the ephemeral lease open until it is dropped or
closed.

## Proxy client compatibility

`baffle-client` manages the Unix control protocol. It does not send application
traffic through the data socket or make an HTTP library use CONNECT. The
consumer must provide an HTTP proxy client that sends CONNECT for every HTTPS
destination. Baffle rejects ordinary forward-proxy requests with both
`http://` and absolute-form `https://` targets. It rejects a plaintext
`http://` destination on every port, including port 80. It does not follow
redirects. If a client follows an HTTPS-to-HTTP downgrade, Baffle rejects the
resulting request through the same policy.

The client must not fall back to direct egress or plaintext HTTP when CONNECT
or TLS fails. Clients that cannot disable plaintext downgrade or fallback are
incompatible with Baffle. An `http://` proxy URL is valid for the local proxy
endpoint; the origin URL must use `https://`. CONNECT authority must include a
port. Map an HTTPS origin with no explicit port to `:443`. Rules default to
destination port 443, and non-default ports must be configured explicitly.
A configured TLS service on port 80 is valid when its rule includes port 80;
the client must still use CONNECT.

## Migration

Change clients that use ordinary `http://` requests to HTTPS URLs and CONNECT,
or remove the plaintext-only host and path rules. Keep an explicitly
configured port-80 rule when its service uses TLS. Do not add automatic HTTPS
upgrades. An upgrade can change origin behavior and does not make a client's
redirect handling safe.

Set `HostRule.paths` to allow exact URL paths or recursive patterns such as
`/repos/example/project/**`. Exact rules match only the listed path. Recursive
rules match the slash after the listed path and all descendant segments.
Matching is case-sensitive and ignores the query string. Baffle rejects
ambiguous encodings and forwards the same canonical path that it authorized.
Path checks apply to each HTTP/1.1 or HTTP/2 request inside successfully
intercepted TLS. A path-restricted rule cannot accept an opaque CONNECT tunnel.

The client API does not contain an address exception. An allowlisted hostname
can resolve to a private, loopback, link-local, metadata, or other sensitive
address, even if its certificate is valid. Apply DNS policy and network egress
rules when the deployment requires address containment.

Cladding or another orchestrator should own the `Client` and ephemeral session
outside the sandbox. It can expose the returned data socket to that workload
through its existing proxy mapping. The sandbox should receive neither the
control socket nor credentials used for secret injection.

The same client supports typed `list` and `stop` operations:

```rust
use baffle_client::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
let client = Client::new("/run/baffle/control.sock");
for session in client.list().await? {
    println!("{}: {:?}", session.id, session.state);
}
client.stop("persistent-session-id").await?;
Ok(())
}
```

`ClientError` separates authorization, invalid policy, capacity, missing or
unavailable session files, disallowed operations, protocol mismatch,
provisioning, transport, and malformed-protocol failures. The daemon returns
safe error messages and does not include file contents or private daemon
paths in them.

## Speak the protocol directly

An orchestrator that cannot use Rust can implement the same protocol. Open one
Unix connection per operation, write one UTF-8 TOML request, then read one JSON
response. Prefix both payloads with a four-byte unsigned big-endian length.
For example, create an ephemeral session with:

```toml
version = 1
operation = "create"

[session]
persistent = false

[[rules]]
host = "crates.io"
mode = "tunnel"
ports = [443]

[[rules]]
host = "internal.example"
mode = "tunnel"
ports = [8443]
```

The rule authorizes the exact hostname and port. It does not restrict the IP
address returned by DNS. Move any intended address restriction to deployment
DNS and network egress policy.

The response contains `result.id`, `result.socket`, and `result.persistent`.
Keep the create connection open while an ephemeral session is in use. Closing
it releases the lease. For a persistent session, close the create connection
after reading the response and later send a `stop` request with the returned
ID. `list` returns the caller's session metadata. See the [control protocol
reference](control-protocol.md) for frame limits, authentication, operation
schemas, and response error codes.
