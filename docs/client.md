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

The [client example](../examples/client.rs) sends an HTTP proxy request through
the returned Unix socket, reads the response, and closes the lease. The request
is forwarded only when the session policy allows its host and destination port.

Set `HostRule.paths` to allow exact URL paths or recursive patterns such as
`/repos/example/project/**`. Exact rules match only the listed path. Recursive
rules match the slash after the listed path and all descendant segments.
Matching is case-sensitive and ignores the query string. Baffle rejects
ambiguous encodings and forwards the same canonical path that it authorized.
These checks apply to each plaintext HTTP request and to each request on an
intercepted HTTPS connection. A path-restricted rule cannot accept an opaque
HTTPS CONNECT tunnel.

Use `with_private_address` to allow one exact non-public DNS answer for a host.
The exception applies only to that rule's ports. Other non-public DNS answers
remain denied.

```rust
let policy = SessionConfig::new().with_rule(
    HostRule::tunnel("internal.example")
        .with_private_address("10.20.30.40"),
);
```

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

`ClientError` separates authorization, invalid policy, capacity, protocol
mismatch, provisioning, transport, and malformed-protocol failures. The
daemon returns safe error messages and does not include policy credentials in
them.

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
private_addresses = ["10.20.30.40"]
```

The response contains `result.id`, `result.socket`, and `result.persistent`.
Keep the create connection open while an ephemeral session is in use. Closing
it releases the lease. For a persistent session, close the create connection
after reading the response and later send a `stop` request with the returned
ID. `list` returns the caller's session metadata. See the [control protocol
reference](control-protocol.md) for frame limits, authentication, operation
schemas, and response error codes.
