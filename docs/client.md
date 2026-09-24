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
the returned Unix socket, reads the response, and closes the lease. The daemon
currently denies outbound requests while policy enforcement is incomplete, so
the example may print an HTTP 403 response.

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
```

The response contains `result.id`, `result.socket`, and `result.persistent`.
Keep the create connection open while an ephemeral session is in use. Closing
it releases the lease. For a persistent session, close the create connection
after reading the response and later send a `stop` request with the returned
ID. `list` returns the caller's session metadata. See the [control protocol
reference](control-protocol.md) for frame limits, authentication, operation
schemas, and response error codes.
