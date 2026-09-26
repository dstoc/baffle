# baffle-client

`baffle-client` is a typed asynchronous Rust client for the Baffle daemon's v1
Unix control protocol. It creates, lists, and stops proxy sessions. It does not
implement HTTP proxying or connect to a session's data socket.

## Install

Add the crate to a Rust application:

```toml
[dependencies]
baffle-client = "0.2"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Create a session

```rust
use baffle_client::{Client, HostRule, SessionConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new("/run/baffle/control.sock");
    let policy = SessionConfig::new().with_rule(HostRule::tunnel("example.com"));
    let session = client.create(policy).await?;

    println!("proxy {} uses {}", session.id(), session.socket_path().display());
    // Keep the session alive while its workload runs. Closing the handle
    // releases an ephemeral session.
    session.close();
    Ok(())
}
```

The orchestrator must retain the returned session while its workload runs. The
workload uses the session's Unix data socket with an HTTPS client that supports
CONNECT. It must not fall back to direct egress or plaintext HTTP.

See the [Baffle client and protocol guide](https://github.com/dstoc/baffle/blob/main/docs/client.md)
for session lifetimes, file-backed policies, compatibility requirements, and
the wire protocol. API documentation is available on [docs.rs](https://docs.rs/baffle-client).
