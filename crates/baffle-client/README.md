# baffle-client

`baffle-client` is a typed asynchronous Rust client for the Baffle daemon's v2
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
use baffle_client::{Client, HostRule, SessionConfig, UnmatchedHostPolicy};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new("/run/baffle/control.sock");
    let policy = SessionConfig::new().with_rule(HostRule::tunnel("example.com"));
    let session = client.create(policy).await?;

    println!("proxy {} uses {}", session.id(), session.socket_path().display());
    if let Some(ca_certificate_pem) = session.ca_certificate_pem() {
        // The create response includes the public certificate for this
        // session's TLS interception CA.
        println!("session CA certificate is {} bytes", ca_certificate_pem.len());
    }
    // Keep the session alive while its workload runs. Closing the handle
    // releases an ephemeral session.
    session.close();
    Ok(())
}
```

To permit opaque tunnels to otherwise-unmatched DNS hostnames on port 443,
create the policy with `SessionConfig::new().unmatched_host_policy(UnmatchedHostPolicy::Tunnel)`.
The default policy denies unmatched hosts.

The orchestrator must retain the returned session while its workload runs. The
workload uses the session's Unix data socket with an HTTPS client that supports
CONNECT. It must not fall back to direct egress or plaintext HTTP.

When the daemon uses `create_mode = "file_only"`, use
`Client::create_ephemeral_from_file(name)` to require an ephemeral
administrator-managed policy. The daemon checks this before session
provisioning. Older protocol-v2 daemons reject the unsupported request field.

`Session::ca_certificate_pem()` returns the public certificate PEM included
with session creation, or `None` when an older protocol-v2 daemon omits the
additive field. Callers that need the certificate for trust setup must treat
`None` as unavailable trust material. The response contains no private key.

See the [Baffle client and protocol guide](https://github.com/dstoc/baffle/blob/main/docs/client.md)
for session lifetimes, file-backed policies, compatibility requirements, and
the wire protocol. API documentation is available on [docs.rs](https://docs.rs/baffle-client).
