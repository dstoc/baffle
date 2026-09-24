use anyhow::{Context, Result};
use baffle_proxy::client::{Client, HostRule, SessionConfig};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new("/run/baffle/control.sock");
    let policy = SessionConfig::new().with_rule(HostRule::tunnel("example.com"));
    let session = client.create(policy).await?;

    let mut proxy = UnixStream::connect(session.socket_path())
        .await
        .context("could not connect to the session proxy socket")?;
    proxy
        .write_all(
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let mut response = Vec::new();
    proxy.read_to_end(&mut response).await?;
    println!("{}", String::from_utf8_lossy(&response));

    // Closing the handle drops the ephemeral control connection and releases
    // the proxy session.
    session.close();
    Ok(())
}
