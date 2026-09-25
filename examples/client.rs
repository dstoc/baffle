use anyhow::{Context, Result};
use baffle_proxy::client::{Client, HostRule, SessionConfig};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

#[tokio::main]
async fn main() -> Result<()> {
    let control_socket = std::env::var_os("BAFFLE_CONTROL_SOCKET")
        .unwrap_or_else(|| "/run/baffle/control.sock".into());
    let client = Client::new(control_socket);
    let host = std::env::var("BAFFLE_EXAMPLE_HOST").unwrap_or_else(|_| "example.com".to_owned());
    let port = std::env::var("BAFFLE_EXAMPLE_PORT")
        .unwrap_or_else(|_| "80".to_owned())
        .parse::<u16>()
        .context("BAFFLE_EXAMPLE_PORT must be an integer from 1 to 65535")?;
    if port == 0 {
        anyhow::bail!("BAFFLE_EXAMPLE_PORT must be greater than zero");
    }
    let mut http_rule = HostRule::tunnel(host.clone());
    http_rule.ports = vec![port];
    if let Ok(address) = std::env::var("BAFFLE_EXAMPLE_PRIVATE_ADDRESS") {
        http_rule.private_addresses.push(address);
    }
    let policy = SessionConfig::new().with_rule(http_rule);
    let session = client.create(policy).await?;

    let mut proxy = UnixStream::connect(session.socket_path())
        .await
        .context("could not connect to the session proxy socket")?;
    proxy
        .write_all(
            format!(
                "GET http://{host}:{port}/ HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
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
