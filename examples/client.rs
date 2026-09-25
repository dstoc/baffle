use anyhow::{Context, Result};
use baffle_proxy::client::{Client, HostRule, SessionConfig};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

// This example opens a CONNECT destination through the Baffle data socket.
// An `http://` proxy URL describes only the client-to-proxy protocol; the
// destination request must use HTTPS. Clients that fall back to plaintext
// HTTP or direct egress after a TLS failure are incompatible with Baffle.
#[tokio::main]
async fn main() -> Result<()> {
    let control_socket = std::env::var_os("BAFFLE_CONTROL_SOCKET")
        .unwrap_or_else(|| "/run/baffle/control.sock".into());
    let client = Client::new(control_socket);
    let host = std::env::var("BAFFLE_EXAMPLE_HOST").unwrap_or_else(|_| "example.com".to_owned());
    let port = std::env::var("BAFFLE_EXAMPLE_PORT")
        .unwrap_or_else(|_| "443".to_owned())
        .parse::<u16>()
        .context("BAFFLE_EXAMPLE_PORT must be an integer from 1 to 65535")?;
    if port == 0 {
        anyhow::bail!("BAFFLE_EXAMPLE_PORT must be greater than zero");
    }
    let mut https_rule = HostRule::tunnel(host.clone());
    https_rule.ports = vec![port];
    let policy = SessionConfig::new().with_rule(https_rule);
    let session = client.create(policy).await?;

    let mut proxy = UnixStream::connect(session.socket_path())
        .await
        .context("could not connect to the session proxy socket")?;
    let authority = format!("{host}:{port}");
    proxy
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await?;
    let mut proxy = BufReader::new(proxy);
    let mut status = String::new();
    proxy.read_line(&mut status).await?;
    if !status.starts_with("HTTP/1.1 200") && !status.starts_with("HTTP/1.0 200") {
        anyhow::bail!("proxy did not establish the HTTPS CONNECT tunnel: {status}");
    }
    loop {
        let mut header = String::new();
        if proxy.read_line(&mut header).await? == 0 || header == "\r\n" {
            break;
        }
    }
    println!("Established an opaque CONNECT tunnel to {authority}.");
    println!(
        "Use TLS for this HTTPS destination and verify its origin certificate before sending application data."
    );

    drop(proxy);
    // Closing the handle drops the ephemeral control connection and releases
    // the proxy session.
    session.close();
    Ok(())
}
