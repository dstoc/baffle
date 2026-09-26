use baffle_client::{Client, HostRule, SessionConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let control_socket = std::env::var_os("BAFFLE_CONTROL_SOCKET")
        .unwrap_or_else(|| "/run/baffle/control.sock".into());
    let client = Client::new(control_socket);
    let policy = SessionConfig::new().with_rule(HostRule::tunnel("example.com"));
    let session = client.create(policy).await?;

    println!(
        "proxy {} uses {}",
        session.id(),
        session.socket_path().display()
    );
    println!("Press Ctrl-C to release the session after its workload exits.");
    tokio::signal::ctrl_c().await?;
    session.close();
    Ok(())
}
