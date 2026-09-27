//! Run a Baffle session and expose it through Cladding's local socat bridge.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use anyhow::{Context, Result, bail};
use baffle_proxy::client::{Client, HostRule, SessionConfig};

struct SocatBridge(Child);

impl Drop for SocatBridge {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let control_socket = std::env::var_os("BAFFLE_CONTROL_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(default_control_socket);
    let allowed_host = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "github.com".to_owned());
    let port = std::env::var("BAFFLE_BRIDGE_PORT")
        .unwrap_or_else(|_| "18080".to_owned())
        .parse::<u16>()
        .context("BAFFLE_BRIDGE_PORT must be a valid TCP port")?;
    if port == 0 {
        bail!("BAFFLE_BRIDGE_PORT must not be zero");
    }

    let client = Client::new(control_socket);
    let session = client
        .create(SessionConfig::new().with_rule(HostRule::tunnel(allowed_host.clone())))
        .await
        .context("could not create the Baffle session")?;

    let bridge = Command::new("socat")
        .arg(format!("TCP-LISTEN:{port},bind=127.0.0.1,reuseaddr,fork"))
        .arg(format!("UNIX-CONNECT:{}", session.socket_path().display()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .context("could not start socat; install socat and make it available on PATH")?;
    let _bridge = SocatBridge(bridge);

    println!("Cladding proxy: http://127.0.0.1:{port}");
    println!("Allowed destination: {allowed_host}");
    println!("Press Ctrl-C to stop the bridge and release the Baffle session.");
    tokio::signal::ctrl_c()
        .await
        .context("could not wait for Ctrl-C")?;

    drop(_bridge);
    session.close();
    Ok(())
}

fn default_control_socket() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                // SAFETY: geteuid has no preconditions and does not access memory.
                let uid = unsafe { libc::geteuid() };
                PathBuf::from(format!("/tmp/baffle-{uid}"))
            })
            .join("Library/Caches/Baffle/control.sock")
    }
    #[cfg(not(target_os = "macos"))]
    {
        PathBuf::from("/run/baffle/control.sock")
    }
}
