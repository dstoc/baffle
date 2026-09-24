use std::path::Path;

use anyhow::{Context, Result};
use tracing::info;

use crate::{config::DaemonConfig, control::ControlServer};

pub async fn run(config_path: &Path) -> Result<()> {
    let config = DaemonConfig::load(config_path)
        .with_context(|| format!("invalid daemon configuration at {}", config_path.display()))?;
    run_with_config(config).await
}

/// Run the daemon with a configuration that has already passed schema validation.
pub async fn run_with_config(config: DaemonConfig) -> Result<()> {
    let mut control = ControlServer::bind(&config)?;
    info!("daemon started");

    tokio::select! {
        result = control.run() => result?,
        signal = tokio::signal::ctrl_c() => {
            signal.context("failed to listen for shutdown signal")?;
        }
    }

    info!("daemon shutting down");
    Ok(())
}
