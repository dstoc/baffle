use std::path::Path;

use anyhow::{Context, Result};
use tracing::info;

use crate::config::DaemonConfig;

pub async fn run(config_path: &Path) -> Result<()> {
    let config = DaemonConfig::load(config_path)
        .with_context(|| format!("invalid daemon configuration at {}", config_path.display()))?;
    run_with_config(config).await
}

/// Run the daemon with a configuration that has already passed schema validation.
pub async fn run_with_config(_config: DaemonConfig) -> Result<()> {
    info!("daemon started");

    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for shutdown signal")?;

    info!("daemon shutting down");
    Ok(())
}
