use std::path::Path;

use anyhow::{Context, Result};
use tracing::info;

pub async fn run(config_path: &Path) -> Result<()> {
    info!(config = %config_path.display(), "daemon started");

    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for shutdown signal")?;

    info!("daemon shutting down");
    Ok(())
}
