use std::{path::Path, sync::Arc};

use anyhow::{Context, Result};
use tracing::info;

use crate::{ca::ManagedCa, config::DaemonConfig, control::ControlServer};

pub async fn run(config_path: &Path) -> Result<()> {
    let config = DaemonConfig::load(config_path)
        .with_context(|| format!("invalid daemon configuration at {}", config_path.display()))?;
    run_with_config(config).await
}

/// Run the daemon with a configuration that has already passed schema validation.
pub async fn run_with_config(config: DaemonConfig) -> Result<()> {
    let ca = Arc::new(ManagedCa::load(&config.ca).context("invalid daemon CA material")?);
    let mut control = ControlServer::bind(&config, ca)?;
    info!("daemon started");

    let result = tokio::select! {
        result = control.run() => result,
        signal = tokio::signal::ctrl_c() => {
            signal.context("failed to listen for shutdown signal").map(|_| ())
        }
    };

    info!("daemon shutting down");
    control.shutdown().await;
    result
}

/// Export the configured public CA certificate for client trust stores.
pub fn export_ca_certificate(config_path: &Path, output: &Path) -> Result<()> {
    let config = DaemonConfig::load(config_path)
        .with_context(|| format!("invalid daemon configuration at {}", config_path.display()))?;
    crate::ca::export_public_certificate(&config.ca, output)
}
