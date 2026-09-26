use anyhow::Result;
use baffle_proxy::{cli::Cli, daemon};
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    initialize_tracing();

    let cli = Cli::parse();
    match cli.command {
        baffle_proxy::cli::Command::Daemon(args) => daemon::run(&args.config).await,
        baffle_proxy::cli::Command::Create(args) => {
            baffle_proxy::cli::create(cli.control_socket, args).await
        }
        baffle_proxy::cli::Command::List => baffle_proxy::cli::list(cli.control_socket).await,
        baffle_proxy::cli::Command::Stop(args) => {
            baffle_proxy::cli::stop(cli.control_socket, args).await
        }
        baffle_proxy::cli::Command::Ca(args) => match args.command {
            baffle_proxy::cli::CaCommand::Export(args) => {
                daemon::export_ca_certificate(&args.config, &args.output)
            }
        },
    }
}

fn initialize_tracing() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("baffle_proxy=info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}
