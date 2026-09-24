use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "baffle",
    version,
    about = "Policy-controlled HTTP/HTTPS proxy daemon"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the Baffle daemon.
    Daemon(DaemonArgs),
}

#[derive(Debug, Args)]
pub struct DaemonArgs {
    /// Path to the daemon TOML configuration file.
    #[arg(long, value_name = "PATH")]
    pub config: PathBuf,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::Parser;

    use super::{Cli, Command};

    #[test]
    fn daemon_requires_a_config_path() {
        assert!(Cli::try_parse_from(["baffle", "daemon"]).is_err());
    }

    #[test]
    fn daemon_accepts_a_config_path() {
        let cli = Cli::try_parse_from(["baffle", "daemon", "--config", "/etc/baffle/daemon.toml"])
            .expect("daemon config argument should parse");

        match cli.command {
            Command::Daemon(args) => {
                assert_eq!(args.config, PathBuf::from("/etc/baffle/daemon.toml"));
            }
        }
    }
}
