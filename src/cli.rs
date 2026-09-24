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
    /// Manage the daemon certificate authority.
    Ca(CaArgs),
}

#[derive(Debug, Args)]
pub struct CaArgs {
    #[command(subcommand)]
    pub command: CaCommand,
}

#[derive(Debug, Subcommand)]
pub enum CaCommand {
    /// Export the public CA certificate for client trust stores.
    Export(CaExportArgs),
}

#[derive(Debug, Args)]
pub struct CaExportArgs {
    /// Path to the daemon TOML configuration file.
    #[arg(long, value_name = "PATH")]
    pub config: PathBuf,
    /// New file path for the public CA certificate. Existing files are not replaced.
    #[arg(long, value_name = "PATH")]
    pub output: PathBuf,
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

    use super::{CaCommand, Cli, Command};

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
            Command::Ca(_) => panic!("expected daemon command"),
        }
    }

    #[test]
    fn ca_export_requires_config_and_output_paths() {
        let cli = Cli::try_parse_from([
            "baffle",
            "ca",
            "export",
            "--config",
            "/etc/baffle/daemon.toml",
            "--output",
            "/tmp/baffle-ca.pem",
        ])
        .expect("CA export arguments should parse");

        match cli.command {
            Command::Ca(args) => match args.command {
                CaCommand::Export(args) => {
                    assert_eq!(args.config, PathBuf::from("/etc/baffle/daemon.toml"));
                    assert_eq!(args.output, PathBuf::from("/tmp/baffle-ca.pem"));
                }
            },
            Command::Daemon(_) => panic!("expected CA command"),
        }
    }
}
