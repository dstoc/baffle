use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};

use anyhow::{Context, Result, anyhow};
use baffle_client::{
    Client, ClientError, HeaderInjection, HostRule, InjectionFormat, ReloadResult, ReloadStatus,
    RuleMode, Session, SessionConfig, SessionInfo,
};
use clap::{ArgGroup, Args, Parser, Subcommand};

const DEFAULT_CONTROL_SOCKET: &str = "/run/baffle/control.sock";

#[derive(Debug, Parser)]
#[command(
    name = "baffle",
    version,
    about = "Policy-controlled HTTP/HTTPS proxy daemon"
)]
pub struct Cli {
    /// Unix control socket for create, list, stop, and reload.
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        default_value = DEFAULT_CONTROL_SOCKET
    )]
    pub control_socket: PathBuf,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the Baffle daemon.
    Daemon(DaemonArgs),
    /// Create a session from a daemon-managed file or local inline TOML.
    Create(CreateArgs),
    /// List active sessions owned by the current user.
    List,
    /// Stop an active session by ID.
    Stop(StopArgs),
    /// Reload one file-backed session or all active file-backed sessions.
    Reload(ReloadArgs),
    /// Manage the daemon certificate authority.
    Ca(CaArgs),
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("source").required(true).args(["file", "config"]))) ]
pub struct CreateArgs {
    /// Relative TOML filename beneath the daemon's session configuration directory.
    #[arg(value_name = "SERVER_FILE", conflicts_with = "config")]
    pub file: Option<String>,
    /// Local session TOML file to send through the inline create operation.
    #[arg(long, value_name = "PATH", conflicts_with = "file")]
    pub config: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct StopArgs {
    /// Opaque session ID returned by `baffle create` or `baffle list`.
    #[arg(value_name = "SESSION_ID")]
    pub session_id: String,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("target").required(true).args(["session_id", "all"])))]
pub struct ReloadArgs {
    /// Opaque file-backed session ID returned by `create` or `list`.
    #[arg(value_name = "SESSION_ID", conflicts_with = "all")]
    pub session_id: Option<String>,
    /// Reload every active file-backed session owned by the current user.
    #[arg(long, conflicts_with = "session_id")]
    pub all: bool,
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

pub async fn create(control_socket: PathBuf, args: CreateArgs) -> Result<()> {
    let client = Client::new(control_socket);
    let session = if let Some(name) = args.file {
        client
            .create_from_file(name)
            .await
            .map_err(|error| client_error(error, client.control_socket(), false))?
    } else if let Some(path) = args.config {
        let config = load_local_session_config(&path)?;
        client
            .create(config)
            .await
            .map_err(|error| client_error(error, client.control_socket(), true))?
    } else {
        unreachable!("clap requires one create source")
    };

    report_created_session(&session)?;
    if !session.is_persistent() {
        wait_for_shutdown_signal().await?;
    }
    Ok(())
}

pub async fn list(control_socket: PathBuf) -> Result<()> {
    let client = Client::new(control_socket);
    let sessions = client
        .list()
        .await
        .map_err(|error| client_error(error, client.control_socket(), false))?;
    print_sessions(&sessions)
}

pub async fn stop(control_socket: PathBuf, args: StopArgs) -> Result<()> {
    let client = Client::new(control_socket);
    client
        .stop(args.session_id.as_str())
        .await
        .map_err(|error| client_error(error, client.control_socket(), false))?;
    println!("Stopped session {}.", args.session_id);
    Ok(())
}

pub async fn reload(control_socket: PathBuf, args: ReloadArgs) -> Result<()> {
    let client = Client::new(control_socket);
    let results = if args.all {
        client
            .reload_all()
            .await
            .map_err(|error| client_error(error, client.control_socket(), false))?
    } else {
        let session_id = args
            .session_id
            .as_deref()
            .expect("clap requires one reload target");
        vec![
            client
                .reload(session_id)
                .await
                .map_err(|error| client_error(error, client.control_socket(), false))?,
        ]
    };
    print_reload_results(&results)?;
    if results
        .iter()
        .any(|result| result.status == ReloadStatus::Failed)
    {
        return Err(anyhow!("one or more sessions failed to reload"));
    }
    Ok(())
}

fn print_reload_results(results: &[ReloadResult]) -> Result<()> {
    for result in results {
        match result.status {
            ReloadStatus::Reloaded => println!(
                "Session {}: reloaded (socket {}).",
                result.id,
                result.socket_path.display()
            ),
            ReloadStatus::Unchanged => println!(
                "Session {}: unchanged (socket {}).",
                result.id,
                result.socket_path.display()
            ),
            ReloadStatus::Failed => println!(
                "Session {}: failed ({}) (socket {}).",
                result.id,
                reload_failure_text(result.reason.as_deref()),
                result.socket_path.display()
            ),
        }
    }
    io::stdout()
        .flush()
        .context("could not flush reload results")
}

fn reload_failure_text(reason: Option<&str>) -> &str {
    match reason {
        Some("inline_session") => "inline-configured sessions cannot be reloaded",
        Some("configuration_not_found") => "configuration file was not found",
        Some("configuration_unavailable") => "configuration file could not be read safely",
        Some("configuration_invalid") => "configuration file is invalid",
        Some("credentials_unavailable") => "credentials are unavailable",
        Some("listener_unavailable") => "replacement listener could not be created",
        Some("generation_limit") => "reload resource limit reached",
        Some("session_stopping") => "session is stopping",
        Some("session_unavailable") => "session is unavailable",
        _ => "reload failed",
    }
}

fn load_local_session_config(path: &std::path::Path) -> Result<SessionConfig> {
    let toml = fs::read_to_string(path)
        .with_context(|| format!("could not read local session config {}", path.display()))?;
    let request = crate::config::ControlRequest::from_toml(&toml)
        .with_context(|| format!("could not parse local session config {}", path.display()))?;
    let crate::config::ControlRequest::Create { session, .. } = request else {
        return Err(anyhow!(
            "local session config {} must contain a version 1 create request",
            path.display()
        ));
    };

    Ok(SessionConfig {
        persistent: session.persistent,
        socket_name: session.socket_name,
        rules: session
            .rules
            .into_iter()
            .map(|rule| HostRule {
                host: rule.host,
                mode: match rule.mode {
                    crate::config::RuleMode::Tunnel => RuleMode::Tunnel,
                    crate::config::RuleMode::Intercept => RuleMode::Intercept,
                },
                ports: rule.ports,
                paths: rule.paths.iter().map(|path| path.as_str()).collect(),
                inject: rule
                    .inject
                    .into_iter()
                    .map(|injection| HeaderInjection {
                        header: injection.header,
                        secret: injection.secret.as_str().to_owned(),
                        format: match injection.format {
                            crate::config::InjectionFormat::Raw => InjectionFormat::Raw,
                            crate::config::InjectionFormat::Bearer => InjectionFormat::Bearer,
                            crate::config::InjectionFormat::BasicPassword => {
                                InjectionFormat::BasicPassword
                            }
                        },
                        username: injection.username,
                    })
                    .collect(),
            })
            .collect(),
    })
}

fn report_created_session(session: &Session) -> Result<()> {
    if session.is_persistent() {
        println!(
            "Created persistent session {} (it remains active after this command exits).",
            session.id()
        );
    } else {
        println!(
            "Created leased session {} (it stops when this command exits).",
            session.id()
        );
    }
    println!("Data socket: {}", session.socket_path().display());
    io::stdout()
        .flush()
        .context("could not flush session details")
}

fn print_sessions(sessions: &[SessionInfo]) -> Result<()> {
    if sessions.is_empty() {
        println!("No active sessions.");
        return Ok(());
    }

    println!("ID\tSTATUS\tTYPE\tDATA SOCKET");
    for session in sessions {
        let session_type = if session.persistent {
            "persistent"
        } else {
            "leased"
        };
        let state = match session.state {
            baffle_client::SessionState::Running => "running",
            baffle_client::SessionState::Stopping => "stopping",
        };
        println!(
            "{}\t{}\t{}\t{}",
            session.id,
            state,
            session_type,
            session.socket_path.display()
        );
    }
    io::stdout().flush().context("could not flush session list")
}

fn client_error(
    error: ClientError,
    control_socket: &std::path::Path,
    inline: bool,
) -> anyhow::Error {
    match error {
        ClientError::Transport(error) => anyhow!(
            "control socket {} is unavailable or the request failed: {error}",
            control_socket.display()
        ),
        ClientError::OperationNotAllowed(message) if inline => anyhow!(
            "inline session creation is disabled by the daemon's file_only mode; use `baffle create <server-relative-file.toml>` instead ({message})"
        ),
        error => anyhow!(error),
    }
}

async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("could not register SIGTERM handler")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("could not wait for Ctrl+C")?,
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c()
        .await
        .context("could not wait for Ctrl+C")?;
    Ok(())
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
                assert_eq!(
                    cli.control_socket,
                    PathBuf::from("/run/baffle/control.sock")
                );
            }
            _ => panic!("expected daemon command"),
        }
    }

    #[test]
    fn create_accepts_either_one_source_and_control_socket() {
        let file = Cli::try_parse_from([
            "baffle",
            "--control-socket",
            "/tmp/baffle.sock",
            "create",
            "cladding/github.toml",
        ])
        .expect("server-side create arguments should parse");
        assert_eq!(file.control_socket, PathBuf::from("/tmp/baffle.sock"));
        assert!(matches!(file.command, Command::Create(_)));

        let inline = Cli::try_parse_from(["baffle", "create", "--config", "./github.toml"])
            .expect("inline create arguments should parse");
        assert!(matches!(inline.command, Command::Create(_)));

        assert!(Cli::try_parse_from(["baffle", "create"]).is_err());
        assert!(
            Cli::try_parse_from([
                "baffle",
                "create",
                "cladding/github.toml",
                "--config",
                "./github.toml"
            ])
            .is_err()
        );
    }

    #[test]
    fn reload_requires_one_id_or_all() {
        let one = Cli::try_parse_from(["baffle", "reload", "session_123"])
            .expect("reload by ID should parse");
        assert!(
            matches!(one.command, Command::Reload(args) if args.session_id.as_deref() == Some("session_123") && !args.all)
        );

        let all =
            Cli::try_parse_from(["baffle", "reload", "--all"]).expect("reload all should parse");
        assert!(
            matches!(all.command, Command::Reload(args) if args.all && args.session_id.is_none())
        );

        assert!(Cli::try_parse_from(["baffle", "reload"]).is_err());
        assert!(Cli::try_parse_from(["baffle", "reload", "session_123", "--all"]).is_err());
    }

    #[test]
    fn local_inline_config_preserves_named_socket() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let config_path = directory.path().join("session.toml");
        std::fs::write(
            &config_path,
            "version = 1\noperation = \"create\"\n\n[session]\nsocket_name = \"cladding/github.sock\"\n\n[[rules]]\nhost = \"github.com\"\nmode = \"tunnel\"\n",
        )
        .expect("inline session config should be written");

        let config = super::load_local_session_config(&config_path)
            .expect("inline session config should load");
        assert_eq!(config.socket_name.as_deref(), Some("cladding/github.sock"));
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
            _ => panic!("expected CA command"),
        }
    }
}
