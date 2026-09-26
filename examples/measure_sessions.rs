//! Measure public control-path session provisioning, idle RSS, and teardown.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use baffle_proxy::client::{Client, HostRule, Session, SessionConfig};
use tokio::{net::UnixStream, task::JoinSet, time::sleep};

#[tokio::main]
async fn main() -> Result<()> {
    let control_socket = std::env::var("BAFFLE_CONTROL_SOCKET")
        .context("set BAFFLE_CONTROL_SOCKET to the daemon control socket")?;
    let daemon_pid = std::env::var("BAFFLE_DAEMON_PID")
        .context("set BAFFLE_DAEMON_PID to the daemon process ID")?
        .parse::<u32>()
        .context("BAFFLE_DAEMON_PID must be an integer")?;
    let repeats = env_usize("BAFFLE_MEASURE_REPEATS", 7)?;
    let counts = env_counts("BAFFLE_MEASURE_COUNTS", &[1, 2, 4, 8])?;
    let settle_ms = env_usize("BAFFLE_MEASURE_SETTLE_MS", 200)?;
    let connections_per_session = env_usize("BAFFLE_MEASURE_CONNECTIONS_PER_SESSION", 4)?;
    let allowed_host =
        std::env::var("BAFFLE_MEASURE_HOST").unwrap_or_else(|_| "example.com".to_owned());
    let output = std::env::var("BAFFLE_BENCH_RAW").ok();
    if repeats == 0 {
        bail!("BAFFLE_MEASURE_REPEATS must be greater than zero");
    }
    if !Client::new(&control_socket).list().await?.is_empty() {
        bail!("use a fresh daemon with no active sessions for this measurement");
    }
    if let Some(path) = &output {
        write_row(path, "kind,repeat,count,index,metric,value\n", false)?;
    }

    let client = Client::new(control_socket);
    let policy = SessionConfig::new().with_rule(HostRule::tunnel(allowed_host));
    for _ in 0..counts[0].max(1) {
        let session = client.create(policy.clone()).await?;
        session.close();
    }
    wait_until_empty(&client).await?;

    for count in counts {
        for repeat in 0..repeats {
            sequential_trial(
                &client,
                &policy,
                daemon_pid,
                repeat,
                count,
                settle_ms,
                output.as_deref(),
            )
            .await?;
            concurrent_trial(
                &client,
                &policy,
                daemon_pid,
                repeat,
                count,
                connections_per_session,
                settle_ms,
                output.as_deref(),
            )
            .await?;
        }
    }
    Ok(())
}

async fn sequential_trial(
    client: &Client,
    policy: &SessionConfig,
    daemon_pid: u32,
    repeat: usize,
    count: usize,
    settle_ms: usize,
    output: Option<&str>,
) -> Result<()> {
    let rss_before = read_rss_kib(daemon_pid)?;
    let mut sessions: Vec<Session> = Vec::with_capacity(count);
    let started = Instant::now();
    for index in 0..count {
        let create_started = Instant::now();
        let session = match client.create(policy.clone()).await {
            Ok(session) => session,
            Err(error) => {
                record_failure(
                    output,
                    repeat,
                    count,
                    index,
                    "sequential_create",
                    &error.to_string(),
                )?;
                return Err(error.into());
            }
        };
        record(
            output,
            "sample",
            repeat,
            count,
            index,
            "sequential_create_ms",
            create_started.elapsed().as_secs_f64() * 1_000.0,
        )?;
        sessions.push(session);
    }
    let create_wall = started.elapsed();
    sleep(Duration::from_millis(settle_ms as u64)).await;
    let rss_after = read_rss_kib(daemon_pid)?;
    record(
        output,
        "sample",
        repeat,
        count,
        0,
        "sequential_create_wall_ms",
        create_wall.as_secs_f64() * 1_000.0,
    )?;
    record(
        output,
        "sample",
        repeat,
        count,
        0,
        "sequential_idle_rss_before_kib",
        rss_before as f64,
    )?;
    record(
        output,
        "sample",
        repeat,
        count,
        0,
        "sequential_idle_rss_after_kib",
        rss_after as f64,
    )?;
    record(
        output,
        "sample",
        repeat,
        count,
        0,
        "sequential_idle_rss_delta_per_session_kib",
        rss_after.saturating_sub(rss_before) as f64 / count as f64,
    )?;
    let stop_started = Instant::now();
    drop(sessions);
    wait_until_empty(client).await?;
    record(
        output,
        "sample",
        repeat,
        count,
        0,
        "sequential_teardown_wall_ms",
        stop_started.elapsed().as_secs_f64() * 1_000.0,
    )
}

async fn concurrent_trial(
    client: &Client,
    policy: &SessionConfig,
    daemon_pid: u32,
    repeat: usize,
    count: usize,
    connections_per_session: usize,
    settle_ms: usize,
    output: Option<&str>,
) -> Result<()> {
    let rss_before = read_rss_kib(daemon_pid)?;
    let started = Instant::now();
    let mut creates = JoinSet::new();
    for index in 0..count {
        let client = client.clone();
        let policy = policy.clone();
        creates.spawn(async move {
            let create_started = Instant::now();
            let result = client.create(policy).await;
            (index, create_started.elapsed(), result)
        });
    }
    let mut sessions = Vec::with_capacity(count);
    while let Some(result) = creates.join_next().await {
        let (index, latency, created) = result.context("session creation task panicked")?;
        let session = match created {
            Ok(session) => session,
            Err(error) => {
                record_failure(
                    output,
                    repeat,
                    count,
                    index,
                    "concurrent_create",
                    &error.to_string(),
                )?;
                return Err(error.into());
            }
        };
        record(
            output,
            "sample",
            repeat,
            count,
            index,
            "concurrent_create_ms",
            latency.as_secs_f64() * 1_000.0,
        )?;
        sessions.push(session);
    }
    let wall = started.elapsed();
    sleep(Duration::from_millis(settle_ms as u64)).await;
    let rss_with_sessions = read_rss_kib(daemon_pid)?;
    record(
        output,
        "sample",
        repeat,
        count,
        0,
        "concurrent_create_wall_ms",
        wall.as_secs_f64() * 1_000.0,
    )?;
    record(
        output,
        "sample",
        repeat,
        count,
        0,
        "concurrent_idle_rss_before_kib",
        rss_before as f64,
    )?;
    record(
        output,
        "sample",
        repeat,
        count,
        0,
        "concurrent_idle_rss_after_kib",
        rss_with_sessions as f64,
    )?;
    record(
        output,
        "sample",
        repeat,
        count,
        0,
        "concurrent_idle_session_rss_delta_per_session_kib",
        rss_with_sessions.saturating_sub(rss_before) as f64 / count as f64,
    )?;
    let mut active_connections = Vec::with_capacity(count * connections_per_session);
    for (session_index, session) in sessions.iter().enumerate() {
        for connection_index in 0..connections_per_session {
            match UnixStream::connect(session.socket_path()).await {
                Ok(connection) => active_connections.push(connection),
                Err(error) => {
                    record_failure(
                        output,
                        repeat,
                        count,
                        session_index * connections_per_session + connection_index,
                        "active_unix_connection",
                        &error.to_string(),
                    )?;
                    return Err(error.into());
                }
            }
        }
    }
    sleep(Duration::from_millis(settle_ms as u64)).await;
    let rss_with_connections = read_rss_kib(daemon_pid)?;
    record(
        output,
        "sample",
        repeat,
        count,
        active_connections.len(),
        "active_idle_connections",
        active_connections.len() as f64,
    )?;
    record(
        output,
        "sample",
        repeat,
        count,
        active_connections.len(),
        "active_connection_rss_delta_kib",
        rss_with_connections.saturating_sub(rss_with_sessions) as f64,
    )?;
    record(
        output,
        "sample",
        repeat,
        count,
        active_connections.len(),
        "active_connection_rss_delta_per_connection_kib",
        rss_with_connections.saturating_sub(rss_with_sessions) as f64
            / active_connections.len().max(1) as f64,
    )?;
    drop(active_connections);
    sleep(Duration::from_millis(settle_ms as u64)).await;
    let rss_after_connection_close = read_rss_kib(daemon_pid)?;
    let stop_started = Instant::now();
    drop(sessions);
    wait_until_empty(client).await?;
    record(
        output,
        "sample",
        repeat,
        count,
        0,
        "concurrent_teardown_wall_ms",
        stop_started.elapsed().as_secs_f64() * 1_000.0,
    )?;
    record(
        output,
        "sample",
        repeat,
        count,
        0,
        "post_teardown_rss_delta_from_baseline_kib",
        read_rss_kib(daemon_pid)?.saturating_sub(rss_before) as f64,
    )?;
    record(
        output,
        "sample",
        repeat,
        count,
        0,
        "post_connection_close_rss_delta_kib",
        rss_with_connections.saturating_sub(rss_after_connection_close) as f64,
    )
}

fn env_usize(name: &str, default: usize) -> Result<usize> {
    std::env::var(name)
        .unwrap_or_else(|_| default.to_string())
        .parse::<usize>()
        .with_context(|| format!("{name} must be an integer"))
}

fn env_counts(name: &str, default: &[usize]) -> Result<Vec<usize>> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(default.to_vec());
    };
    let counts = value
        .to_string_lossy()
        .split(',')
        .map(|value| value.trim().parse::<usize>())
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("{name} must be a comma-separated list of integers"))?;
    if counts.is_empty() || counts.contains(&0) {
        bail!("{name} must contain one or more positive session counts");
    }
    Ok(counts)
}

fn write_row(path: &str, row: &str, append: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create(true).write(true);
    if append {
        options.append(true);
    } else {
        options.truncate(true);
    }
    let mut output = options.open(path)?;
    output.write_all(row.as_bytes())?;
    Ok(())
}

fn record(
    output: Option<&str>,
    kind: &str,
    repeat: usize,
    count: usize,
    index: usize,
    metric: &str,
    value: f64,
) -> Result<()> {
    if let Some(output) = output {
        write_row(
            output,
            &format!("{kind},{repeat},{count},{index},{metric},{value:.6}\n"),
            true,
        )?;
    } else {
        println!("{kind},{repeat},{count},{index},{metric},{value:.6}");
    }
    Ok(())
}

fn record_failure(
    output: Option<&str>,
    repeat: usize,
    count: usize,
    index: usize,
    metric: &str,
    error: &str,
) -> Result<()> {
    let safe_error = error.replace(',', ";").replace('\n', " ");
    if let Some(output) = output {
        write_row(
            output,
            &format!("failure,{repeat},{count},{index},{metric},{safe_error}\n"),
            true,
        )?;
    } else {
        eprintln!("failure,{repeat},{count},{index},{metric},{safe_error}");
    }
    Ok(())
}

fn read_rss_kib(pid: u32) -> Result<u64> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))
        .with_context(|| format!("could not read /proc/{pid}/status"))?;
    let line = status
        .lines()
        .find(|line| line.starts_with("VmRSS:"))
        .context("VmRSS was not present in process status")?;
    line.split_whitespace()
        .nth(1)
        .context("VmRSS had no value")?
        .parse()
        .context("VmRSS was not an integer")
}

async fn wait_until_empty(client: &Client) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if client.list().await?.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("ephemeral sessions did not stop within three seconds");
        }
        sleep(Duration::from_millis(1)).await;
    }
}
