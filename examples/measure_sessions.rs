//! Report session creation latency, concurrent creation, and idle daemon RSS.

use std::{
    fs,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use baffle_proxy::client::{Client, HostRule, Session, SessionConfig};
use tokio::{task::JoinSet, time::sleep};

#[tokio::main]
async fn main() -> Result<()> {
    let control_socket = std::env::var("BAFFLE_CONTROL_SOCKET")
        .context("set BAFFLE_CONTROL_SOCKET to the daemon control socket")?;
    let daemon_pid = std::env::var("BAFFLE_DAEMON_PID")
        .context("set BAFFLE_DAEMON_PID to the baffle process ID")?
        .parse::<u32>()
        .context("BAFFLE_DAEMON_PID must be an integer")?;
    let count = std::env::var("BAFFLE_MEASURE_COUNT")
        .unwrap_or_else(|_| "8".to_owned())
        .parse::<usize>()
        .context("BAFFLE_MEASURE_COUNT must be an integer")?;
    if count == 0 {
        bail!("BAFFLE_MEASURE_COUNT must be greater than zero");
    }
    let allowed_host =
        std::env::var("BAFFLE_MEASURE_HOST").unwrap_or_else(|_| "example.com".to_owned());
    let client = Client::new(control_socket);
    let policy = SessionConfig::new().with_rule(HostRule::tunnel(allowed_host));

    if !client.list().await?.is_empty() {
        bail!("use an idle daemon with no existing sessions for this measurement");
    }

    let mut sequential_latencies = Vec::with_capacity(count);
    for _ in 0..count {
        let started = Instant::now();
        let session = client.create(policy.clone()).await?;
        sequential_latencies.push(started.elapsed());
        session.close();
    }
    wait_until_empty(&client).await?;
    sleep(Duration::from_millis(200)).await;
    let rss_before_kib = read_rss_kib(daemon_pid)?;

    let started = Instant::now();
    let mut creates = JoinSet::new();
    for _ in 0..count {
        let client = client.clone();
        let policy = policy.clone();
        creates.spawn(async move {
            let started = Instant::now();
            let session = client.create(policy).await?;
            Ok::<_, baffle_proxy::client::ClientError>((started.elapsed(), session))
        });
    }

    let mut concurrent_latencies = Vec::with_capacity(count);
    let mut sessions: Vec<Session> = Vec::with_capacity(count);
    while let Some(result) = creates.join_next().await {
        let (latency, session) = result.context("session creation task failed")??;
        concurrent_latencies.push(latency);
        sessions.push(session);
    }
    let concurrent_wall = started.elapsed();
    sleep(Duration::from_millis(200)).await;
    let rss_after_kib = read_rss_kib(daemon_pid)?;
    let rss_delta_kib = rss_after_kib.saturating_sub(rss_before_kib);

    println!("sequential_create_count={count}");
    println!(
        "sequential_create_median_ms={:.3}",
        percentile_ms(&sequential_latencies, 0.50)
    );
    println!(
        "sequential_create_p95_ms={:.3}",
        percentile_ms(&sequential_latencies, 0.95)
    );
    println!("concurrent_create_completed={}", sessions.len());
    println!(
        "concurrent_create_wall_ms={:.3}",
        concurrent_wall.as_secs_f64() * 1_000.0
    );
    println!(
        "concurrent_create_p95_ms={:.3}",
        percentile_ms(&concurrent_latencies, 0.95)
    );
    println!("idle_session_count={}", sessions.len());
    println!("daemon_rss_before_kib={rss_before_kib}");
    println!("daemon_rss_after_kib={rss_after_kib}");
    println!("daemon_rss_delta_kib={rss_delta_kib}");
    println!(
        "idle_rss_delta_per_session_kib={:.3}",
        rss_delta_kib as f64 / sessions.len() as f64
    );

    drop(sessions);
    wait_until_empty(&client).await?;
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

fn percentile_ms(samples: &[Duration], percentile: f64) -> f64 {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let index = ((sorted.len() as f64 * percentile).ceil() as usize)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    sorted[index].as_secs_f64() * 1_000.0
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
        sleep(Duration::from_millis(10)).await;
    }
}
