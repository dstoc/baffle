//! Opt-in live runtime benchmark shared by the two proxy backend builds.
//!
//! Run with `cargo test --lib --no-default-features --features <backend>
//! runtime_benchmark -- --ignored --nocapture --test-threads=1`. The test uses
//! local TLS origins and records request-level latency rows when
//! `BAFFLE_BENCH_RAW` names an output file.

use std::{
    fs::{self, OpenOptions},
    io,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use rcgen::KeyPair;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{Barrier, mpsc},
    task::JoinSet,
    time::sleep,
};
use tokio_rustls::{TlsAcceptor, TlsConnector, rustls};

use super::{
    ProxyRuntime, ProxyRuntimeEvent, RuntimeId, benchmark_tcp_nodelay_enabled,
    benchmark_tcp_nodelay_mode, set_test_upstream_trust_anchor,
};
use crate::{
    ca::ManagedCa,
    config::{CaConfig, ControlRequest, SessionConfig},
    secrets::ResolvedSecrets,
    telemetry::Metrics,
};

type BenchError = Box<dyn std::error::Error + Send + Sync>;

const TRIALS: usize = 5;
const WARMUP_REQUESTS: usize = 16;
const MEASURED_REQUESTS: usize = 80;
const CHARACTERIZATION_CONCURRENCY: [usize; 3] = [1, 4, 16];
const REQUEST_BODY_BYTES: usize = 4096;
const RESPONSE_BODY_BYTES: usize = 32768;
const MAX_CHARACTERIZATION_BODY_BYTES: usize = 4 * 1024 * 1024;

const BAFFLE_CA_SHA256: &str = "88:0E:ED:ED:4A:CC:4E:9E:3A:5B:C6:31:3B:AC:F2:84:64:DF:41:D5:5E:01:71:F9:7E:21:78:8E:AB:BE:35:D6";
const ORIGIN_ROOT_SHA256: &str = "37:F2:22:D7:81:9C:58:33:75:B8:E6:86:50:B9:CF:09:BE:13:50:D3:38:25:31:98:81:D8:36:64:AE:9B:02:5B";
const ORIGIN_LEAF_SHA256: &str = "0E:C9:4E:6E:FB:77:C3:D1:79:16:DD:F1:C8:01:A9:7C:47:E0:7D:4C:6E:CD:C9:4F:A3:23:D6:2D:9C:17:7C:20";

#[cfg(debug_assertions)]
const PROFILE: &str = "debug";
#[cfg(not(debug_assertions))]
const PROFILE: &str = "release";

#[cfg(feature = "backend-hudsucker")]
const BACKEND: &str = "hudsucker";
#[cfg(feature = "backend-rama")]
const BACKEND: &str = "rama";

#[derive(Clone)]
struct OriginMaterial {
    tls: Arc<rustls::ServerConfig>,
    root_der: Vec<u8>,
}

struct Origin {
    address: std::net::SocketAddr,
    requests: Arc<AtomicUsize>,
    valid_credentials: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

#[tokio::test]
#[ignore = "opt-in comparative runtime benchmark; see docs/benchmarking.md"]
async fn runtime_benchmark() -> Result<(), BenchError> {
    let output = BenchOutput::new()?;
    output.row("meta", 0, 0, "backend", BACKEND)?;
    output.row("meta", 0, 0, "profile", PROFILE)?;
    output.row("meta", 0, 0, "rustc", &rustc_version())?;
    output.row("meta", 0, 0, "tcp_nodelay", &benchmark_tcp_nodelay_mode())?;
    output.row("meta", 0, 0, "baffle_ca_sha256", BAFFLE_CA_SHA256)?;
    output.row("meta", 0, 0, "origin_root_sha256", ORIGIN_ROOT_SHA256)?;
    output.row("meta", 0, 0, "origin_leaf_sha256", ORIGIN_LEAF_SHA256)?;

    let ca_dir = tempfile::tempdir()?;
    let ca = managed_ca(ca_dir.path())?;
    let (baffle_ca_der, origin_material) = tls_material(&ca)?;
    set_test_upstream_trust_anchor(origin_material.root_der.clone());
    let origin = start_http1_origin(origin_material.tls.clone(), RESPONSE_BODY_BYTES).await?;
    let authority = format!("localhost:{}", origin.address.port());
    let session = intercept_session(origin.address.port());

    let mut startup_ms = Vec::with_capacity(TRIALS);
    let mut teardown_ms = Vec::with_capacity(TRIALS);
    for trial in 0..TRIALS {
        let socket_path = ca_dir.path().join(format!("startup-{trial}.sock"));
        let started = Instant::now();
        let runtime = start_runtime(
            format!("bench-startup-{trial}"),
            session.clone(),
            Arc::clone(&ca),
            socket_path.clone(),
        )
        .await?;
        let start_elapsed = started.elapsed();
        let stopped = Instant::now();
        runtime.shutdown(Duration::from_secs(2)).await;
        let stop_elapsed = stopped.elapsed();
        if socket_path.exists() {
            output.row("failure", trial, 0, "startup_teardown", "socket retained")?;
            return Err("runtime teardown retained its Unix socket".into());
        }
        startup_ms.push(start_elapsed.as_secs_f64() * 1_000.0);
        teardown_ms.push(stop_elapsed.as_secs_f64() * 1_000.0);
        output.row(
            "sample",
            trial,
            0,
            "session_start_ms",
            &format!("{:.3}", startup_ms[trial]),
        )?;
        output.row(
            "sample",
            trial,
            0,
            "session_stop_ms",
            &format!("{:.3}", teardown_ms[trial]),
        )?;
    }
    output.summary("session_start_ms", &startup_ms)?;
    output.summary("session_stop_ms", &teardown_ms)?;

    for session_count in [1_usize, 2, 4, 8] {
        for trial in 0..TRIALS {
            let before = read_rss_kib()?;
            let started = Instant::now();
            let mut runtimes = Vec::with_capacity(session_count);
            for index in 0..session_count {
                runtimes.push(
                    start_runtime(
                        format!("bench-idle-{session_count}-{trial}-{index}"),
                        session.clone(),
                        Arc::clone(&ca),
                        ca_dir
                            .path()
                            .join(format!("idle-{session_count}-{trial}-{index}.sock")),
                    )
                    .await?,
                );
            }
            let create_elapsed = started.elapsed();
            sleep(Duration::from_millis(100)).await;
            let after = read_rss_kib()?;
            output.row(
                "sample",
                trial,
                session_count,
                "sequential_runtime_create_ms",
                &format!("{:.3}", create_elapsed.as_secs_f64() * 1_000.0),
            )?;
            output.row(
                "sample",
                trial,
                session_count,
                "idle_process_rss_delta_kib",
                &after.saturating_sub(before).to_string(),
            )?;
            output.row(
                "sample",
                trial,
                session_count,
                "idle_rss_delta_per_session_kib",
                &format!(
                    "{:.3}",
                    after.saturating_sub(before) as f64 / session_count as f64
                ),
            )?;
            for runtime in runtimes {
                runtime.shutdown(Duration::from_secs(2)).await;
            }

            let before = read_rss_kib()?;
            let concurrent_started = Instant::now();
            let mut creates = JoinSet::new();
            for index in 0..session_count {
                let ca = Arc::clone(&ca);
                let session = session.clone();
                let socket_path = ca_dir
                    .path()
                    .join(format!("concurrent-{session_count}-{trial}-{index}.sock"));
                creates.spawn(async move {
                    start_runtime(
                        format!("bench-concurrent-{session_count}-{trial}-{index}"),
                        session,
                        ca,
                        socket_path,
                    )
                    .await
                });
            }
            let mut concurrent_runtimes = Vec::with_capacity(session_count);
            while let Some(result) = creates.join_next().await {
                match result {
                    Ok(Ok(runtime)) => concurrent_runtimes.push(runtime),
                    Ok(Err(error)) => {
                        output.row(
                            "failure",
                            trial,
                            concurrent_runtimes.len(),
                            "concurrent_runtime_create",
                            &error.to_string(),
                        )?;
                        return Err(error);
                    }
                    Err(error) => {
                        output.row(
                            "failure",
                            trial,
                            concurrent_runtimes.len(),
                            "concurrent_runtime_task",
                            &error.to_string(),
                        )?;
                        return Err(error.into());
                    }
                }
            }
            let create_elapsed = concurrent_started.elapsed();
            sleep(Duration::from_millis(100)).await;
            let after = read_rss_kib()?;
            output.row(
                "sample",
                trial,
                session_count,
                "concurrent_runtime_create_wall_ms",
                &format!("{:.3}", create_elapsed.as_secs_f64() * 1_000.0),
            )?;
            output.row(
                "sample",
                trial,
                session_count,
                "concurrent_idle_process_rss_delta_kib",
                &after.saturating_sub(before).to_string(),
            )?;
            for runtime in concurrent_runtimes {
                let socket = runtime.socket_path().to_path_buf();
                runtime.shutdown(Duration::from_secs(2)).await;
                if socket.exists() {
                    output.row(
                        "failure",
                        trial,
                        session_count,
                        "concurrent_teardown",
                        "socket retained",
                    )?;
                    return Err("concurrent runtime teardown retained a Unix socket".into());
                }
            }
        }
    }

    let runtime = start_runtime(
        "bench-http1".to_owned(),
        session,
        Arc::clone(&ca),
        ca_dir.path().join("http1.sock"),
    )
    .await?;
    let (cpu_before, rss_before) = (cpu_time_us()?, read_rss_kib()?);
    let mut all_latencies = Vec::with_capacity(TRIALS * MEASURED_REQUESTS);
    for trial in 0..TRIALS {
        let rss_before_connection = read_rss_kib()?;
        let mut client = http1_client(runtime.local_addr(), &authority, &baffle_ca_der).await?;
        output.row(
            "sample",
            trial,
            1,
            "http1_active_connection_rss_delta_kib",
            &read_rss_kib()?
                .saturating_sub(rss_before_connection)
                .to_string(),
        )?;
        for _ in 0..WARMUP_REQUESTS {
            if let Err(error) =
                send_http1_request(&mut client, &authority, REQUEST_BODY_BYTES).await
            {
                output.row("failure", trial, 0, "http1_warmup", &error.to_string())?;
                return Err(error);
            }
        }
        let started = Instant::now();
        let trial_cpu_before = cpu_time_us()?;
        let first = all_latencies.len();
        for request_index in 0..MEASURED_REQUESTS {
            let request_started = Instant::now();
            if let Err(error) =
                send_http1_request(&mut client, &authority, REQUEST_BODY_BYTES).await
            {
                output.row("failure", trial, request_index, "http1", &error.to_string())?;
                return Err(error);
            }
            let elapsed = request_started.elapsed();
            all_latencies.push(elapsed.as_secs_f64() * 1_000.0);
            output.row(
                "latency",
                trial,
                request_index,
                "http1_keepalive_ms",
                &format!("{:.6}", elapsed.as_secs_f64() * 1_000.0),
            )?;
        }
        let total_elapsed = started.elapsed();
        output.row(
            "trial",
            trial,
            MEASURED_REQUESTS,
            "http1_process_cpu_us",
            &cpu_time_us()?.saturating_sub(trial_cpu_before).to_string(),
        )?;
        let median = percentile(&all_latencies[first..], 0.50);
        let p95 = percentile(&all_latencies[first..], 0.95);
        let request_bytes = REQUEST_BODY_BYTES + RESPONSE_BODY_BYTES;
        output.row(
            "trial",
            trial,
            MEASURED_REQUESTS,
            "http1_median_ms",
            &format!("{median:.6}"),
        )?;
        output.row(
            "trial",
            trial,
            MEASURED_REQUESTS,
            "http1_p95_ms",
            &format!("{p95:.6}"),
        )?;
        output.row(
            "trial",
            trial,
            MEASURED_REQUESTS,
            "http1_requests_per_second",
            &format!(
                "{:.3}",
                MEASURED_REQUESTS as f64 / total_elapsed.as_secs_f64()
            ),
        )?;
        output.row(
            "trial",
            trial,
            MEASURED_REQUESTS,
            "http1_mib_per_second",
            &format!(
                "{:.3}",
                ((MEASURED_REQUESTS * request_bytes) as f64 / 1_048_576.0)
                    / total_elapsed.as_secs_f64()
            ),
        )?;
    }
    output.summary("http1_request_latency_ms", &all_latencies)?;
    output.row(
        "meta",
        TRIALS,
        MEASURED_REQUESTS,
        "process_cpu_us",
        &cpu_time_us()?.saturating_sub(cpu_before).to_string(),
    )?;
    output.row(
        "meta",
        TRIALS,
        MEASURED_REQUESTS,
        "process_rss_delta_kib",
        &read_rss_kib()?.saturating_sub(rss_before).to_string(),
    )?;
    output.row(
        "meta",
        0,
        origin.requests.load(Ordering::Relaxed),
        "origin_requests_seen",
        &origin.requests.load(Ordering::Relaxed).to_string(),
    )?;
    output.row(
        "meta",
        0,
        origin.valid_credentials.load(Ordering::Relaxed),
        "credentialed_origin_requests_seen",
        &origin.valid_credentials.load(Ordering::Relaxed).to_string(),
    )?;
    let expected_http1 = TRIALS * (WARMUP_REQUESTS + MEASURED_REQUESTS);
    if origin.requests.load(Ordering::Relaxed) != expected_http1
        || origin.valid_credentials.load(Ordering::Relaxed) != expected_http1
    {
        output.row(
            "failure",
            0,
            expected_http1,
            "http1_fixture_validation",
            &format!(
                "expected {expected_http1} origin requests with injected credentials; observed {} requests and {} credentials",
                origin.requests.load(Ordering::Relaxed),
                origin.valid_credentials.load(Ordering::Relaxed)
            ),
        )?;
        return Err(
            "HTTP/1.1 requests did not reach the origin with the injected credential".into(),
        );
    }
    runtime.shutdown(Duration::from_secs(2)).await;

    let tunnel_runtime = start_runtime(
        "bench-tunnel".to_owned(),
        tunnel_session(origin.address.port()),
        Arc::clone(&ca),
        ca_dir.path().join("tunnel.sock"),
    )
    .await?;
    let mut tunnel_latencies = Vec::with_capacity(TRIALS * MEASURED_REQUESTS);
    for trial in 0..TRIALS {
        let mut client = http1_client(
            tunnel_runtime.local_addr(),
            &authority,
            &origin_material.root_der,
        )
        .await?;
        for _ in 0..WARMUP_REQUESTS {
            if let Err(error) =
                send_http1_request(&mut client, &authority, REQUEST_BODY_BYTES).await
            {
                output.row("failure", trial, 0, "tunnel_warmup", &error.to_string())?;
                return Err(error);
            }
        }
        let started = Instant::now();
        for request_index in 0..MEASURED_REQUESTS {
            let request_started = Instant::now();
            if let Err(error) =
                send_http1_request(&mut client, &authority, REQUEST_BODY_BYTES).await
            {
                output.row(
                    "failure",
                    trial,
                    request_index,
                    "tunnel_http1",
                    &error.to_string(),
                )?;
                return Err(error);
            }
            let elapsed = request_started.elapsed();
            tunnel_latencies.push(elapsed.as_secs_f64() * 1_000.0);
            output.row(
                "latency",
                trial,
                request_index,
                "tunnel_http1_keepalive_ms",
                &format!("{:.6}", elapsed.as_secs_f64() * 1_000.0),
            )?;
        }
        let elapsed = started.elapsed();
        output.row(
            "trial",
            trial,
            MEASURED_REQUESTS,
            "tunnel_http1_requests_per_second",
            &format!("{:.3}", MEASURED_REQUESTS as f64 / elapsed.as_secs_f64()),
        )?;
        output.row(
            "trial",
            trial,
            MEASURED_REQUESTS,
            "tunnel_http1_mib_per_second",
            &format!(
                "{:.3}",
                (MEASURED_REQUESTS * (REQUEST_BODY_BYTES + RESPONSE_BODY_BYTES)) as f64
                    / 1_048_576.0
                    / elapsed.as_secs_f64()
            ),
        )?;
    }
    output.summary("tunnel_http1_request_latency_ms", &tunnel_latencies)?;
    tunnel_runtime.shutdown(Duration::from_secs(2)).await;

    let h2_origin = start_http2_origin(origin_material.tls.clone()).await?;
    let h2_authority = format!("localhost:{}", h2_origin.address.port());
    let h2_runtime = start_runtime(
        "bench-http2".to_owned(),
        intercept_session(h2_origin.address.port()),
        Arc::clone(&ca),
        ca_dir.path().join("http2.sock"),
    )
    .await?;
    let h2_latencies = benchmark_http2(
        &output,
        h2_runtime.local_addr(),
        &h2_authority,
        &baffle_ca_der,
    )
    .await?;
    output.summary("http2_request_latency_ms", &h2_latencies)?;
    output.row(
        "meta",
        0,
        h2_origin.requests.load(Ordering::Relaxed),
        "http2_origin_requests_seen",
        &h2_origin.requests.load(Ordering::Relaxed).to_string(),
    )?;
    output.row(
        "meta",
        0,
        h2_origin.valid_credentials.load(Ordering::Relaxed),
        "http2_credentialed_origin_requests_seen",
        &h2_origin
            .valid_credentials
            .load(Ordering::Relaxed)
            .to_string(),
    )?;
    let expected_http2 = WARMUP_REQUESTS + (TRIALS * MEASURED_REQUESTS);
    if h2_origin.requests.load(Ordering::Relaxed) != expected_http2
        || h2_origin.valid_credentials.load(Ordering::Relaxed) != expected_http2
    {
        output.row(
            "failure",
            0,
            expected_http2,
            "http2_fixture_validation",
            &format!(
                "expected {expected_http2} origin requests with injected credentials; observed {} requests and {} credentials",
                h2_origin.requests.load(Ordering::Relaxed),
                h2_origin.valid_credentials.load(Ordering::Relaxed)
            ),
        )?;
        return Err("HTTP/2 requests did not reach the origin with the injected credential".into());
    }
    h2_runtime.shutdown(Duration::from_secs(2)).await;
    h2_origin.task.abort();
    origin.task.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "opt-in HTTP/1.1 latency characterization; see docs/benchmarking.md"]
async fn runtime_http1_characterization() -> Result<(), BenchError> {
    let output = BenchOutput::new()?;
    let tcp_nodelay_mode = benchmark_tcp_nodelay_mode();
    let client_tcp_nodelay = benchmark_tcp_nodelay_enabled("client");
    let concurrency_levels = benchmark_concurrency_levels()?;
    let request_body_bytes =
        benchmark_body_bytes("BAFFLE_BENCH_REQUEST_BYTES", REQUEST_BODY_BYTES)?;
    let response_body_bytes =
        benchmark_body_bytes("BAFFLE_BENCH_RESPONSE_BYTES", RESPONSE_BODY_BYTES)?;
    let external_origin = std::env::var("BAFFLE_BENCH_ORIGIN_ADDR").ok();
    let origin_name = if external_origin.is_some() {
        "python"
    } else {
        "rust"
    };

    output.row("meta", 0, 0, "backend", BACKEND)?;
    output.row("meta", 0, 0, "profile", PROFILE)?;
    output.row("meta", 0, 0, "rustc", &rustc_version())?;
    output.row("meta", 0, 0, "origin", origin_name)?;
    output.row(
        "meta",
        0,
        0,
        "cpu_affinity",
        &std::env::var("BAFFLE_BENCH_CPU").unwrap_or_else(|_| "unrecorded".to_owned()),
    )?;
    output.row("meta", 0, 0, "tcp_nodelay", &tcp_nodelay_mode)?;
    output.row(
        "meta",
        0,
        0,
        "request_body_bytes",
        &request_body_bytes.to_string(),
    )?;
    output.row(
        "meta",
        0,
        0,
        "response_body_bytes",
        &response_body_bytes.to_string(),
    )?;
    output.row(
        "meta",
        0,
        0,
        "concurrency_levels",
        &concurrency_levels
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(";"),
    )?;

    let ca_dir = tempfile::tempdir()?;
    let ca = managed_ca(ca_dir.path())?;
    let (baffle_ca_der, origin_material) = tls_material(&ca)?;
    set_test_upstream_trust_anchor(origin_material.root_der.clone());

    let (origin_address, embedded_origin) = match external_origin {
        Some(address) => {
            let address = address.parse::<std::net::SocketAddr>()?;
            if !address.ip().is_loopback() {
                return Err("benchmark origin must use a loopback address".into());
            }
            (address, None)
        }
        None => {
            let origin =
                start_http1_origin(origin_material.tls.clone(), response_body_bytes).await?;
            (origin.address, Some(origin))
        }
    };
    let authority = format!("localhost:{}", origin_address.port());
    let runtime = start_runtime(
        "bench-http1-characterization".to_owned(),
        intercept_session(origin_address.port()),
        ca,
        ca_dir.path().join("http1-characterization.sock"),
    )
    .await?;

    for concurrency in concurrency_levels.iter().copied() {
        let metric = format!(
            "http1_{origin_name}_nodelay_{tcp_nodelay_mode}_req{request_body_bytes}_resp{response_body_bytes}_c{concurrency}"
        );
        let mut all_latencies = Vec::with_capacity(TRIALS * concurrency * MEASURED_REQUESTS);
        for trial in 0..TRIALS {
            let mut opening = JoinSet::new();
            for _ in 0..concurrency {
                let authority = authority.clone();
                let root = baffle_ca_der.clone();
                let proxy = runtime.local_addr();
                opening.spawn(async move {
                    http1_client_with_nodelay(proxy, &authority, &root, client_tcp_nodelay).await
                });
            }
            let mut clients = Vec::with_capacity(concurrency);
            while let Some(client) = opening.join_next().await {
                clients.push(client??);
            }

            let mut warming = JoinSet::new();
            for mut client in clients {
                let authority = authority.clone();
                warming.spawn(async move {
                    for _ in 0..WARMUP_REQUESTS {
                        send_http1_request(&mut client, &authority, request_body_bytes).await?;
                    }
                    Ok::<_, BenchError>(client)
                });
            }
            let mut warmed_clients = Vec::with_capacity(concurrency);
            while let Some(client) = warming.join_next().await {
                warmed_clients.push(client??);
            }

            let barrier = Arc::new(Barrier::new(concurrency));
            let trial_cpu_before = cpu_time_us()?;
            let started = Instant::now();
            let mut requests = JoinSet::new();
            for (client_index, mut client) in warmed_clients.into_iter().enumerate() {
                let barrier = Arc::clone(&barrier);
                let authority = authority.clone();
                requests.spawn(async move {
                    barrier.wait().await;
                    let mut latencies = Vec::with_capacity(MEASURED_REQUESTS);
                    for _ in 0..MEASURED_REQUESTS {
                        let request_started = Instant::now();
                        send_http1_request(&mut client, &authority, request_body_bytes).await?;
                        latencies.push(request_started.elapsed().as_secs_f64() * 1_000.0);
                    }
                    Ok::<_, BenchError>((client_index, latencies))
                });
            }

            let mut trial_latencies = Vec::with_capacity(concurrency * MEASURED_REQUESTS);
            while let Some(result) = requests.join_next().await {
                let (client_index, latencies) = result??;
                for (request_index, latency) in latencies.into_iter().enumerate() {
                    let index = client_index * MEASURED_REQUESTS + request_index;
                    output.row(
                        "latency",
                        trial,
                        index,
                        &format!("{metric}_keepalive_ms"),
                        &format!("{latency:.6}"),
                    )?;
                    trial_latencies.push(latency);
                }
            }
            let elapsed = started.elapsed();
            let median = percentile(&trial_latencies, 0.50);
            let p95 = percentile(&trial_latencies, 0.95);
            let request_count = concurrency * MEASURED_REQUESTS;
            output.row(
                "trial",
                trial,
                request_count,
                &format!("{metric}_median_ms"),
                &format!("{median:.6}"),
            )?;
            output.row(
                "trial",
                trial,
                request_count,
                &format!("{metric}_p95_ms"),
                &format!("{p95:.6}"),
            )?;
            output.row(
                "trial",
                trial,
                request_count,
                &format!("{metric}_requests_per_second"),
                &format!("{:.3}", request_count as f64 / elapsed.as_secs_f64()),
            )?;
            output.row(
                "trial",
                trial,
                request_count,
                &format!("{metric}_wall_ms"),
                &format!("{:.3}", elapsed.as_secs_f64() * 1_000.0),
            )?;
            output.row(
                "trial",
                trial,
                request_count,
                &format!("{metric}_mib_per_second"),
                &format!(
                    "{:.3}",
                    (request_count * (request_body_bytes + response_body_bytes)) as f64
                        / 1_048_576.0
                        / elapsed.as_secs_f64()
                ),
            )?;
            output.row(
                "trial",
                trial,
                request_count,
                &format!("{metric}_process_cpu_us"),
                &cpu_time_us()?.saturating_sub(trial_cpu_before).to_string(),
            )?;
            all_latencies.extend(trial_latencies);
        }
        output.summary(&format!("{metric}_keepalive_ms"), &all_latencies)?;
    }

    if let Some(origin) = embedded_origin {
        let expected = TRIALS
            * concurrency_levels.iter().sum::<usize>()
            * (WARMUP_REQUESTS + MEASURED_REQUESTS);
        let requests = origin.requests.load(Ordering::Relaxed);
        let credentials = origin.valid_credentials.load(Ordering::Relaxed);
        output.row(
            "meta",
            0,
            expected,
            "origin_requests_expected",
            &expected.to_string(),
        )?;
        output.row(
            "meta",
            0,
            requests,
            "origin_requests_seen",
            &requests.to_string(),
        )?;
        output.row(
            "meta",
            0,
            credentials,
            "credentialed_origin_requests_seen",
            &credentials.to_string(),
        )?;
        if requests != expected || credentials != expected {
            return Err(format!(
                "expected {expected} embedded origin requests with injected credentials; saw {requests} requests and {credentials} credentials"
            )
            .into());
        }
        origin.task.abort();
    }

    runtime.shutdown(Duration::from_secs(2)).await;
    Ok(())
}

fn benchmark_concurrency_levels() -> Result<Vec<usize>, BenchError> {
    let Some(value) = std::env::var_os("BAFFLE_BENCH_CONCURRENCY") else {
        return Ok(CHARACTERIZATION_CONCURRENCY.to_vec());
    };
    let levels = value
        .to_string_lossy()
        .split(',')
        .map(str::parse::<usize>)
        .collect::<Result<Vec<_>, _>>()?;
    if levels.is_empty()
        || levels
            .iter()
            .any(|level| !CHARACTERIZATION_CONCURRENCY.contains(level))
        || levels
            .iter()
            .enumerate()
            .any(|(index, level)| levels[..index].contains(level))
    {
        return Err("benchmark concurrency must use 1, 4, and/or 16".into());
    }
    Ok(levels)
}

fn benchmark_body_bytes(variable: &str, default: usize) -> Result<usize, BenchError> {
    let Some(value) = std::env::var_os(variable) else {
        return Ok(default);
    };
    let value = value.to_string_lossy().parse::<usize>()?;
    if value == 0 || value > MAX_CHARACTERIZATION_BODY_BYTES {
        return Err(format!(
            "{variable} must be between 1 and {MAX_CHARACTERIZATION_BODY_BYTES} bytes"
        )
        .into());
    }
    Ok(value)
}

fn managed_ca(directory: &Path) -> Result<Arc<ManagedCa>, BenchError> {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("bench/fixtures");
    let certificate_path = directory.join("baffle-bench-ca.pem");
    let key_path = directory.join("baffle-bench-ca-key.pem");
    fs::copy(fixtures.join("baffle-ca.pem"), &certificate_path)?;
    fs::copy(fixtures.join("baffle-ca-key.pem"), &key_path)?;
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
    Ok(Arc::new(ManagedCa::load(&CaConfig {
        certificate: certificate_path,
        private_key: key_path,
    })?))
}

fn tls_material(ca: &ManagedCa) -> Result<(Vec<u8>, OriginMaterial), BenchError> {
    let (_, baffle_ca) = x509_parser::pem::parse_x509_pem(ca.public_certificate_pem())?;
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("bench/fixtures");
    let root_pem = fs::read(fixtures.join("origin-root.pem"))?;
    let leaf_pem = fs::read(fixtures.join("origin-leaf.pem"))?;
    let key_pem = fs::read(fixtures.join("origin-leaf-key.pem"))?;
    let (_, root) = x509_parser::pem::parse_x509_pem(&root_pem)?;
    let (_, leaf) = x509_parser::pem::parse_x509_pem(&leaf_pem)?;
    let key = KeyPair::from_pem(std::str::from_utf8(&key_pem)?)?;
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(leaf.contents)],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                key.serialize_der(),
            )),
        )?;
    let mut server_config = server_config;
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok((
        baffle_ca.contents,
        OriginMaterial {
            tls: Arc::new(server_config),
            root_der: root.contents,
        },
    ))
}

fn intercept_session(port: u16) -> SessionConfig {
    let request = format!(
        "version = 1\noperation = \"create\"\n\n[session]\npersistent = true\n\n[[rules]]\nhost = \"localhost\"\nmode = \"intercept\"\nports = [{port}]\npaths = [\"/allowed\"]\n\n[[rules.inject]]\nheader = \"X-Bench-Token\"\nsecret = \"benchmark-token\"\nformat = \"raw\"\n"
    );
    let ControlRequest::Create { session, .. } =
        ControlRequest::from_toml(&request).expect("benchmark session policy should parse")
    else {
        unreachable!("benchmark request should create a session")
    };
    session
}

fn tunnel_session(port: u16) -> SessionConfig {
    let request = format!(
        "version = 1\noperation = \"create\"\n\n[session]\npersistent = true\n\n[[rules]]\nhost = \"localhost\"\nmode = \"tunnel\"\nports = [{port}]\n"
    );
    let ControlRequest::Create { session, .. } =
        ControlRequest::from_toml(&request).expect("tunnel benchmark policy should parse")
    else {
        unreachable!("benchmark request should create a session")
    };
    session
}

async fn start_runtime(
    id: String,
    session: SessionConfig,
    ca: Arc<ManagedCa>,
    socket_path: std::path::PathBuf,
) -> Result<ProxyRuntime, BenchError> {
    let (events, _receiver) = mpsc::unbounded_channel::<ProxyRuntimeEvent>();
    Ok(ProxyRuntime::start_with_metrics(
        RuntimeId::new(id),
        session,
        Arc::new(ResolvedSecrets::from_values([(
            "benchmark-token".to_owned(),
            "fixed-benchmark-credential".to_owned(),
        )])),
        ca,
        socket_path,
        128,
        Duration::from_secs(2),
        Duration::from_secs(30),
        Arc::new(Metrics::default()),
        events,
    )
    .await?)
}

async fn start_http1_origin(
    config: Arc<rustls::ServerConfig>,
    response_body_bytes: usize,
) -> Result<Origin, BenchError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let requests = Arc::new(AtomicUsize::new(0));
    let valid_credentials = Arc::new(AtomicUsize::new(0));
    let request_counter = Arc::clone(&requests);
    let credential_counter = Arc::clone(&valid_credentials);
    let task = tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(config);
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            if benchmark_tcp_nodelay_enabled("origin")
                && let Err(error) = stream.set_nodelay(true)
            {
                tracing::debug!(%error, "benchmark origin could not set TCP_NODELAY");
                return;
            }
            let acceptor = acceptor.clone();
            let requests = Arc::clone(&request_counter);
            let credentials = Arc::clone(&credential_counter);
            tokio::spawn(async move {
                if let Err(error) =
                    serve_http1(stream, acceptor, requests, credentials, response_body_bytes).await
                    && error.kind() != io::ErrorKind::UnexpectedEof
                {
                    tracing::debug!(%error, "benchmark origin connection closed");
                }
            });
        }
    });
    Ok(Origin {
        address,
        requests,
        valid_credentials,
        task,
    })
}

async fn start_http2_origin(config: Arc<rustls::ServerConfig>) -> Result<Origin, BenchError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let requests = Arc::new(AtomicUsize::new(0));
    let valid_credentials = Arc::new(AtomicUsize::new(0));
    let request_counter = Arc::clone(&requests);
    let credential_counter = Arc::clone(&valid_credentials);
    let mut config = (*config).clone();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let task = tokio::spawn(async move {
        let config = Arc::new(config);
        let (stream, _) = listener
            .accept()
            .await
            .expect("HTTP/2 origin should accept");
        let tls = TlsAcceptor::from(config)
            .accept(stream)
            .await
            .expect("HTTP/2 origin TLS should complete");
        assert_eq!(
            tls.get_ref().1.alpn_protocol(),
            Some(b"h2".as_slice()),
            "origin should negotiate HTTP/2"
        );
        #[cfg(feature = "backend-hudsucker")]
        {
            use hudsucker::hyper_util::rt::{TokioExecutor, TokioIo};
            use hudsucker::{
                Body,
                hyper::{Response, StatusCode, body::Incoming, service::service_fn},
            };

            let service = service_fn(move |request: hudsucker::hyper::Request<Incoming>| {
                let requests = Arc::clone(&request_counter);
                let credentials = Arc::clone(&credential_counter);
                async move {
                    requests.fetch_add(1, Ordering::Relaxed);
                    if request
                        .headers()
                        .get("x-bench-token")
                        .and_then(|value| value.to_str().ok())
                        == Some("fixed-benchmark-credential")
                    {
                        credentials.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Body::empty())
                            .expect("HTTP/2 origin response should build"),
                    )
                }
            });
            hudsucker::hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls), service)
                .await
                .expect("HTTP/2 origin connection should complete");
        }
        #[cfg(feature = "backend-rama")]
        {
            let service = rama::service::service_fn(
                move |request: rama::http::Request<rama::http::core::body::Incoming>| {
                    let requests = Arc::clone(&request_counter);
                    let credentials = Arc::clone(&credential_counter);
                    async move {
                        requests.fetch_add(1, Ordering::Relaxed);
                        if request
                            .headers()
                            .get("x-bench-token")
                            .and_then(|value| value.to_str().ok())
                            == Some("fixed-benchmark-credential")
                        {
                            credentials.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok::<_, std::convert::Infallible>(
                            rama::http::Response::builder()
                                .status(rama::http::StatusCode::OK)
                                .body(rama::http::Body::empty())
                                .expect("HTTP/2 origin response should build"),
                        )
                    }
                },
            );
            rama::http::core::server::conn::http2::Builder::new(rama::rt::Executor::default())
                .serve_connection(rama::ServiceInput::new(tls), service)
                .await
                .expect("HTTP/2 origin connection should complete");
        }
    });
    Ok(Origin {
        address,
        requests,
        valid_credentials,
        task,
    })
}

async fn serve_http1(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    requests: Arc<AtomicUsize>,
    credentials: Arc<AtomicUsize>,
    response_body_bytes: usize,
) -> io::Result<()> {
    let stream = acceptor.accept(stream).await?;
    let mut reader = BufReader::new(stream);
    let response_body = vec![b'R'; response_body_bytes];
    loop {
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).await? == 0 {
            return Ok(());
        }
        let mut content_length = 0;
        let mut authorized = false;
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).await? == 0 || header == "\r\n" {
                break;
            }
            if let Some((name, value)) = header.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().unwrap_or(0);
                }
                if name.eq_ignore_ascii_case("x-bench-token")
                    && value.trim() == "fixed-benchmark-credential"
                {
                    authorized = true;
                }
            }
        }
        let mut body = vec![0; content_length];
        reader.read_exact(&mut body).await?;
        requests.fetch_add(1, Ordering::Relaxed);
        if authorized {
            credentials.fetch_add(1, Ordering::Relaxed);
        }
        let writer = reader.get_mut();
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            response_body.len()
        )
        .into_bytes();
        response.extend_from_slice(&response_body);
        writer.write_all(&response).await?;
        writer.flush().await?;
    }
}

async fn tls_over_connect(
    proxy: std::net::SocketAddr,
    authority: &str,
    root_der: &[u8],
    alpn: &[&[u8]],
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, BenchError> {
    tls_over_connect_with_nodelay(proxy, authority, root_der, alpn, false).await
}

async fn tls_over_connect_with_nodelay(
    proxy: std::net::SocketAddr,
    authority: &str,
    root_der: &[u8],
    alpn: &[&[u8]],
    tcp_nodelay: bool,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, BenchError> {
    let mut stream = TcpStream::connect(proxy).await?;
    if tcp_nodelay {
        stream.set_nodelay(true)?;
    }
    stream
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await?;
    let mut reader = BufReader::new(stream);
    let mut status = String::new();
    reader.read_line(&mut status).await?;
    if !status.starts_with("HTTP/1.1 200") {
        return Err(format!("CONNECT failed: {status:?}").into());
    }
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).await?;
        if header == "\r\n" || header.is_empty() {
            break;
        }
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(root_der.to_vec()))?;
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    let connector = TlsConnector::from(Arc::new(config));
    let tls = connector
        .connect(
            rustls::pki_types::ServerName::try_from("localhost".to_owned())?,
            reader.into_inner(),
        )
        .await?;
    Ok(tls)
}

async fn http1_client(
    proxy: std::net::SocketAddr,
    authority: &str,
    root_der: &[u8],
) -> Result<BufReader<tokio_rustls::client::TlsStream<TcpStream>>, BenchError> {
    Ok(BufReader::new(
        tls_over_connect(proxy, authority, root_der, &[b"http/1.1"]).await?,
    ))
}

async fn http1_client_with_nodelay(
    proxy: std::net::SocketAddr,
    authority: &str,
    root_der: &[u8],
    tcp_nodelay: bool,
) -> Result<BufReader<tokio_rustls::client::TlsStream<TcpStream>>, BenchError> {
    Ok(BufReader::new(
        tls_over_connect_with_nodelay(proxy, authority, root_der, &[b"http/1.1"], tcp_nodelay)
            .await?,
    ))
}

async fn send_http1_request(
    stream: &mut BufReader<tokio_rustls::client::TlsStream<TcpStream>>,
    authority: &str,
    request_body_bytes: usize,
) -> Result<(), BenchError> {
    let body = vec![b'Q'; request_body_bytes];
    let mut request = format!(
        "POST /allowed HTTP/1.1\r\nHost: {authority}\r\nContent-Length: {request_body_bytes}\r\nConnection: keep-alive\r\n\r\n"
    )
    .into_bytes();
    request.extend_from_slice(&body);
    stream.get_mut().write_all(&request).await?;
    stream.get_mut().flush().await?;
    let mut status = String::new();
    stream.read_line(&mut status).await?;
    if !status.starts_with("HTTP/1.1 200") {
        return Err(format!("HTTP/1.1 request failed: {status:?}").into());
    }
    let mut response_length = 0;
    loop {
        let mut header = String::new();
        if stream.read_line(&mut header).await? == 0 || header == "\r\n" {
            break;
        }
        if let Some((name, value)) = header.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            response_length = value.trim().parse::<usize>().unwrap_or(0);
        }
    }
    let mut response = vec![0; response_length];
    stream.read_exact(&mut response).await?;
    Ok(())
}

#[cfg(feature = "backend-hudsucker")]
async fn benchmark_http2(
    output: &BenchOutput,
    proxy: std::net::SocketAddr,
    authority: &str,
    baffle_ca_der: &[u8],
) -> Result<Vec<f64>, BenchError> {
    use hudsucker::{
        Body,
        hyper::{Request, Version, client::conn::http2},
        hyper_util::rt::{TokioExecutor, TokioIo},
    };

    let tls = tls_over_connect(proxy, authority, baffle_ca_der, &[b"h2"]).await?;
    let (mut sender, connection) =
        http2::handshake(TokioExecutor::new(), TokioIo::new(tls)).await?;
    let driver = tokio::spawn(connection);
    let (cpu_before, rss_before) = (cpu_time_us()?, read_rss_kib()?);
    let mut latencies = Vec::with_capacity(TRIALS * MEASURED_REQUESTS);
    for _ in 0..WARMUP_REQUESTS {
        let request = Request::builder()
            .method("GET")
            .version(Version::HTTP_2)
            .uri(format!("https://{authority}/allowed"))
            .header("host", authority)
            .header("x-bench-token", "attacker-value")
            .body(Body::empty())?;
        sender.ready().await?;
        let response = sender.send_request(request).await?;
        if response.status() != hudsucker::hyper::StatusCode::OK {
            return Err(format!("HTTP/2 warm-up returned {}", response.status()).into());
        }
    }
    for trial in 0..TRIALS {
        let started = Instant::now();
        let trial_cpu_before = cpu_time_us()?;
        for request_index in 0..MEASURED_REQUESTS {
            let request = Request::builder()
                .method("GET")
                .version(Version::HTTP_2)
                .uri(format!("https://{authority}/allowed"))
                .header("host", authority)
                .header("x-bench-token", "attacker-value")
                .body(Body::empty())?;
            sender.ready().await?;
            let request_started = Instant::now();
            let response = match sender.send_request(request).await {
                Ok(response) => response,
                Err(error) => {
                    output.row("failure", trial, request_index, "http2", &error.to_string())?;
                    driver.abort();
                    return Err(error.into());
                }
            };
            if response.status() != hudsucker::hyper::StatusCode::OK {
                return Err(format!("HTTP/2 request returned {}", response.status()).into());
            }
            let elapsed = request_started.elapsed();
            latencies.push(elapsed.as_secs_f64() * 1_000.0);
            output.row(
                "latency",
                trial,
                request_index,
                "http2_keepalive_ms",
                &format!("{:.6}", elapsed.as_secs_f64() * 1_000.0),
            )?;
        }
        record_h2_trial(
            output,
            trial,
            &latencies[trial * MEASURED_REQUESTS..],
            started.elapsed(),
        )?;
        output.row(
            "trial",
            trial,
            MEASURED_REQUESTS,
            "http2_process_cpu_us",
            &cpu_time_us()?.saturating_sub(trial_cpu_before).to_string(),
        )?;
    }
    drop(sender);
    driver.abort();
    output.row(
        "meta",
        TRIALS,
        MEASURED_REQUESTS * TRIALS,
        "http2_process_cpu_us",
        &cpu_time_us()?.saturating_sub(cpu_before).to_string(),
    )?;
    output.row(
        "meta",
        TRIALS,
        MEASURED_REQUESTS * TRIALS,
        "http2_process_rss_delta_kib",
        &read_rss_kib()?.saturating_sub(rss_before).to_string(),
    )?;
    Ok(latencies)
}

#[cfg(feature = "backend-rama")]
async fn benchmark_http2(
    output: &BenchOutput,
    proxy: std::net::SocketAddr,
    authority: &str,
    baffle_ca_der: &[u8],
) -> Result<Vec<f64>, BenchError> {
    use rama::http::{Body, Request, Version, core::client::conn::http2};

    let tls = tls_over_connect(proxy, authority, baffle_ca_der, &[b"h2"]).await?;
    let (mut sender, connection) =
        http2::handshake(rama::rt::Executor::default(), rama::ServiceInput::new(tls)).await?;
    let driver = tokio::spawn(connection);
    let (cpu_before, rss_before) = (cpu_time_us()?, read_rss_kib()?);
    let mut latencies = Vec::with_capacity(TRIALS * MEASURED_REQUESTS);
    for _ in 0..WARMUP_REQUESTS {
        let request = Request::builder()
            .method("GET")
            .version(Version::HTTP_2)
            .uri(format!("https://{authority}/allowed"))
            .header("host", authority)
            .header("x-bench-token", "attacker-value")
            .body(Body::empty())?;
        sender.ready().await?;
        let response = sender.send_request(request).await?;
        if response.status() != rama::http::StatusCode::OK {
            return Err(format!("HTTP/2 warm-up returned {}", response.status()).into());
        }
    }
    for trial in 0..TRIALS {
        let started = Instant::now();
        let trial_cpu_before = cpu_time_us()?;
        for request_index in 0..MEASURED_REQUESTS {
            let request = Request::builder()
                .method("GET")
                .version(Version::HTTP_2)
                .uri(format!("https://{authority}/allowed"))
                .header("host", authority)
                .header("x-bench-token", "attacker-value")
                .body(Body::empty())?;
            sender.ready().await?;
            let request_started = Instant::now();
            let response = match sender.send_request(request).await {
                Ok(response) => response,
                Err(error) => {
                    output.row("failure", trial, request_index, "http2", &error.to_string())?;
                    driver.abort();
                    return Err(error.into());
                }
            };
            if response.status() != rama::http::StatusCode::OK {
                return Err(format!("HTTP/2 request returned {}", response.status()).into());
            }
            let elapsed = request_started.elapsed();
            latencies.push(elapsed.as_secs_f64() * 1_000.0);
            output.row(
                "latency",
                trial,
                request_index,
                "http2_keepalive_ms",
                &format!("{:.6}", elapsed.as_secs_f64() * 1_000.0),
            )?;
        }
        record_h2_trial(
            output,
            trial,
            &latencies[trial * MEASURED_REQUESTS..],
            started.elapsed(),
        )?;
        output.row(
            "trial",
            trial,
            MEASURED_REQUESTS,
            "http2_process_cpu_us",
            &cpu_time_us()?.saturating_sub(trial_cpu_before).to_string(),
        )?;
    }
    drop(sender);
    driver.abort();
    output.row(
        "meta",
        TRIALS,
        MEASURED_REQUESTS * TRIALS,
        "http2_process_cpu_us",
        &cpu_time_us()?.saturating_sub(cpu_before).to_string(),
    )?;
    output.row(
        "meta",
        TRIALS,
        MEASURED_REQUESTS * TRIALS,
        "http2_process_rss_delta_kib",
        &read_rss_kib()?.saturating_sub(rss_before).to_string(),
    )?;
    Ok(latencies)
}

fn record_h2_trial(
    output: &BenchOutput,
    trial: usize,
    latencies: &[f64],
    elapsed: Duration,
) -> Result<(), BenchError> {
    output.row(
        "trial",
        trial,
        MEASURED_REQUESTS,
        "http2_median_ms",
        &format!("{:.6}", percentile(latencies, 0.50)),
    )?;
    output.row(
        "trial",
        trial,
        MEASURED_REQUESTS,
        "http2_p95_ms",
        &format!("{:.6}", percentile(latencies, 0.95)),
    )?;
    output.row(
        "trial",
        trial,
        MEASURED_REQUESTS,
        "http2_requests_per_second",
        &format!("{:.3}", MEASURED_REQUESTS as f64 / elapsed.as_secs_f64()),
    )
}

fn read_rss_kib() -> Result<u64, BenchError> {
    let status = fs::read_to_string("/proc/self/status")?;
    let rss = status
        .lines()
        .find(|line| line.starts_with("VmRSS:"))
        .ok_or_else(|| io::Error::other("VmRSS is unavailable"))?;
    Ok(rss
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| io::Error::other("VmRSS has no value"))?
        .parse()?)
}

fn cpu_time_us() -> Result<u64, BenchError> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage initializes the provided rusage record on success.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: the successful getrusage call initialized the record.
    let usage = unsafe { usage.assume_init() };
    let user = usage.ru_utime.tv_sec as u64 * 1_000_000 + usage.ru_utime.tv_usec as u64;
    let system = usage.ru_stime.tv_sec as u64 * 1_000_000 + usage.ru_stime.tv_usec as u64;
    Ok(user + system)
}

fn percentile(samples: &[f64], percentile: f64) -> f64 {
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    sorted[((sorted.len() as f64 * percentile).ceil() as usize)
        .saturating_sub(1)
        .min(sorted.len() - 1)]
}

fn rustc_version() -> String {
    std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_else(|| "unavailable".to_owned())
}

struct BenchOutput {
    path: Option<std::path::PathBuf>,
}

impl BenchOutput {
    fn new() -> Result<Self, BenchError> {
        let path = std::env::var_os("BAFFLE_BENCH_RAW").map(std::path::PathBuf::from);
        if let Some(path) = &path {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            if !path.exists() {
                fs::write(path, "kind,trial,index,metric,value\n")?;
            }
        }
        Ok(Self { path })
    }

    fn row(
        &self,
        kind: &str,
        trial: usize,
        index: usize,
        metric: &str,
        value: &str,
    ) -> Result<(), BenchError> {
        let row = format!("{kind},{trial},{index},{metric},{value}\n");
        if let Some(path) = &self.path {
            use std::io::Write as _;
            let mut output = OpenOptions::new().append(true).open(path)?;
            output.write_all(row.as_bytes())?;
        } else {
            eprint!("{row}");
        }
        Ok(())
    }

    fn summary(&self, metric: &str, values: &[f64]) -> Result<(), BenchError> {
        let median = percentile(values, 0.50);
        let p95 = percentile(values, 0.95);
        self.row(
            "summary",
            0,
            values.len(),
            &format!("{metric}_median"),
            &format!("{median:.6}"),
        )?;
        self.row(
            "summary",
            0,
            values.len(),
            &format!("{metric}_p95"),
            &format!("{p95:.6}"),
        )
    }
}
