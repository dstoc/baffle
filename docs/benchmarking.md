# Backend benchmark report

## Result

This report compares the Hudsucker and Rama backend selections. Hudsucker
remains the default. The measurements do not support a backend migration
decision on their own.

The clearest result is a repeatable HTTP/1.1 latency difference in the local
release workload. Hudsucker's median request latency was 0.108 ms. Rama's was
41.979 ms. Both used the same pinned TLS fixtures, 4 KiB request body, 32 KiB
response body, path rule, credential injection, CONNECT authority, and
keep-alive pattern. The cause of Rama's delay needs profiling. It may be
sensitive to TCP acknowledgement and buffering behavior on this sequential
loopback workload.

The HTTP/2 medians were 0.088 ms for Hudsucker and 0.114 ms for Rama. The
tunnel-only medians were close in throughput at about 24 requests per second
for both backends. Session provisioning and teardown were also close. Idle RSS
changes were below useful resolution at these session counts.

## Environment and fixtures

The runs used Linux `7.0.0-31-generic`, x86-64, an AMD Ryzen 9 5900X, Rust
1.98.1, and Cargo 1.98.1. Release runtime tests and public-daemon session runs
were pinned to CPU 0 with `taskset` or `sched_setaffinity`. The build sweep was
not CPU-pinned. The raw build record includes the native tool versions that
were available on `PATH`.

Both backend selections used the same fixture certificates. Their SHA-256
fingerprints are in [the fixture README](../bench/fixtures/README.md). The
benchmark starts a local TLS origin on loopback. It uses one intercepted
session with an exact `localhost` host rule, an `/allowed` path rule, and a
fixed injected `X-Bench-Token` credential. The origin verifies that every
intercepted request contains the replacement credential.

The HTTP/1.1 and tunnel workloads warm each connection with 16 requests, then
measure 5 batches of 80 keep-alive requests. Each request has a 4 KiB body and
each response has a 32 KiB body. The HTTP/2 workload uses one TLS connection,
16 warm-up requests, and 5 batches of 80 requests. Its requests have no body
and its responses are empty. The HTTP/2 rows therefore compare request/response
latency and request rate, not bulk transfer throughput.

The runtime benchmark starts `ProxyRuntime` directly inside a single test
process. CPU and active-connection RSS therefore include the client, fixture
origin, and test harness. They are not daemon-only measurements. The separate
session benchmark starts the real daemon and uses the public `baffle-client`
control path.

## Runtime results

The latency and throughput values below are medians of five batches. Ranges
show the minimum and maximum batch result. Each batch contains 80 measured
requests. CPU values are per batch and include its 16 warm-up requests. The
process RSS readings are quantized and include the fixture and client.

| Workload | Hudsucker | Rama |
| --- | ---: | ---: |
| Runtime start median | 0.048 ms | 0.044 ms |
| Runtime stop median | 0.030 ms | 0.026 ms |
| HTTP/1.1 median latency | 0.108 ms (0.107–0.111) | 41.979 ms (40.997–41.987) |
| HTTP/1.1 p95 latency | 0.118 ms (0.115–0.140) | 42.003 ms (41.998–42.979) |
| HTTP/1.1 rate | 8,563 req/s (7,879–8,687) | 24.0 req/s (23.9–24.1) |
| HTTP/1.1 payload rate | 301.0 MiB/s (277.0–305.4) | 0.843 MiB/s (0.842–0.847) |
| HTTP/1.1 process CPU | 9.3 ms (9.2–10.2) | 16.0 ms (14.3–16.9) |
| HTTP/2 median latency | 0.088 ms (0.081–0.098) | 0.114 ms (0.113–0.114) |
| HTTP/2 p95 latency | 0.098 ms (0.096–0.111) | 0.123 ms (0.122–0.124) |
| HTTP/2 rate | 10,226 req/s (9,633–10,760) | 7,840 req/s (7,780–7,857) |
| HTTP/2 process CPU | 7.8 ms (7.4–8.3) | 10.2 ms (10.2–10.3) |
| Tunnel-only HTTP/1.1 rate | 24.1 req/s (24.0–24.3) | 24.3 req/s (24.2–24.3) |
| Tunnel-only payload rate | 0.846 MiB/s (0.844–0.853) | 0.853 MiB/s (0.849–0.855) |

The high Rama HTTP/1.1 latency repeats across all five batches. HTTP/2 and
tunnel-only results do not show the same gap. This suggests that the measured
effect is specific to this sequential HTTP/1.1 path. A second workload with
concurrent clients and an independent origin implementation should test that
inference before anyone uses the result to choose a backend.

## Session lifecycle and resources

The public-daemon benchmark ran five repeats at 1, 2, 4, and 8 sessions. It
measured sequential and simultaneous creation, daemon RSS at idle, four idle
Unix connections per session, and cleanup after each batch.

| Measure | Hudsucker | Rama |
| --- | ---: | ---: |
| Sequential control-path create, median | 0.220 ms | 0.216 ms |
| Eight-session public control-path create wall, median | 1.127 ms | 1.072 ms |
| Eight-session direct runtime start wall, median | 0.447 ms | 0.389 ms |
| Eight-session public control-path teardown, median | 0.864 ms | 0.859 ms |
| Idle RSS delta per session, median | 0 KiB | 0 KiB |

The RSS process reports KiB and did not resolve a stable per-session increase
at these counts. Active connection RSS was also noisy: the median change was
0 KiB per connection for Hudsucker and 0.4 KiB for Rama, with occasional
multi-hundred-KiB allocator jumps. These readings do not establish a memory
advantage. The CSVs retain each raw RSS sample, including zero deltas and
post-teardown changes.

The public control-path driver waited for the session list to become empty
after every stop. No create or connection failures occurred. The direct runtime
benchmark also checked that each session socket disappeared after shutdown.

## Build and binary results

`benchmark_builds.py` runs a clean and a no-op incremental build for each
backend and profile. It also records release binary sizes and distinct normal
dependency graph entries. The raw JSONL file retains the commands' environment
and each sample. See [the benchmark results directory](../bench/results/).

| Profile and measure | Hudsucker | Rama |
| --- | ---: | ---: |
| Clean debug build | 18.59 s | 47.00 s |
| No-op incremental debug build | 0.13 s | 0.17 s |
| Clean release build | 33.61 s | 69.67 s |
| No-op incremental release build | 0.14 s | 0.18 s |
| Release binary size | 14,486,032 bytes | 18,165,256 bytes |
| Normal dependency graph entries | 252 | 358 |

The release binary size gap is 3,679,224 bytes. The Rama build adds 106
distinct normal dependency graph entries. Each build value is one clean/no-op
pair; run the script three times to estimate build-time variation.

Rama 0.4.0 requires Rust 1.96 or newer. Its BoringSSL build needs CMake, a
C++ toolchain, and libclang for the DNS dependency. The Hudsucker selection
does not compile Rama or BoringSSL. The existing [Rama prototype report](rama-prototype.md)
records those toolchain details; this run's raw build record contains the
available CMake and C++ version strings.

## Resilience coverage and limits

The opt-in benchmark does not add load or timing assertions to ordinary
`cargo test`. Normal tests already exercise connection admission, idle bridge
timeouts, stalled and fragmented ClientHello input, cancellation during an
active tunnel or intercepted request, task-failure propagation, socket cleanup,
and repeated session creation and teardown. These are functional checks; they
do not measure leak slopes under a long soak.

An early fixture attempt returned HTTP 502 because its HTTP/1.1 origin also
advertised HTTP/2. The fixture now uses separate ALPN settings for HTTP/1.1
and HTTP/2. The final raw files contain no failed workload samples.

## Reproduction

Run the matched release runtime workload and write raw per-request rows:

```sh
taskset -c 0 env BAFFLE_BENCH_RAW=bench/results/hudsucker-runtime-release.csv \
  cargo test --locked --release --lib --no-default-features \
  --features backend-hudsucker runtime_benchmark -- \
  --ignored --nocapture --test-threads=1

taskset -c 0 env BAFFLE_BENCH_RAW=bench/results/rama-runtime-release.csv \
  cargo test --locked --release --lib --no-default-features \
  --features backend-rama runtime_benchmark -- \
  --ignored --nocapture --test-threads=1
```

Run the real daemon/control-path session workload. It uses the same pinned CA
fixture for both builds:

```sh
python3 scripts/benchmark_sessions.py --profile release --repeats 5 \
  --counts 1,2,4,8 --cpu 0
```

Run clean and no-op incremental builds, dependency counts, and binary-size
checks:

```sh
python3 scripts/benchmark_builds.py --repeats 3
```

These commands are opt-in. They do not run as part of the required checks.
