# Runtime benchmark report

## Result

Historical Hudsucker measurements below were collected before baffle/34 made
Rama the only supported runtime. They record past comparisons and do not
describe a current build option. All commands and benchmark scripts now run
Rama only.

Issue 32 measured a 41.979 ms Rama median and a 0.108 ms Hudsucker median on a
Rust-origin HTTP/1.1 keep-alive workload. Issue 33 repeats that workload with
the production Rama ingress setting and a reproducible off control. Rama's
production medians are 0.136, 0.129, and 1.631 ms at 1, 4, and 16 clients.
The off control stays near 41 ms. This confirms that the accepted-socket
setting removes the delay for the Rust-origin workload.

The same production Rama setting does not change the 41 ms result with the
independent Python TLS origin. Hudsucker, Rama production, and the Rama-off
control all measure about 41 ms there. The origin and socket path still affect
the result.

The new HTTP/2 run measures empty requests and responses on one reused TLS
connection. Rama's median is 0.095 ms and Hudsucker's is 0.080 ms. The 1 MiB
HTTP/1.1 transfer has a bimodal Rama latency distribution and wider trial
variation. Its throughput does not show a clear regression, but it is
inconclusive. The small-payload run also records higher Rama process CPU per
request and more host-wide loopback packets than Hudsucker. The detailed
measurements and limits are in the Issue 33 section below.

## Environment and fixtures

The runs used Linux `7.0.0-31-generic`, x86-64, an AMD Ryzen 9 5900X, Rust
1.98.1, and Cargo 1.98.1. Release runtime tests and public-daemon session runs
were pinned to CPU 0 with `taskset` or `sched_setaffinity`. The repeated build
sweep was pinned to CPU 0 with `CARGO_BUILD_JOBS=1`. The raw build record
includes CPU affinity, Cargo's build-job limit, native tool versions, and the
libclang library path.

The historical backend builds used the same fixture certificates. Their SHA-256
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

`benchmark_builds.py` runs clean and no-op incremental builds for the current
Rama runtime in each profile. The table retains historical Hudsucker and Rama
measurements collected before baffle/34. Current runs record the Rama binary
size and dependency graph. The script removes Cargo's trailing `(*)`
repeat-node marker before it deduplicates package entries.
The raw JSONL file retains the environment and every sample. See [the benchmark
results directory](../bench/results/).

| Profile and measure | Hudsucker | Rama |
| --- | ---: | ---: |
| Clean debug build | 128.858 s (128.554–129.812) | 247.856 s (247.693–247.884) |
| No-op incremental debug build | 0.133 s (0.133–0.137) | 0.177 s (0.171–0.180) |
| Clean release build | 248.771 s (242.894–252.562) | 453.861 s (453.819–468.198) |
| No-op incremental release build | 0.135 s (0.134–0.140) | 0.178 s (0.177–0.184) |
| Release binary size | 14,486,344 bytes | 18,165,664 bytes |
| Normal dependency graph package entries | 201 | 273 |

Each build-time cell reports the median of three samples and the minimum and
maximum in parentheses. The release binary size gap is 3,679,320 bytes. The
Rama graph adds 72 package entries. These build
times use one CPU and one Cargo job; they describe this pinned runner setup and
should not be read as multi-core developer workstation times.

Rama 0.4.0 requires Rust 1.96 or newer. Its BoringSSL build needs CMake, a
C++ toolchain, and the libclang library for the DNS dependency. The source-build
requirements are documented in the [runtime migration note](runtime-migration.md).

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

Run the release Rama runtime workload and write raw per-request rows:

```sh
taskset -c 0 env BAFFLE_BENCH_RAW=bench/results/rama-runtime-release.csv \
  cargo test --locked --release --lib runtime_benchmark -- \
  --ignored --nocapture --test-threads=1
```

Run the real daemon/control-path session workload:

```sh
python3 scripts/benchmark_sessions.py --profile release --repeats 5 \
  --counts 1,2,4,8 --cpu 0
```

Run three clean/no-op build samples per profile. The environment row records
CPU affinity and Cargo build jobs:

```sh
taskset -c 0 env CARGO_BUILD_JOBS=1 \
  python3 scripts/benchmark_builds.py --repeats 3
```

These commands are opt-in. They do not run as part of the required checks.

## Issue 32: HTTP/1.1 latency follow-up

The earlier sequential release samples remain in
[`hudsucker-runtime-release.csv`](../bench/results/hudsucker-runtime-release.csv)
and [`rama-runtime-release.csv`](../bench/results/rama-runtime-release.csv).
The follow-up writes separate raw request and trial rows to files named
`issue32-*.csv` in the [results directory](../bench/results/).

`benchmark_http1.py` runs five trials at 1, 4, and 16 concurrent clients. Each
client warms one keep-alive TLS connection with 16 requests, then sends 80
measured requests per trial. The request and response bodies match the earlier
benchmark: 4 KiB and 32 KiB. The script pins the test, client, and local origin
to CPU 0. It records the backend, origin, `TCP_NODELAY` mode, CPU, Rust version,
request latencies, trial percentiles, wall time, and request rate.

The `rust` origin is the in-process TLS server used by the earlier benchmark.
The `python` origin is an independent Python standard-library HTTPS server. It
uses the same pinned certificate, returns the same response body, and checks
that the proxy injected the benchmark credential. Each Python-origin run
verified all 10,080 warm-up and measured requests.

The table reports median and p95 request latency across all five trials. The
`all` mode enables `TCP_NODELAY` on the client, proxy accepted socket, proxy
outbound socket, and origin accepted socket. `proxy-ingress` and `proxy-egress`
enable it on only the named Rama socket leg.

| Backend | Origin | `TCP_NODELAY` | 1 client, median / p95 | 4 clients, median / p95 | 16 clients, median / p95 |
| --- | --- | --- | ---: | ---: | ---: |
| Hudsucker | Rust | off | 0.148 / 0.171 ms | 0.149 / 0.678 ms | 1.363 / 2.196 ms |
| Hudsucker | Rust | all | 0.108 / 0.127 ms | 0.114 / 0.420 ms | 1.365 / 1.765 ms |
| Hudsucker | Python | off | 41.012 / 42.013 ms | 41.163 / 42.397 ms | 41.609 / 43.871 ms |
| Hudsucker | Python | all | 0.226 / 0.301 ms | 0.732 / 1.276 ms | 2.711 / 5.394 ms |
| Rama | Rust | off | 41.987 / 42.015 ms | 41.073 / 42.427 ms | 41.032 / 42.292 ms |
| Rama | Rust | all | 0.142 / 0.213 ms | 0.129 / 0.472 ms | 1.707 / 2.268 ms |
| Rama | Rust | proxy-ingress | 0.152 / 0.265 ms | 0.137 / 0.487 ms | 1.723 / 2.147 ms |
| Rama | Rust | proxy-egress | 41.003 / 42.006 ms | 41.009 / 42.020 ms | 41.015 / 42.266 ms |
| Rama | Python | off | 41.005 / 42.015 ms | 41.042 / 42.150 ms | 41.691 / 43.465 ms |
| Rama | Python | all | 0.274 / 0.313 ms | 0.782 / 1.442 ms | 2.778 / 5.355 ms |

The original Rama result reproduces against the Rust origin at all three client
counts. Its per-request median stays near 41 ms while throughput increases from
about 24 to 96 to 385 requests per second. Hudsucker stays below 1.4 ms against
the same origin. The independent Python origin produces a roughly 41 ms result
for both backends when `TCP_NODELAY` is off. This shows that the result depends
on the origin and socket path as well as the backend.

On the original Rama/Rust-origin workload, enabling `TCP_NODELAY` only on
Rama’s accepted client socket is sufficient to reduce the median to 0.14–1.72
ms across the tested client counts. Enabling it only on Rama’s outbound origin
socket leaves the median near 41 ms. The Python-origin runs did not isolate
each socket leg, so they do not identify which leg produces their delay. The
16-client measurements also do not identify the component that limits this
single-CPU workload.

The socket profile uses `strace -T` on the HTTP/1.1 characterization. The CSVs
record call counts, returned bytes, and syscall durations by TCP read/write
call. Times below are summed syscall durations across the full characterization
and its 10,080 warm-up and measured requests.

| Backend | `recvfrom`: calls / bytes / time | `sendto`: calls / bytes / time | `writev`: calls / bytes / time | Longest call |
| --- | --- | --- | --- | ---: |
| Rama | 120,671 / 433.8 MB / 1.484 s | 27,487 / 233.6 MB / 0.588 s | 14,713 / 282.0 MB / 0.330 s | 3.222 ms; 9 calls over 1 ms |
| Hudsucker | 11,965 / 55.8 MB / 0.189 s | 32 / 1.9 KB / 1.438 ms | 3,044 / 54.4 MB / 0.081 s | 0.109 ms; none over 1 ms |

No single socket call accounts for the roughly 42 ms request latency. These
traced durations include `strace` overhead and are diagnostic; use the
untraced CSVs for latency.

The runner was Linux `7.0.0-31-generic`, x86-64, an AMD Ryzen 9 5900X, and Rust
`1.98.1`. These Issue 32 rows are diagnostic measurements from before the
production Rama ingress change. The `benchmark-tcp-nodelay` feature enabled
socket toggles for that experiment. It did not change the production socket
settings at that revision. This investigation does not make a backend
migration decision.

Reproduce the two-origin and all-socket comparison, the one-leg Rama runs, and
the socket profile with:

```sh
python3 scripts/benchmark_http1.py \
  --origins rust,python \
  --tcp-nodelay off,all --result-prefix issue32 --cpu 0

python3 scripts/benchmark_http1.py \
  --origins rust \
  --tcp-nodelay proxy-ingress,proxy-egress --result-prefix issue32 --cpu 0

python3 scripts/profile_http1_sockets.py --cpu 0
```

## Issue 33: production Rama ingress behavior

Rama now enables `TCP_NODELAY` on every accepted client-facing TCP socket in
normal builds. The setting applies before CONNECT parsing, TLS peeking, or HTTP
handling. The `benchmark-tcp-nodelay` feature remains opt-in. It supports an
explicit `off` control for repeatable comparisons; compiling that feature does
not turn the production ingress setting off by default.

The `production` benchmark mode builds without the diagnostic feature. It
measures Rama with the production ingress setting. The `off` mode enables the
diagnostic feature and explicitly disables the Rama ingress setting. The current
`runtime_http1_characterization` test uses the same TLS proxy policy,
credential injection, CONNECT authority, keep-alive pattern, and payload sizes
across these modes.

The characterization measures five trials at 1, 4, and 16 HTTP/1.1 clients.
Each client warms its keep-alive connection with 16 requests and sends 80
measured requests per trial. Use `--payloads 4096:32768` for the Issue 32
payload pair. Use `--payloads 1048576:1048576` for a 1 MiB request and response
transfer. Each raw file records request latency, median, p95, request rate,
payload throughput, and process CPU per trial. It also records loopback packet
deltas when Linux exposes the interface counters. Those counters are host
wide, so other loopback traffic can affect them. Process CPU includes the
client, proxy runtime, and in-process Rust origin. It is not daemon-only CPU.

Run matched production-mode HTTP/1.1 measurements against the Rust TLS origin:

```sh
python3 scripts/benchmark_http1.py \
  --origins rust --tcp-nodelay production \
  --payloads 4096:32768 --concurrency-levels 1,4,16 \
  --result-prefix issue33-production --cpu 0

python3 scripts/benchmark_http1.py \
  --origins rust --tcp-nodelay production \
  --payloads 1048576:1048576 --concurrency-levels 1 \
  --result-prefix issue33-bulk-production --cpu 0
```

Run Rama's reproducible `TCP_NODELAY`-off control with the same workloads:

```sh
python3 scripts/benchmark_http1.py \
  --origins rust --tcp-nodelay off \
  --payloads 4096:32768 --concurrency-levels 1,4,16 \
  --result-prefix issue33-control --cpu 0

python3 scripts/benchmark_http1.py \
  --origins rust --tcp-nodelay off \
  --payloads 1048576:1048576 --concurrency-levels 1 \
  --result-prefix issue33-bulk-control --cpu 0
```

Run `runtime_benchmark` for sequential HTTP/1.1 and HTTP/2 results. Its HTTP/1.1
requests use the original 4 KiB request and 32 KiB response. Its HTTP/2
requests and responses are empty and reuse one TLS connection. HTTP/2 results
therefore describe request-path latency and rate, not bulk transfer speed.

```sh
taskset -c 0 env BAFFLE_BENCH_RAW=bench/results/issue33-rama-runtime.csv \
  cargo test --locked --release --lib runtime_benchmark -- \
  --ignored --nocapture --test-threads=1
```

### Issue 33 measurements on `ld-cladding`

The runs used Linux `7.0.0-31-generic`, x86-64, an AMD Ryzen 9 5900X, Rust
`1.98.1`, and CPU 0 affinity. The HTTP/1.1 characterization used five trials.
Each trial measured 80 requests per client after 16 warm-up requests. The
request and response bodies were 4 KiB and 32 KiB. The table reports the
median and p95 across measured requests, median trial request rate, and median
process CPU per request. Process CPU includes the client, proxy runtime, and
Rust origin in the same test process.

| Clients | Hudsucker median / p95 | Hudsucker req/s | Hudsucker CPU/request | Rama median / p95 | Rama req/s | Rama CPU/request |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0.106 / 0.136 ms | 8,658 | 0.116 ms | 0.136 / 0.238 ms | 6,005 | 0.167 ms |
| 4 | 0.107 / 0.427 ms | 8,999 | 0.111 ms | 0.129 / 0.481 ms | 7,502 | 0.133 ms |
| 16 | 1.433 / 1.858 ms | 8,894 | 0.112 ms | 1.631 / 2.072 ms | 7,985 | 0.125 ms |

The Rama-off control measured 41.002 / 42.011 ms, 41.068 / 42.425 ms, and
41.725 / 42.876 ms at 1, 4, and 16 clients. Its median rates were 24, 97, and
384 requests per second. The production setting reduces the median by more
than 99% in this workload. Rama's request rate remains 10–31% below Hudsucker
in these runs, and its process CPU per request is 12–44% higher. These are
backend comparisons from one runner; they do not isolate CPU use by the socket
option.

The host-wide loopback counter recorded 93,355 packets for the combined Rama
production run, 84,641 for the Rama-off control, and 43,976 for Hudsucker.
The counter is not per socket and does not classify packet sizes. Background
loopback traffic can affect it. It indicates a packet-count increase after
the setting, but does not show how many additional packets were small TCP
segments.

The HTTP/2 runtime benchmark used one reused TLS connection with empty request
and response bodies. It ran five 80-request trials after a 16-request warm-up.

| Backend | Median / p95 latency | Median request rate | Median process CPU per trial |
| --- | ---: | ---: | ---: |
| Hudsucker | 0.080 / 0.093 ms | 11,038 req/s | 7.26 ms |
| Rama production | 0.095 / 0.110 ms | 9,385 req/s | 8.54 ms |

For bulk transfer, the harness sent a 1 MiB request and received a 1 MiB
response on one reused HTTP/1.1 connection. It measured 80 requests in each of
five trials.

| Backend and setting | Median / p95 request latency | Median trial rate | Median payload rate | Median process CPU per trial | Loopback packets |
| --- | ---: | ---: | ---: | ---: | ---: |
| Hudsucker production | 44.126 / 46.204 ms | 35.5 req/s | 71.1 MiB/s | 290.6 ms | 67,379 |
| Rama production | 6.306 / 47.873 ms | 37.9 req/s | 75.7 MiB/s | 379.8 ms | 90,285 |
| Rama off control | 45.045 / 86.643 ms | 24.3 req/s | 48.6 MiB/s | 371.5 ms | 68,506 |

The Rama production bulk latencies were bimodal: 200 of 400 measured
requests completed below 10 ms and 200 took more than 40 ms. The trial rate
varied from 35.0 to 46.8 requests per second. The p95 was close to Hudsucker's,
but the changing median and loopback packet count make this bulk run
inconclusive. The off control had lower throughput and a higher p95. Issue
baffle/35 tracks a follow-up with per-flow packet capture, process-level CPU
accounting, and a repeat under lower host noise. Do not claim throughput or
packet-size parity until those measurements explain the differences.

The Python TLS origin check measured a 41.015 / 42.013 ms Hudsucker median / p95,
41.019 / 42.019 ms for Rama production, and 41.032 / 42.034 ms for the Rama-off
control. The origin verified all 480 requests and injected credentials in each
run. Enabling `TCP_NODELAY` on Rama ingress alone did not remove this Python
origin delay. The Issue 32 `all` mode also changed the client, outbound proxy,
and origin sockets, so those results are not an equivalent comparison.

Raw Issue 33 rows are in the [benchmark results directory](../bench/results/):

- [Hudsucker small-payload HTTP/1.1](../bench/results/issue33-hudsucker-production-hudsucker-rust-nodelay-production-req4096-resp32768.csv)
- [Rama production small-payload HTTP/1.1](../bench/results/issue33-rama-production-rama-rust-nodelay-production-req4096-resp32768.csv)
- [Rama-off small-payload HTTP/1.1](../bench/results/issue33-rama-control-rama-rust-nodelay-off-req4096-resp32768.csv)
- 1 MiB transfers: [Hudsucker](../bench/results/issue33-bulk-production-hudsucker-rust-nodelay-production-req1048576-resp1048576-c1.csv), [Rama production](../bench/results/issue33-bulk-production-rama-rust-nodelay-production-req1048576-resp1048576-c1.csv), and [Rama off](../bench/results/issue33-bulk-control-rama-rust-nodelay-off-req1048576-resp1048576-c1.csv)
- [Hudsucker HTTP/2 and sequential HTTP/1.1](../bench/results/issue33-hudsucker-runtime.csv)
- [Rama HTTP/2 and sequential HTTP/1.1](../bench/results/issue33-rama-runtime.csv)
- Python-origin runs: [Hudsucker production](../bench/results/issue33-python-production-hudsucker-python-nodelay-production-req4096-resp32768-c1.csv), [Rama production](../bench/results/issue33-python-production-rama-python-nodelay-production-req4096-resp32768-c1.csv), and [Rama off](../bench/results/issue33-python-control-rama-python-nodelay-off-req4096-resp32768-c1.csv)

The timing benchmarks remain opt-in. They do not add thresholds to the
required `Format, lint, and test` CI check.
