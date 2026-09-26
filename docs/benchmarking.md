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
were pinned to CPU 0 with `taskset` or `sched_setaffinity`. The repeated build
sweep was pinned to CPU 0 with `CARGO_BUILD_JOBS=1`. The raw build record
includes CPU affinity, Cargo's build-job limit, native tool versions, and the
libclang library path.

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

`benchmark_builds.py` runs three clean/no-op incremental build pairs for each
backend and profile. It alternates the backend order between repeats. The
table shows the median and full range for each build time. The script also
records release binary sizes and distinct package entries in each normal
dependency graph. It removes Cargo's trailing `(*)` repeat-node marker before
it deduplicates package entries.
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
C++ toolchain, and the libclang library for the DNS dependency. This host had
CMake 3.31.6, Debian C++ 14.2.0, and libclang-dev 19 at
`/usr/lib/x86_64-linux-gnu/libclang-19.so.19`. The `clang` command-line driver
was unavailable. The Hudsucker selection does not compile Rama or BoringSSL.
The existing [Rama prototype report](rama-prototype.md) records those
toolchain requirements.

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

Run three paired clean/no-op build samples per backend and profile, with
backend order alternated between repeats. The environment row records CPU 0
affinity and one Cargo build job:

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
`1.98.1`. The benchmark-only `benchmark-tcp-nodelay` feature enables these
socket toggles for the experiment. It does not change the default runtime
socket settings. This investigation does not make a backend migration
decision.

Reproduce the two-origin and all-socket comparison, the one-leg Rama runs, and
the socket profile with:

```sh
python3 scripts/benchmark_http1.py \
  --backends hudsucker,rama --origins rust,python \
  --tcp-nodelay off,all --cpu 0

python3 scripts/benchmark_http1.py \
  --backends rama --origins rust \
  --tcp-nodelay proxy-ingress,proxy-egress --cpu 0

python3 scripts/profile_http1_sockets.py \
  --backends hudsucker,rama --cpu 0
```
