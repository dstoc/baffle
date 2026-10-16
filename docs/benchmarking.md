# Rama benchmarks

Baffle has one supported runtime. These opt-in benchmarks measure that Rama
runtime through its Unix data socket. They do not add timing thresholds to the
required test suite.

The HTTP/1.1 characterization uses a local Rust TLS origin by default. It
measures five trials at 1, 4, and 16 clients. Each client sends 16 warm-up
requests and 80 measured requests per trial. The default request and response
bodies are 4 KiB and 32 KiB. The raw output records request latency, trial
percentiles, request rate, process CPU, and available loopback counters.

Run the release runtime benchmark, which exercises session startup and stop,
HTTP/1.1, HTTP/2, and tunnel traffic:

```sh
taskset -c 0 env BAFFLE_BENCH_RAW=bench/results/rama-runtime-release.csv \
  cargo test --locked --release --lib runtime_benchmark -- \
  --ignored --nocapture --test-threads=1
```

Run the HTTP/1.1 characterization:

```sh
taskset -c 0 env BAFFLE_BENCH_RAW=bench/results/rama-unix-http1.csv \
  cargo test --locked --release --lib runtime_http1_characterization -- \
  --ignored --nocapture --test-threads=1
```

Run the HTTP/1.1 harness against its Rust and Python TLS origins with current
production socket settings and a no-delay control:

```sh
python3 scripts/benchmark_http1.py \
  --origins rust,python --tcp-nodelay production,off \
  --concurrency-levels 1,4,16 --payloads 4096:32768 \
  --result-prefix rama-current --profile release --cpu 0
```

The harness starts the Python origin with the pinned fixture certificate and
checks the injected `X-Bench-Token` value. The optional no-delay controls apply
to outbound TCP and the origin; Baffle accepts client traffic on a Unix socket.

Run the public-daemon session benchmark:

```sh
python3 scripts/benchmark_sessions.py --profile release --repeats 5 \
  --counts 1,2,4,8 --cpu 0
```

Run three clean and no-op incremental build samples per profile. Set
`CARGO_BUILD_JOBS=1` to record a single-job build sweep:

```sh
taskset -c 0 env CARGO_BUILD_JOBS=1 \
  python3 scripts/benchmark_builds.py --repeats 3
```

The scripts write raw files to `bench/results/` by default. Set their output
options to keep separate samples. The recorded environment includes CPU,
toolchain, and benchmark fixture fingerprints. These results describe the
recorded machine and build; they are not release performance targets.
