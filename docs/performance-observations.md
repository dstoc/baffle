# Session performance observations

The Linux measurement example reports observations. It does not enforce a performance target. Run it against a fresh daemon with no active sessions:

```sh
BAFFLE_CONTROL_SOCKET=/run/baffle/control.sock \
BAFFLE_DAEMON_PID=1234 \
BAFFLE_MEASURE_COUNT=8 \
cargo run --example measure_sessions
```

On 2026-09-25, one local run used Linux `7.0.0-31-generic`, x86_64, an AMD Ryzen 9 5900X host, and Rust `1.98.1`. The daemon and example used Cargo's default development profile. The measurement warmed the daemon with eight sequential create-and-close operations, then measured eight concurrent idle sessions.

| Measure | Observed value |
| --- | ---: |
| Sequential create median | 0.426 ms |
| Sequential create p95 | 0.692 ms |
| Concurrent sessions created | 8 of 8 |
| Concurrent create wall time | 1.507 ms |
| Concurrent create p95 | 1.405 ms |
| Daemon RSS before concurrent idle sessions | 20,696 KiB |
| Daemon RSS with eight idle sessions | 21,104 KiB |
| RSS increase | 408 KiB total; 51 KiB per session |

This is one short run in a development container. It records observed behavior and does not predict production latency or memory use.
