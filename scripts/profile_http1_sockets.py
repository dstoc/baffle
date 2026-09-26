#!/usr/bin/env python3
"""Run the HTTP/1.1 characterization under strace and retain a socket profile."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TRACE_SYSCALLS = "read,write,readv,writev,recvfrom,sendto,recvmsg,sendmsg"
CPU = 0


def test_binary() -> Path:
    command = [
        "cargo",
        "test",
        "--locked",
        "--release",
        "--features",
        "benchmark-tcp-nodelay",
        "--lib",
        "runtime_http1_characterization",
        "--no-run",
        "--message-format=json",
    ]
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError(f"build failed:\n{result.stdout[-4000:]}\n{result.stderr[-4000:]}")

    for line in result.stdout.splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            message.get("reason") == "compiler-artifact"
            and message.get("target", {}).get("name") == "baffle_proxy"
            and message.get("executable")
        ):
            return Path(message["executable"])
    raise RuntimeError("Cargo did not report the baffle-proxy test executable")


def run() -> None:
    binary = test_binary()
    stem = "issue32-rama-http1-socket"
    summary_output = ROOT / "bench" / "results" / f"{stem}-profile.csv"
    environment = os.environ.copy()
    environment["BAFFLE_BENCH_TCP_NODELAY"] = "off"
    environment.pop("BAFFLE_BENCH_ORIGIN_ADDR", None)
    environment["BAFFLE_BENCH_CPU"] = str(CPU)

    with tempfile.TemporaryDirectory(prefix="baffle-issue32-profile-") as temporary:
        temporary_path = Path(temporary)
        raw_trace = temporary_path / "socket-trace.txt"
        environment["BAFFLE_BENCH_RAW"] = str(temporary_path / "workload.csv")
        command = [
            "strace",
            "-f",
            "-tt",
            "-T",
            "-yy",
            "-s",
            "24",
            "-e",
            f"trace={TRACE_SYSCALLS}",
            "-o",
            str(raw_trace),
            str(binary),
            "runtime_http1_characterization",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ]
        print("Tracing Rama HTTP/1.1 sockets under strace...", flush=True)
        subprocess.run(command, cwd=ROOT, env=environment, check=True)
        subprocess.run(
            [
                "python3",
                str(ROOT / "scripts" / "summarize_socket_trace.py"),
                "--cpu",
                str(CPU),
                "--trace",
                str(raw_trace),
                "--output",
                str(summary_output),
            ],
            cwd=ROOT,
            check=True,
        )
    print(f"Summary: {summary_output}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpu", type=int, default=0)
    args = parser.parse_args()
    if not hasattr(os, "sched_getaffinity") or args.cpu not in os.sched_getaffinity(0):
        parser.error(f"CPU {args.cpu} is not available to this process")
    os.sched_setaffinity(0, {args.cpu})
    global CPU
    CPU = args.cpu
    run()


if __name__ == "__main__":
    main()
