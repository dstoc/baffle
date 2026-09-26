#!/usr/bin/env python3
"""Run matched session provisioning benchmarks against both local backends."""

from __future__ import annotations

import argparse
import json
import os
import signal
import shutil
import subprocess
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKENDS = {"hudsucker": "backend-hudsucker", "rama": "backend-rama"}


def run(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True, check=False)
    if check and result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(args)}\n"
            f"{result.stdout[-3000:]}\n{result.stderr[-3000:]}"
        )
    return result


def daemon_config(root: Path, cert: Path, key: Path, uid: int) -> Path:
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700, parents=True)
    config = runtime / "daemon.toml"
    config.write_text(
        f"""[daemon]
control_socket = "{runtime / 'control.sock'}"
socket_dir = "{runtime / 'proxies'}"
trusted_operator_uid = {uid}
max_sessions = 64
max_connections_per_session = 128
shutdown_grace_seconds = 2
control_read_timeout_ms = 5000
max_provisioning_requests = 8
connection_timeout_ms = 5000
io_timeout_ms = 30000

[ca]
certificate = "{cert}"
private_key = "{key}"

[secrets]
directory = "{runtime / 'secrets'}"
""",
        encoding="utf-8",
    )
    return config


def wait_for_socket(process: subprocess.Popen[bytes], path: Path, log_path: Path) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"daemon exited with {process.returncode}: {log_path.read_text()[-3000:]}")
        if path.exists():
            return
        time.sleep(0.01)
    raise RuntimeError(f"daemon did not create {path}: {log_path.read_text()[-3000:]}")


def stop_daemon(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)
        raise RuntimeError("daemon did not stop within ten seconds")
    if process.returncode != 0:
        raise RuntimeError(f"daemon exited with status {process.returncode}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backends", default="hudsucker,rama")
    parser.add_argument("--profile", choices=["debug", "release"], default="release")
    parser.add_argument("--repeats", type=int, default=7)
    parser.add_argument("--counts", default="1,2,4,8")
    parser.add_argument("--settle-ms", type=int, default=200)
    parser.add_argument("--cpu", type=int, help="pin all build/runtime processes to this CPU")
    parser.add_argument("--output-dir", type=Path, default=Path("bench/results"))
    args = parser.parse_args()
    backends = [value.strip() for value in args.backends.split(",")]
    counts = [int(value) for value in args.counts.split(",")]
    if args.repeats < 1 or not counts or min(counts) < 1:
        parser.error("repeats and all session counts must be positive")
    if any(backend not in BACKENDS for backend in backends):
        parser.error("--backends accepts hudsucker,rama")
    if args.cpu is not None:
        try:
            os.sched_setaffinity(0, {args.cpu})
        except (AttributeError, OSError) as error:
            parser.error(f"could not pin this Linux process to CPU {args.cpu}: {error}")
    args.output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="baffle-bench-") as temp:
        root = Path(temp)
        fixtures = ROOT / "bench" / "fixtures"
        key = root / "benchmark-ca-key.pem"
        cert = root / "benchmark-ca.pem"
        shutil.copyfile(fixtures / "baffle-ca-key.pem", key)
        shutil.copyfile(fixtures / "baffle-ca.pem", cert)
        key.chmod(0o600)
        fingerprint = run(["openssl", "x509", "-in", str(cert), "-noout", "-fingerprint", "-sha256"]).stdout.strip()
        origin_root_fingerprint = run([
            "openssl", "x509", "-in", str(fixtures / "origin-root.pem"), "-noout", "-fingerprint", "-sha256"
        ]).stdout.strip()
        origin_leaf_fingerprint = run([
            "openssl", "x509", "-in", str(fixtures / "origin-leaf.pem"), "-noout", "-fingerprint", "-sha256"
        ]).stdout.strip()
        metadata = {
            "kind": "environment",
            "uname": run(["uname", "-a"]).stdout.strip(),
            "rustc": run(["rustc", "-Vv"]).stdout.strip(),
            "cargo": run(["cargo", "-V"]).stdout.strip(),
            "profile": args.profile,
            "counts": counts,
            "repeats": args.repeats,
            "settle_ms": args.settle_ms,
            "cpu_affinity": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else "unavailable",
            "ca_sha256": fingerprint,
            "origin_root_sha256": origin_root_fingerprint,
            "origin_leaf_sha256": origin_leaf_fingerprint,
        }
        (args.output_dir / "sessions-environment.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        for backend in backends:
            feature = BACKENDS[backend]
            build = [
                "cargo", "build", "--locked", "--no-default-features", "--features", feature,
                "--bin", "baffle", "--example", "measure_sessions",
            ]
            if args.profile == "release":
                build.append("--release")
            run(build)
            profile_dir = "release" if args.profile == "release" else "debug"
            daemon_bin = ROOT / "target" / profile_dir / "baffle"
            measure_bin = ROOT / "target" / profile_dir / "examples" / "measure_sessions"
            config = daemon_config(root / backend, cert, key, os.getuid())
            log_path = args.output_dir / f"{backend}-daemon.log"
            raw_path = args.output_dir / f"{backend}-sessions.csv"
            log = log_path.open("wb")
            daemon = subprocess.Popen(
                [str(daemon_bin), "daemon", "--config", str(config)],
                cwd=ROOT,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            try:
                control_socket = root / backend / "runtime" / "control.sock"
                wait_for_socket(daemon, control_socket, log_path)
                env = os.environ.copy()
                env.update({
                    "BAFFLE_CONTROL_SOCKET": str(control_socket),
                    "BAFFLE_DAEMON_PID": str(daemon.pid),
                    "BAFFLE_MEASURE_REPEATS": str(args.repeats),
                    "BAFFLE_MEASURE_COUNTS": ",".join(map(str, counts)),
                    "BAFFLE_MEASURE_SETTLE_MS": str(args.settle_ms),
                    "BAFFLE_BENCH_RAW": str(raw_path),
                })
                result = subprocess.run([str(measure_bin)], cwd=ROOT, env=env, text=True, capture_output=True)
                if result.returncode:
                    raise RuntimeError(
                        f"{backend} session benchmark failed:\n{result.stdout[-3000:]}\n{result.stderr[-3000:]}\n"
                        f"daemon log:\n{log_path.read_text()[-3000:]}"
                    )
                print(f"{backend}: wrote {raw_path}", flush=True)
            finally:
                stop_daemon(daemon)
                log.close()


if __name__ == "__main__":
    main()
