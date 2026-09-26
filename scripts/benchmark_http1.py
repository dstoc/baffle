#!/usr/bin/env python3
"""Compare HTTP/1.1 proxy latency across concurrency, TCP_NODELAY, and origins."""

from __future__ import annotations

import argparse
import os
import socket
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "bench" / "fixtures"
CONCURRENCY = (1, 4, 16)
TRIALS = 5
WARMUP_REQUESTS = 16
MEASURED_REQUESTS = 80


class BenchOrigin(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, tcp_nodelay: bool, response_body_bytes: int):
        self.tcp_nodelay = tcp_nodelay
        self.response_body_bytes = response_body_bytes
        self.request_count = 0
        self.authorized_request_count = 0
        self.counter_lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), BenchOriginHandler)

    def get_request(self):
        request, address = super().get_request()
        if self.tcp_nodelay:
            request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return request, address


class BenchOriginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        pass

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(content_length)
        with self.server.counter_lock:
            self.server.request_count += 1
            if self.headers.get("X-Bench-Token") == "fixed-benchmark-credential":
                self.server.authorized_request_count += 1

        body = b"R" * self.server.response_body_bytes
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.write(body)


def run_case(
    backend: str,
    origin_name: str,
    nodelay_mode: str,
    profile: str,
    concurrency_levels: tuple[int, ...],
    request_body_bytes: int,
    response_body_bytes: int,
    result_prefix: str,
) -> None:
    concurrency_suffix = (
        "" if concurrency_levels == CONCURRENCY else "-c" + "-".join(map(str, concurrency_levels))
    )
    output = ROOT / "bench" / "results" / (
        f"{result_prefix}-{backend}-{origin_name}-nodelay-{nodelay_mode}"
        f"-req{request_body_bytes}-resp{response_body_bytes}{concurrency_suffix}.csv"
    )
    output.unlink(missing_ok=True)
    environment = os.environ.copy()
    environment["BAFFLE_BENCH_RAW"] = str(output.relative_to(ROOT))
    environment["BAFFLE_BENCH_TCP_NODELAY"] = nodelay_mode
    environment["BAFFLE_BENCH_CONCURRENCY"] = ",".join(map(str, concurrency_levels))
    environment["BAFFLE_BENCH_REQUEST_BYTES"] = str(request_body_bytes)
    environment["BAFFLE_BENCH_RESPONSE_BYTES"] = str(response_body_bytes)
    environment.pop("BAFFLE_BENCH_ORIGIN_ADDR", None)

    origin: BenchOrigin | None = None
    if origin_name == "python":
        origin = BenchOrigin(
            tcp_nodelay=nodelay_mode in ("origin", "all"),
            response_body_bytes=response_body_bytes,
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(
            certfile=FIXTURES / "origin-leaf.pem",
            keyfile=FIXTURES / "origin-leaf-key.pem",
        )
        origin.socket = context.wrap_socket(origin.socket, server_side=True)
        origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
        origin_thread.start()
        address = f"127.0.0.1:{origin.server_address[1]}"
        environment["BAFFLE_BENCH_ORIGIN_ADDR"] = address

    features = f"backend-{backend}"
    if nodelay_mode != "production":
        features += ",benchmark-tcp-nodelay"
    command = [
        "cargo",
        "test",
        "--locked",
        "--no-default-features",
        "--features",
        features,
        "--lib",
    ]
    if profile == "release":
        command.append("--release")
    command.extend(
        [
            "runtime_http1_characterization",
            "--",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ]
    )

    print(
        f"\n=== {backend}: origin={origin_name}, TCP_NODELAY={nodelay_mode}, "
        f"request={request_body_bytes} bytes, response={response_body_bytes} bytes, "
        f"profile={profile} ===",
        flush=True,
    )
    packets_before = loopback_packet_counts()
    try:
        completed = subprocess.run(command, cwd=ROOT, env=environment, check=False)
        if completed.returncode:
            raise RuntimeError(f"benchmark failed with exit code {completed.returncode}")
        if origin is not None:
            expected_requests = (
                TRIALS
                * sum(concurrency_levels)
                * (WARMUP_REQUESTS + MEASURED_REQUESTS)
            )
            with origin.counter_lock:
                requests = origin.request_count
                authorized = origin.authorized_request_count
            if requests != expected_requests or authorized != expected_requests:
                raise RuntimeError(
                    f"Python origin saw {requests} requests and {authorized} injected credentials; "
                    f"expected {expected_requests} of each"
                )
            print(f"Python origin verified {requests} requests and credentials.", flush=True)
        packets_after = loopback_packet_counts()
        if packets_before is not None and packets_after is not None:
            with output.open("a", encoding="utf-8") as raw:
                raw.write("meta,0,0,loopback_rx_packets_delta,"
                          f"{packets_after[0] - packets_before[0]}\n")
                raw.write("meta,0,0,loopback_tx_packets_delta,"
                          f"{packets_after[1] - packets_before[1]}\n")
        print(f"Raw rows: {output}", flush=True)
    finally:
        if origin is not None:
            origin.shutdown()
            origin.server_close()


def loopback_packet_counts() -> tuple[int, int] | None:
    try:
        statistics = Path("/sys/class/net/lo/statistics")
        return (
            int((statistics / "rx_packets").read_text(encoding="ascii")),
            int((statistics / "tx_packets").read_text(encoding="ascii")),
        )
    except (OSError, ValueError):
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backends", default="hudsucker,rama")
    parser.add_argument("--origins", default="rust,python")
    parser.add_argument("--tcp-nodelay", default="off,all")
    parser.add_argument("--concurrency-levels", default="1,4,16")
    parser.add_argument(
        "--payloads",
        default="4096:32768",
        help="comma-separated request:response byte sizes (for example 4096:32768,1048576:1048576)",
    )
    parser.add_argument("--result-prefix", default="issue33")
    parser.add_argument("--cpu", type=int, default=0)
    parser.add_argument("--profile", choices=("release", "debug"), default="release")
    args = parser.parse_args()

    backends = [value.strip() for value in args.backends.split(",") if value.strip()]
    origins = [value.strip() for value in args.origins.split(",") if value.strip()]
    nodelay_modes = [value.strip() for value in args.tcp_nodelay.split(",") if value.strip()]
    try:
        concurrency_levels = tuple(
            int(value.strip())
            for value in args.concurrency_levels.split(",")
            if value.strip()
        )
    except ValueError:
        parser.error("--concurrency-levels must use 1, 4, and/or 16")
    if (
        not concurrency_levels
        or any(level not in CONCURRENCY for level in concurrency_levels)
        or len(set(concurrency_levels)) != len(concurrency_levels)
    ):
        parser.error("--concurrency-levels must use unique values from 1, 4, and 16")
    if not backends or any(value not in ("hudsucker", "rama") for value in backends):
        parser.error("--backends must contain hudsucker and/or rama")
    if not origins or any(value not in ("rust", "python") for value in origins):
        parser.error("--origins must contain rust and/or python")
    allowed_modes = {
        "production",
        "off",
        "client",
        "proxy-ingress",
        "proxy-egress",
        "origin",
        "all",
    }
    if not nodelay_modes or any(value not in allowed_modes for value in nodelay_modes):
        parser.error(
            "--tcp-nodelay must contain production, off, client, proxy-ingress, proxy-egress, origin, or all"
        )
    payloads = []
    try:
        for pair in args.payloads.split(","):
            request, response = (int(part.strip()) for part in pair.split(":"))
            if not (1 <= request <= 4 * 1024 * 1024 and 1 <= response <= 4 * 1024 * 1024):
                raise ValueError
            payloads.append((request, response))
    except ValueError:
        parser.error("--payloads must contain request:response sizes from 1 to 4194304 bytes")
    if not payloads or len(set(payloads)) != len(payloads):
        parser.error("--payloads must contain unique request:response pairs")
    if not args.result_prefix or any(character in args.result_prefix for character in "/\\"):
        parser.error("--result-prefix must be a nonempty filename prefix")

    if not hasattr(os, "sched_getaffinity") or args.cpu not in os.sched_getaffinity(0):
        parser.error(f"CPU {args.cpu} is not available to this process")
    os.sched_setaffinity(0, {args.cpu})
    os.environ["BAFFLE_BENCH_CPU"] = str(args.cpu)

    for backend in backends:
        for origin_name in origins:
            for mode in nodelay_modes:
                for request_body_bytes, response_body_bytes in payloads:
                    run_case(
                        backend,
                        origin_name,
                        mode,
                        args.profile,
                        concurrency_levels,
                        request_body_bytes,
                        response_body_bytes,
                        args.result_prefix,
                    )


if __name__ == "__main__":
    main()
