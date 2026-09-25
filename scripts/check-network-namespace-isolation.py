#!/usr/bin/env python3
"""Verify that a sandbox client cannot reach Baffle's internal TCP listeners."""

import os
import re
import subprocess
import sys
from typing import NoReturn


PROBE = r"""
import socket
import sys
import errno

blocked_errnos = {
    errno.ECONNREFUSED,
    errno.EHOSTUNREACH,
    errno.ENETUNREACH,
    errno.EACCES,
    errno.EPERM,
}

address, port = sys.argv[1], int(sys.argv[2])
family = socket.AF_INET6 if ":" in address else socket.AF_INET
try:
    with socket.socket(family, socket.SOCK_STREAM) as connection:
        connection.settimeout(1.0)
        connection.connect((address, port))
except TimeoutError:
    print(f"TIMEOUT {address}:{port}")
    raise SystemExit(11)
except OSError as error:
    if error.errno not in blocked_errnos:
        print(f"ERROR {address}:{port}: {error}")
        raise SystemExit(12)
    print(f"BLOCKED {address}:{port}: {error}")
    raise SystemExit(10)
else:
    print(f"CONNECTED {address}:{port}")
"""


def fail(message: str) -> NoReturn:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def listener_rows(daemon_pid: int) -> list[tuple[str, int]]:
    result = subprocess.run(
        [
            "nsenter",
            "--target",
            str(daemon_pid),
            "--net",
            "ss",
            "-H",
            "-ltnp",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        fail(f"could not inspect Baffle listeners: {result.stderr.strip()}")

    pid_field = re.compile(rf"\bpid={daemon_pid},")
    listeners = []
    for row in result.stdout.splitlines():
        if not pid_field.search(row):
            continue
        fields = row.split()
        if len(fields) < 4:
            fail(f"could not parse listener row: {row}")
        address, separator, port_text = fields[3].rpartition(":")
        address = address.strip("[]")
        if not separator or not port_text.isdigit():
            fail(f"could not parse listener address: {fields[3]}")
        listeners.append((address, int(port_text)))

    if not listeners:
        fail("no Baffle TCP listeners found; start a session before running this check")
    return listeners


def main() -> None:
    if len(sys.argv) != 3:
        fail(f"usage: {sys.argv[0]} BAFFLE_PID SANDBOX_CLIENT_PID")

    try:
        daemon_pid, client_pid = (int(value) for value in sys.argv[1:])
        daemon_namespace = os.readlink(f"/proc/{daemon_pid}/ns/net")
        client_namespace = os.readlink(f"/proc/{client_pid}/ns/net")
    except (OSError, ValueError) as error:
        fail(f"could not read process network namespaces: {error}")

    if daemon_namespace == client_namespace:
        fail(f"Baffle and client share network namespace {daemon_namespace}")
    print(f"PASS: Baffle {daemon_namespace}; client {client_namespace}")

    listeners = listener_rows(daemon_pid)
    for address, port in listeners:
        if address not in {"127.0.0.1", "::1"}:
            fail(f"Baffle listener {address}:{port} is not bound to loopback")

        result = subprocess.run(
            [
                "nsenter",
                "--target",
                str(client_pid),
                "--net",
                "python3",
                "-c",
                PROBE,
                address,
                str(port),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0 and result.stdout.startswith("CONNECTED "):
            fail(f"client connected to Baffle listener {address}:{port}")
        if result.returncode == 10 and result.stdout.startswith("BLOCKED "):
            print(f"PASS: client cannot reach {address}:{port}")
            continue
        if result.returncode == 11 and result.stdout.startswith("TIMEOUT "):
            fail(f"probe timed out for {address}:{port}; result is inconclusive")
        fail(
            "could not verify listener "
            f"{address}:{port}: {result.stderr.strip() or result.stdout.strip()}"
        )


if __name__ == "__main__":
    main()
