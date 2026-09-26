#!/usr/bin/env python3
"""Verify network namespace separation and the absence of Baffle TCP listeners."""

import os
import re
import subprocess
import sys
from typing import NoReturn


def fail(message: str) -> NoReturn:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def parse_listener_rows(daemon_pid: int, output: str) -> list[tuple[str, int]]:
    pid_field = re.compile(rf"\bpid={daemon_pid},")
    listeners = []
    for row in output.splitlines():
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

    return listeners


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
    return parse_listener_rows(daemon_pid, result.stdout)


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
    print(
        "PASS: Baffle and sandbox client use different network namespaces "
        f"({daemon_namespace}; {client_namespace})"
    )

    listeners = listener_rows(daemon_pid)
    if listeners:
        fail(f"Baffle created unexpected TCP listening ports: {listeners}")
    print("PASS: Baffle has no internal TCP listeners")


if __name__ == "__main__":
    main()
