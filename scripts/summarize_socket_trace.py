#!/usr/bin/env python3
"""Summarize TCP read/write calls from a strace -yy -T log."""

from __future__ import annotations

import argparse
import gzip
import re
from collections import defaultdict
from pathlib import Path

SYSCALL = re.compile(
    r"\b(read|write|readv|writev|recvfrom|sendto|recvmsg|sendmsg)\("
    r"\d+<TCP:\[[^]]+\]>.* = (-?\d+)(?: <([0-9.]+)>)?"
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cpu", default="unrecorded")
    args = parser.parse_args()

    stats: dict[str, list[float | int]] = defaultdict(lambda: [0, 0, 0.0, 0, 0.0])
    open_trace = gzip.open if args.trace.suffix == ".gz" else open
    with open_trace(args.trace, "rt", encoding="utf-8", errors="replace") as trace:
        for line in trace:
            match = SYSCALL.search(line)
            if match is None:
                continue
            syscall, result, duration = match.groups()
            result_bytes = max(0, int(result))
            elapsed = float(duration or 0)
            row = stats[syscall]
            row[0] += 1
            row[1] += result_bytes
            row[2] += elapsed
            row[3] += int(elapsed >= 0.001)
            row[4] = max(float(row[4]), elapsed)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as output:
        output.write(
            "backend,cpu_affinity,scope,syscall,calls,bytes,total_ms,"
            "calls_over_1ms,max_ms\n"
        )
        for syscall, row in sorted(stats.items()):
            output.write(
                f"rama,{args.cpu},http1_characterization,tcp_{syscall},"
                f"{int(row[0])},{int(row[1])},{float(row[2]) * 1000:.3f},"
                f"{int(row[3])},{float(row[4]) * 1000:.3f}\n"
            )


if __name__ == "__main__":
    main()
