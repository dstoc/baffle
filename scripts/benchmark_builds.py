#!/usr/bin/env python3
"""Collect matched Cargo clean/no-op build and binary/dependency measurements."""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKENDS = {
    "hudsucker": "backend-hudsucker",
    "rama": "backend-rama",
}


def paired_backend_order(backends: list[str], repeat: int) -> list[str]:
    """Alternate paired build order to reduce systematic order bias."""
    return backends if repeat % 2 == 0 else list(reversed(backends))


def unique_dependency_entries(lines: list[str]) -> list[str]:
    """Deduplicate Cargo tree entries after removing its repeat-node marker."""
    return sorted({
        entry
        for line in lines
        if (entry := line.strip().removesuffix(" (*)"))
    })


def command(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True, check=False)
    except FileNotFoundError as error:
        result = subprocess.CompletedProcess(args, 127, "", str(error))
    if check and result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(args)}\n"
            f"stdout:\n{result.stdout[-4000:]}\nstderr:\n{result.stderr[-4000:]}"
        )
    return result


def timed_build(feature: str, release: bool) -> float:
    args = ["cargo", "build", "--locked", "--no-default-features", "--features", feature]
    if release:
        args.append("--release")
    started = time.perf_counter()
    command(args)
    return time.perf_counter() - started


def native_versions() -> dict[str, str]:
    values = {}
    for name, args in {
        "cmake": ["cmake", "--version"],
        "cxx": ["c++", "--version"],
        "clang_driver": ["clang", "--version"],
    }.items():
        result = command(args, check=False)
        values[name] = result.stdout.splitlines()[0] if result.returncode == 0 else "unavailable"
    configured_libclang = os.environ.get("LIBCLANG_PATH")
    libclang_paths = []
    if configured_libclang:
        configured_path = Path(configured_libclang)
        if configured_path.is_dir():
            libclang_paths.extend(configured_path.glob("libclang.so*"))
        elif configured_path.exists():
            libclang_paths.append(configured_path)
    if not libclang_paths:
        libclang_paths.extend(Path("/usr/lib").glob("llvm-*/lib/libclang.so*"))
        libclang_paths.extend(Path("/usr/local/lib").glob("libclang.so*"))
    values["libclang"] = (
        str(sorted(path.resolve() for path in libclang_paths)[-1])
        if libclang_paths
        else "unavailable"
    )
    return values


def cpu_name() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backends", default="hudsucker,rama")
    parser.add_argument("--profiles", default="debug,release")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--output", type=Path, default=Path("bench/results/builds.jsonl"))
    args = parser.parse_args()
    backends = [value.strip() for value in args.backends.split(",")]
    profiles = [value.strip() for value in args.profiles.split(",")]
    if args.repeats < 1 or any(value not in BACKENDS for value in backends):
        parser.error("use positive --repeats and --backends hudsucker,rama")
    if any(value not in {"debug", "release"} for value in profiles):
        parser.error("--profiles accepts debug and release")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as output:
        environment = {
            "kind": "environment",
            "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "uname": platform.platform(),
            "cpu": cpu_name(),
            "cpu_affinity": (
                sorted(os.sched_getaffinity(0))
                if hasattr(os, "sched_getaffinity")
                else "unavailable"
            ),
            "cargo_build_jobs": os.environ.get("CARGO_BUILD_JOBS", "cargo default"),
            "rustc": command(["rustc", "-Vv"]).stdout.strip(),
            "cargo": command(["cargo", "-V"]).stdout.strip(),
            "native_tools": native_versions(),
        }
        output.write(json.dumps(environment, sort_keys=True) + "\n")
        for backend in backends:
            feature = BACKENDS[backend]
            graph = command([
                "cargo", "tree", "--locked", "--no-default-features", "--features", feature,
                "-e", "normal", "--prefix", "none",
            ]).stdout.splitlines()
            dependencies = unique_dependency_entries(graph)
            output.write(json.dumps({
                "kind": "dependency_graph",
                "backend": backend,
                "entries": len(dependencies),
                "values": dependencies,
            }, sort_keys=True) + "\n")
        for profile in profiles:
            release = profile == "release"
            for repeat in range(args.repeats):
                for backend in paired_backend_order(backends, repeat):
                    feature = BACKENDS[backend]
                    command(["cargo", "clean"])
                    clean_seconds = timed_build(feature, release)
                    incremental_seconds = timed_build(feature, release)
                    row = {
                        "kind": "build_sample",
                        "backend": backend,
                        "profile": profile,
                        "repeat": repeat,
                        "clean_seconds": round(clean_seconds, 6),
                        "incremental_noop_seconds": round(incremental_seconds, 6),
                    }
                    if release:
                        binary = ROOT / "target" / "release" / "baffle"
                        row["release_binary_bytes"] = binary.stat().st_size
                    output.write(json.dumps(row, sort_keys=True) + "\n")
                    output.flush()
                    print(json.dumps(row, sort_keys=True), flush=True)
    print(f"wrote raw build measurements to {args.output}")


if __name__ == "__main__":
    main()
