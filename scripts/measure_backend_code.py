#!/usr/bin/env python3
"""Count Baffle Rust code and tests by explicit backend ownership.

The counter treats blank lines and Rust line/block comments as non-code. It
counts string-literal lines as code and removes cfg(test) items from production
counts. The file manifest below is the complete scope; examples, documentation,
fixtures, generated files, and unlisted Rust files are excluded.
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path


CORE_FILES = (
    "src/cli.rs",
    "src/config.rs",
    "src/control.rs",
    "src/daemon.rs",
    "src/lib.rs",
    "src/main.rs",
    "src/secrets.rs",
    "src/telemetry.rs",
    "crates/baffle-client/src/lib.rs",
)
SHARED_FILES = (
    "src/proxy_runtime.rs",
    "src/policy.rs",
    "src/ca.rs",
)
HUDSUCKER_FILES = ("src/proxy_runtime/hudsucker.rs",)
RAMA_FILES = ("src/proxy_runtime/rama.rs",)
HUDSUCKER_EXTERNAL_TESTS = (
    "tests/client.rs",
    "tests/control_protocol.rs",
    "tests/daemon_lifecycle.rs",
    "tests/proxy_runtime.rs",
)
SHARED_EXTERNAL_TESTS = ("tests/documentation.rs",)
VENDOR_PREFIX = "vendor/hudsucker/src/"
UPSTREAM_REVISION = "631fa972a4eb1428c52de2ebeab700bc39ea380c"

CATEGORIES = {
    "Backend-neutral Baffle core": CORE_FILES,
    "Shared adapters and policy abstractions": SHARED_FILES,
    "Hudsucker adapter/runtime": HUDSUCKER_FILES,
    "Rama adapter/runtime": RAMA_FILES,
}


def mask_rust(text: str) -> list[str]:
    """Mask comments and string contents while preserving line boundaries.

    A non-whitespace marker remains at each string's opening delimiter so a
    line containing only a string literal still counts as code. The mask is
    used for Rust line classification and brace matching, not compilation.
    """
    out: list[str] = []
    i = 0
    state = "normal"
    block_depth = 0
    raw_end = ""
    escaped = False
    line: list[str] = []

    def blank(ch: str) -> str:
        return "\n" if ch == "\n" else " "

    def char_literal_end(start: int) -> int | None:
        # Rust character literals are short; lifetimes have no closing quote.
        j = start + 1
        if j >= len(text) or text[j] == "\n":
            return None
        if text[j] == "\\":
            j += 2
        else:
            j += 1
        if j < len(text) and text[j] == "'":
            return j
        return None

    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if state == "line_comment":
            line.append(blank(ch))
            if ch == "\n":
                state = "normal"
        elif state == "block_comment":
            if ch == "/" and nxt == "*":
                line.extend((" ", " "))
                block_depth += 1
                i += 1
            elif ch == "*" and nxt == "/":
                line.extend((" ", " "))
                block_depth -= 1
                i += 1
                if block_depth == 0:
                    state = "normal"
            else:
                line.append(blank(ch))
        elif state == "string":
            line.append(blank(ch))
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                state = "normal"
        elif state == "raw_string":
            if text.startswith(raw_end, i):
                if not line:
                    line.append("S")
                line.extend(" " for _ in raw_end)
                i += len(raw_end) - 1
                state = "normal"
            else:
                if not line:
                    line.append("S")
                line.append(blank(ch))
        else:
            # Detect raw and byte-raw string openers before ordinary tokens.
            raw_start = None
            if ch == "r" or (ch == "b" and nxt == "r"):
                raw_start = i + (1 if ch == "r" else 2)
            if raw_start is not None and raw_start < len(text):
                j = raw_start
                while j < len(text) and text[j] == "#":
                    j += 1
                if j < len(text) and text[j] == '"':
                    hashes = text[raw_start:j]
                    line.append("S")
                    while i < j:
                        i += 1
                    raw_end = '"' + hashes
                    state = "raw_string"
            if state == "raw_string":
                pass
            elif ch == "/" and nxt == "/":
                line.extend((" ", " "))
                i += 1
                state = "line_comment"
            elif ch == "/" and nxt == "*":
                line.extend((" ", " "))
                i += 1
                block_depth = 1
                state = "block_comment"
            elif ch == '"':
                line.append("S")
                state = "string"
                escaped = False
            elif ch == "'" and char_literal_end(i) is not None:
                end = char_literal_end(i)
                line.append("S")
                while i < end:
                    i += 1
                line.append(" ")
            else:
                line.append(ch)

        if ch == "\n":
            out.append("".join(line))
            line = []
        i += 1

    if line:
        out.append("".join(line))
    return out


def line_kinds(text: str) -> tuple[int, int, int]:
    """Return (code, comment, blank) line counts for Rust text."""
    masked = mask_rust(text)
    original = text.splitlines()
    code = comment = blank = 0
    in_comment = False
    for index, visible in enumerate(masked):
        if not visible.strip():
            # A masked nonblank original line is a comment unless it is blank.
            if index < len(original) and original[index].strip():
                comment += 1
            else:
                blank += 1
        else:
            code += 1
    return code, comment, blank


def test_item_spans(text: str) -> list[tuple[int, int, str]]:
    """Return 0-based inclusive/exclusive spans for items gated by cfg(test)."""
    original_lines = text.splitlines()
    masked = mask_rust(text)
    spans: list[tuple[int, int, str]] = []
    cfg_pattern = re.compile(r"#\s*\[\s*cfg\([^]]*\btest\b[^]]*\)\s*\]")
    for start, line in enumerate(masked):
        match = cfg_pattern.search(line)
        if not match:
            continue
        item_end = start + 1
        depth = 0
        opened = False
        for index in range(start + 1, len(masked)):
            current = masked[index]
            for ch in current:
                if ch == "{":
                    depth += 1
                    opened = True
                elif ch == "}" and opened:
                    depth -= 1
                    if depth == 0:
                        item_end = index + 1
                        break
            else:
                if not opened and ";" in current:
                    item_end = index + 1
                    break
                continue
            break
        else:
            item_end = len(masked)
        if item_end == start + 1:
            item_end = min(start + 2, len(masked))
        cfg = original_lines[start]
        spans.append((start, item_end, cfg))

    # Nested cfg(test) items inside a test module collapse to one region.
    spans.sort()
    merged: list[tuple[int, int, str]] = []
    for start, end, cfg in spans:
        if merged and start < merged[-1][1]:
            old_start, old_end, old_cfg = merged[-1]
            merged[-1] = (old_start, max(old_end, end), old_cfg)
        else:
            merged.append((start, end, cfg))
    return merged


def kinds_without_spans(text: str, spans: list[tuple[int, int, str]]) -> tuple[int, int, int]:
    lines = text.splitlines(keepends=True)
    excluded = {line for start, end, _ in spans for line in range(start, end)}
    kept = "".join(value for index, value in enumerate(lines) if index not in excluded)
    return line_kinds(kept)


def kinds_in_spans(text: str, spans: list[tuple[int, int, str]]) -> tuple[int, int, int]:
    lines = text.splitlines(keepends=True)
    selected = {line for start, end, _ in spans for line in range(start, end)}
    kept = "".join(value for index, value in enumerate(lines) if index in selected)
    return line_kinds(kept)


def source_text(revision: str, path: str) -> str:
    return subprocess.run(
        ["git", "show", f"{revision}:{path}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def in_revision(revision: str, path: str) -> bool:
    return subprocess.run(
        ["git", "cat-file", "-e", f"{revision}:{path}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0


def rust_structure(text: str, spans: list[tuple[int, int, str]]) -> tuple[int, int]:
    lines = text.splitlines(keepends=True)
    excluded = {line for start, end, _ in spans for line in range(start, end)}
    production = "".join(value for index, value in enumerate(lines) if index not in excluded)
    masked = mask_rust(production)
    function = re.compile(
        r"^\s*(?:(?:pub(?:\([^)]*\))?|async|unsafe|const|extern\s+\"[^\"]+\")\s+)*fn\s+[A-Za-z_][A-Za-z_0-9]*\b"
    )
    module = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+[A-Za-z_][A-Za-z_0-9]*\b")
    return sum(bool(function.search(line)) for line in masked), sum(bool(module.search(line)) for line in masked)


def vendor_paths(revision: str) -> list[str]:
    raw = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", revision, VENDOR_PREFIX],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [path for path in raw.splitlines() if path.endswith(".rs")]


def revision_file_map(revision: str, paths: list[str]) -> dict[str, str]:
    return {path.removeprefix(VENDOR_PREFIX): source_text(revision, path) for path in paths}


def directory_file_map(directory: Path) -> dict[str, str]:
    return {
        path.relative_to(directory).as_posix(): path.read_text()
        for path in sorted(directory.rglob("*.rs"))
    }


def vendor_change_counts(old: dict[str, str], new: dict[str, str]) -> tuple[int, int, int]:
    added = removed = changed_files = 0
    for path in sorted(set(old) | set(new)):
        before = old.get(path, "").splitlines()
        after = new.get(path, "").splitlines()
        if before != after:
            changed_files += 1
        for op, i1, i2, j1, j2 in difflib.SequenceMatcher(a=before, b=after, autojunk=False).get_opcodes():
            if op in ("replace", "delete"):
                removed += i2 - i1
            if op in ("replace", "insert"):
                added += j2 - j1
    return added, removed, changed_files


def count_project(revision: str) -> dict:
    totals = {name: [0, 0, 0, 0, 0] for name in CATEGORIES}
    tests = defaultdict(lambda: [0, 0, 0])
    for category, paths in CATEGORIES.items():
        for path in paths:
            if not in_revision(revision, path):
                continue
            text = source_text(revision, path)
            spans = test_item_spans(text)
            code, comments, blanks = kinds_without_spans(text, spans)
            functions, modules = rust_structure(text, spans)
            row = totals[category]
            row[0] += code
            row[1] += comments
            row[2] += blanks
            row[3] += functions
            row[4] += modules
            test_code, test_comments, test_blanks = kinds_in_spans(text, spans)
            if test_code or test_comments or test_blanks:
                cfg = " ".join(item[2] for item in spans)
                if path in HUDSUCKER_FILES:
                    target = "Hudsucker adapter unit tests"
                elif path in RAMA_FILES:
                    target = "Rama-specific unit tests"
                elif "backend-hudsucker" in cfg:
                    target = "Hudsucker-specific shared-policy/CA/control unit tests"
                else:
                    target = "Backend-neutral unit tests"
                for index, value in enumerate((test_code, test_comments, test_blanks)):
                    tests[target][index] += value

    external_files = []
    for group, paths in (
        ("Hudsucker-gated external integration tests", HUDSUCKER_EXTERNAL_TESTS),
        ("Backend-neutral external documentation tests", SHARED_EXTERNAL_TESTS),
    ):
        code_total = comments_total = blanks_total = 0
        for path in paths:
            if not in_revision(revision, path):
                continue
            text = source_text(revision, path)
            code, comments, blanks = line_kinds(text)
            code_total += code
            comments_total += comments
            blanks_total += blanks
            external_files.append(path)
        tests[group] = [code_total, comments_total, blanks_total]

    return {
        "revision": revision,
        "source": {
            name: {
                "code": row[0],
                "comments": row[1],
                "blank": row[2],
                "functions": row[3],
                "modules": row[4],
            }
            for name, row in totals.items()
        },
        "tests": {
            name: {"code": row[0], "comments": row[1], "blank": row[2]}
            for name, row in sorted(tests.items())
        },
        "test_files": external_files,
        "vendor_paths": vendor_paths(revision),
    }


def count_vendor(revision: str, upstream_src: Path) -> dict:
    vendored_paths = vendor_paths(revision)
    vendored = revision_file_map(revision, vendored_paths)
    upstream = directory_file_map(upstream_src)
    vendored_code = sum(line_kinds(text)[0] for text in vendored.values())
    upstream_code = sum(line_kinds(text)[0] for text in upstream.values())
    added, removed, changed_files = vendor_change_counts(upstream, vendored)
    return {
        "upstream_git_revision": UPSTREAM_REVISION,
        "source_files_upstream": len(upstream),
        "source_files_vendored": len(vendored),
        "upstream_source_code_loc": upstream_code,
        "vendored_source_code_loc": vendored_code,
        "patch_added_lines": added,
        "patch_removed_lines": removed,
        "patch_changed_files": changed_files,
        "patch_test_code_loc": 0,
    }


def markdown(result: dict, vendor: dict | None) -> str:
    rows = [
        "| Baffle-authored category | Production Rust code LOC | Test Rust code LOC | Functions | Modules |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    test_loc = result["tests"]
    def tests_for(*keys: str) -> int:
        return sum(test_loc.get(key, {}).get("code", 0) for key in keys)

    tests_by_category = {
        "Backend-neutral Baffle core": tests_for(
            "Backend-neutral unit tests", "Backend-neutral external documentation tests"
        ),
        "Shared adapters and policy abstractions": tests_for(
            "Hudsucker-specific shared-policy/CA/control unit tests"
        ),
        "Hudsucker adapter/runtime": tests_for(
            "Hudsucker adapter unit tests", "Hudsucker-gated external integration tests"
        ),
        "Rama adapter/runtime": tests_for("Rama-specific unit tests"),
    }
    for category, values in result["source"].items():
        rows.append(
            f"| {category} | {values['code']} | {tests_by_category[category]} | {values['functions']} | {values['modules']} |"
        )
    rows.extend(
        [
            "",
            "| Test grouping | Rust test code LOC | Rust comment LOC | Blank LOC |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    for category, values in result["tests"].items():
        rows.append(f"| {category} | {values['code']} | {values['comments']} | {values['blank']} |")
    if vendor:
        rows.extend(
            [
                "",
                "| Vendored Hudsucker (excluded from Baffle-authored totals) | Value |",
                "| --- | ---: |",
                f"| Upstream source code LOC | {vendor['upstream_source_code_loc']} |",
                f"| Vendored source code LOC | {vendor['vendored_source_code_loc']} |",
                f"| Local source patch lines added / removed | {vendor['patch_added_lines']} / {vendor['patch_removed_lines']} |",
                f"| Changed source files | {vendor['patch_changed_files']} |",
                f"| Local patch test code LOC | {vendor['patch_test_code_loc']} |",
                f"| Exact upstream source revision | `{vendor['upstream_git_revision']}` |",
            ]
        )
    rows.append("")
    return "\n".join(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", default="HEAD", help="Baffle git revision to measure (default: HEAD)")
    parser.add_argument(
        "--upstream-hudsucker-src",
        type=Path,
        help="path to exact upstream Hudsucker 0.25.0 src/ directory for vendor delta measurements",
    )
    parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    args = parser.parse_args()
    result = count_project(args.revision)
    vendor = count_vendor(args.revision, args.upstream_hudsucker_src) if args.upstream_hudsucker_src else None
    if args.format == "json":
        print(json.dumps({"measurement": result, "vendor": vendor}, indent=2))
    else:
        print(markdown(result, vendor))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
