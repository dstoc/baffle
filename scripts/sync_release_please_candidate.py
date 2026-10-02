#!/usr/bin/env python3
"""Synchronize Cargo release metadata on a generated Release Please candidate."""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path


ROOT_PACKAGE = "baffle-proxy"
CLIENT_PACKAGE = "baffle-client"
CLIENT_PATH = "crates/baffle-client"
class CandidateError(ValueError):
    """The generated candidate cannot be synchronized safely."""


def _replace_toml_version_dependency(contents: str, version: str) -> str:
    section = None
    result: list[str] = []
    found = False

    for line in contents.splitlines(keepends=True):
        header = re.match(r"^\s*\[([^]]+)\]\s*(?:#.*)?(?:\r?\n)?$", line)
        if header:
            section = header.group(1)

        if section == "dependencies" and re.match(r"^\s*baffle-client\s*=\s*\{", line):
            if found:
                raise CandidateError("Cargo.toml has multiple baffle-client dependencies")
            updated, replacements = re.subn(
                r'(\bversion\s*=\s*)"[^"]+"',
                lambda match: match.group(1) + json.dumps(version),
                line,
                count=1,
            )
            if replacements != 1:
                raise CandidateError(
                    "Cargo.toml baffle-client dependency must have an inline version"
                )
            line = updated
            found = True

        result.append(line)

    if not found:
        raise CandidateError("Cargo.toml is missing the baffle-client path dependency")
    return "".join(result)


def _replace_package_version(contents: str, package_name: str, version: str) -> str:
    section = None
    result: list[str] = []
    package_matches = 0
    version_matches = 0

    for line in contents.splitlines(keepends=True):
        header = re.match(r"^\s*\[([^]]+)\]\s*(?:#.*)?(?:\r?\n)?$", line)
        if header:
            section = header.group(1)

        if section == "package" and re.match(r"^\s*name\s*=", line):
            name = re.search(r'"([^"]+)"', line)
            if not name or name.group(1) != package_name:
                raise CandidateError(f"Cargo.toml package must be {package_name}")
            package_matches += 1

        if section == "package" and re.match(r"^\s*version\s*=", line):
            line, replacements = re.subn(
                r'^(\s*version\s*=\s*)"[^"]+"',
                lambda match: match.group(1) + json.dumps(version),
                line,
                count=1,
            )
            if replacements != 1:
                raise CandidateError(f"Cargo.toml package {package_name} has an invalid version")
            version_matches += 1

        result.append(line)

    if package_matches != 1 or version_matches != 1:
        raise CandidateError(f"Cargo.toml must contain one [package] name and version for {package_name}")
    return "".join(result)


def _synchronize_lockfile(contents: str, versions: dict[str, str]) -> str:
    blocks = re.split(r"(?m)(?=^\[\[package\]\]\s*$)", contents)
    counts = {name: 0 for name in versions}
    updated_blocks: list[str] = []

    for block in blocks:
        name_match = re.search(r'(?m)^name\s*=\s*"([^"]+)"\s*$', block)
        if not name_match or name_match.group(1) not in versions:
            updated_blocks.append(block)
            continue

        name = name_match.group(1)
        counts[name] += 1
        updated, replacements = re.subn(
            r'(?m)^version[ \t]*=[ \t]*"[^"]+"[ \t]*$',
            f'version = {json.dumps(versions[name])}',
            block,
            count=1,
        )
        if replacements != 1:
            raise CandidateError(f"Cargo.lock package {name} has no unique version")
        updated_blocks.append(updated)

    missing = [name for name, count in counts.items() if count != 1]
    if missing:
        raise CandidateError(
            "Cargo.lock must contain exactly one package entry for: " + ", ".join(missing)
        )
    return "".join(updated_blocks)


def synchronize_candidate(repo_root: Path) -> bool:
    """Apply the root Release Please version to every Cargo workspace package."""

    root_manifest_path = repo_root / "Cargo.toml"
    client_manifest_path = repo_root / CLIENT_PATH / "Cargo.toml"
    release_manifest_path = repo_root / ".release-please-manifest.json"
    lockfile_path = repo_root / "Cargo.lock"

    root_text = root_manifest_path.read_text()
    client_text = client_manifest_path.read_text()
    root = tomllib.loads(root_text)
    release_manifest = json.loads(release_manifest_path.read_text())
    version = release_manifest.get(".")
    if not isinstance(version, str) or not re.fullmatch(
        r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version
    ):
        raise CandidateError("Release Please manifest must contain a stable root version")
    if root.get("package", {}).get("name") != ROOT_PACKAGE:
        raise CandidateError(f"Cargo.toml root package must be {ROOT_PACKAGE}")
    if root.get("package", {}).get("version") != version:
        raise CandidateError(
            "Release Please root manifest and Cargo package disagree: "
            f"{version} != {root.get('package', {}).get('version')}"
        )

    client = tomllib.loads(client_text)
    if client.get("package", {}).get("name") != CLIENT_PACKAGE:
        raise CandidateError(f"{CLIENT_PATH}/Cargo.toml package must be {CLIENT_PACKAGE}")

    dependency = root.get("dependencies", {}).get(CLIENT_PACKAGE)
    if not isinstance(dependency, dict) or dependency.get("path") != CLIENT_PATH:
        raise CandidateError(
            f"Cargo.toml must keep {CLIENT_PACKAGE} on the local {CLIENT_PATH} path"
        )
    if not isinstance(dependency.get("version"), str):
        raise CandidateError(
            f"Cargo.toml {CLIENT_PACKAGE} path dependency must have a version requirement"
        )

    updated_root = _replace_package_version(root_text, ROOT_PACKAGE, version)
    updated_root = _replace_toml_version_dependency(updated_root, version)
    updated_client = _replace_package_version(client_text, CLIENT_PACKAGE, version)
    updated_release_manifest = json.dumps({".": version}, indent=2) + "\n"
    updated_lockfile = _synchronize_lockfile(
        lockfile_path.read_text(), {ROOT_PACKAGE: version, CLIENT_PACKAGE: version}
    )

    changes = (
        (root_manifest_path, updated_root),
        (client_manifest_path, updated_client),
        (release_manifest_path, updated_release_manifest),
        (lockfile_path, updated_lockfile),
    )
    changed = False
    for path, contents in changes:
        if path.read_text() != contents:
            path.write_text(contents)
            changed = True
    return changed


def main() -> int:
    root = Path.cwd()
    try:
        changed = synchronize_candidate(root)
    except (CandidateError, KeyError, OSError, tomllib.TOMLDecodeError, json.JSONDecodeError) as error:
        print(f"Release Please candidate synchronization failed: {error}", file=sys.stderr)
        return 1

    if changed:
        print("Synchronized generated Cargo package versions, dependency, manifest, and lockfile.")
    else:
        print("Generated Cargo release candidate is already synchronized.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
