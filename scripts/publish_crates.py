#!/usr/bin/env python3
"""Validate a Release Please release and publish the two Baffle crates."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


CRATES_IO_API = "https://crates.io/api/v1"
GITHUB_API = "https://api.github.com"
EXPECTED_REPOSITORY = "https://github.com/dstoc/baffle"
EXPECTED_OWNER = "dstoc"
MAX_API_ATTEMPTS = 5
PROPAGATION_ATTEMPTS = 24
PROPAGATION_DELAY_SECONDS = 15
SEMVER_TAG = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SHA = re.compile(r"^[0-9a-fA-F]{40}$")


class PublishError(RuntimeError):
    """An actionable failure that must stop the release publication."""


def version_from_tag(tag: str) -> str:
    match = SEMVER_TAG.fullmatch(tag)
    if not match:
        raise PublishError(f"Release tag {tag!r} must use the vX.Y.Z format without a prerelease suffix.")
    return ".".join(match.groups())


def parse_manifest_versions(workspace: Path) -> dict[str, str]:
    try:
        root = tomllib.loads((workspace / "Cargo.toml").read_text())
        client = tomllib.loads((workspace / "crates/baffle-client/Cargo.toml").read_text())
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise PublishError(f"Cannot read the release Cargo manifests: {error}") from error

    try:
        root_version = root["package"]["version"]
        client_version = client["package"]["version"]
        dependency = root["dependencies"]["baffle-client"]
        dependency_version = dependency["version"]
        dependency_path = dependency["path"]
    except (KeyError, TypeError) as error:
        raise PublishError("Cargo manifests do not contain the expected Baffle package and local dependency metadata.") from error

    if dependency_path != "crates/baffle-client":
        raise PublishError(f"baffle-proxy has unexpected baffle-client path {dependency_path!r}.")
    if root_version != client_version or root_version != dependency_version:
        raise PublishError(
            "Cargo package versions do not match: "
            f"baffle-proxy={root_version}, baffle-client={client_version}, dependency={dependency_version}."
        )
    return {"baffle-proxy": root_version, "baffle-client": client_version}


def validate_tag_versions(tag: str, workspace: Path) -> str:
    version = version_from_tag(tag)
    versions = parse_manifest_versions(workspace)
    mismatches = {name: current for name, current in versions.items() if current != version}
    if mismatches:
        actual = ", ".join(f"{name}={current}" for name, current in mismatches.items())
        raise PublishError(f"Tag {tag} does not match the checked-out Cargo versions ({actual}).")
    return version


def request_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    opener: Callable = urllib.request.urlopen,
    sleep: Callable[[float], None] = time.sleep,
) -> dict | None:
    request_headers = {"User-Agent": "baffle-crates-release/1", "Accept": "application/json"}
    if headers:
        request_headers.update(headers)

    for attempt in range(1, MAX_API_ATTEMPTS + 1):
        request = urllib.request.Request(url, headers=request_headers)
        try:
            with opener(request, timeout=20) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            if error.code not in (429, 500, 502, 503, 504):
                detail = error.read().decode("utf-8", errors="replace")[:500]
                raise PublishError(f"Registry/API request failed with HTTP {error.code} for {url}: {detail}") from error
            if attempt == MAX_API_ATTEMPTS:
                raise PublishError(f"Registry/API request remained unavailable (HTTP {error.code}) for {url}.") from error
            retry_after = error.headers.get("Retry-After")
            delay = min(30, int(retry_after)) if retry_after and retry_after.isdigit() else min(20, attempt * 3)
            print(f"API returned HTTP {error.code}; retry {attempt}/{MAX_API_ATTEMPTS} in {delay}s.", flush=True)
            sleep(delay)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            if attempt == MAX_API_ATTEMPTS:
                raise PublishError(f"Registry/API request failed for {url}: {error}") from error
            delay = min(20, attempt * 3)
            print(f"API request failed; retry {attempt}/{MAX_API_ATTEMPTS} in {delay}s.", flush=True)
            sleep(delay)
    raise AssertionError("unreachable")


def verify_release(repo: str, tag: str, release_sha: str, workspace: Path, github_token: str) -> str:
    version = validate_tag_versions(tag, workspace)
    if not SHA.fullmatch(release_sha):
        raise PublishError("Release Please did not report a full commit SHA; refusing to publish.")
    if not github_token:
        raise PublishError("GitHub token is missing; cannot verify the GitHub Release identity.")

    encoded_tag = urllib.parse.quote(tag, safe="")
    release = request_json(
        f"{GITHUB_API}/repos/{repo}/releases/tags/{encoded_tag}",
        headers={"Authorization": f"Bearer {github_token}", "X-GitHub-Api-Version": "2022-11-28"},
    )
    if not release:
        raise PublishError(f"GitHub has no Release for Release Please tag {tag}.")
    if release.get("tag_name") != tag:
        raise PublishError(f"GitHub Release tag identity does not match Release Please output {tag}.")
    if release.get("draft") is not False or release.get("prerelease") is not False:
        raise PublishError(f"GitHub Release {tag} is a draft or prerelease; crates.io publication is disabled.")

    try:
        tag_sha = subprocess.run(
            ["git", "rev-parse", f"refs/tags/{tag}^{{commit}}"],
            cwd=workspace,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        head_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=workspace, check=True, capture_output=True, text=True
        ).stdout.strip()
        subprocess.run(["git", "fetch", "origin", "main", "--quiet"], cwd=workspace, check=True)
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", release_sha, "refs/remotes/origin/main"],
            cwd=workspace,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as error:
        raise PublishError(f"Cannot verify the Release Please tag against main: {error}") from error

    if tag_sha.lower() != release_sha.lower() or head_sha.lower() != release_sha.lower():
        raise PublishError(
            f"Checked-out tag {tag} does not point to Release Please's reported commit {release_sha}."
        )
    print(f"Verified GitHub Release {tag} at {release_sha}; both Cargo packages are version {version}.")
    return version


@dataclass(frozen=True)
class RegistryState:
    registered: bool
    version_exists: bool


class CratesIo:
    def __init__(
        self,
        *,
        api: str = CRATES_IO_API,
        token: str = "",
        opener: Callable = urllib.request.urlopen,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.api = api.rstrip("/")
        self.token = token
        self.opener = opener
        self.sleep = sleep

    def get(self, path: str, *, authenticated: bool = False) -> dict | None:
        headers = {"Authorization": self.token} if authenticated else None
        return request_json(
            f"{self.api}/{path.lstrip('/')}",
            headers=headers,
            opener=self.opener,
            sleep=self.sleep,
        )

    def check_identity(self, crate: str) -> bool:
        result = self.get(f"crates/{crate}")
        if result is None:
            print(f"{crate}: name is not registered; the first publish will claim it for the token owner.")
            return False

        metadata = result.get("crate", {})
        if metadata.get("name") != crate:
            raise PublishError(f"crates.io returned unexpected identity for {crate}: {metadata.get('name')!r}.")
        if metadata.get("repository") != EXPECTED_REPOSITORY:
            raise PublishError(
                f"crates.io name {crate} is already registered to a different repository "
                f"({metadata.get('repository')!r}); refusing to publish."
            )

        owners_result = self.get(f"crates/{crate}/owners", authenticated=True) or {}
        owners = owners_result.get("users", []) + owners_result.get("teams", [])
        owner_logins = {owner.get("login", "") for owner in owners}
        has_expected_owner = EXPECTED_OWNER in owner_logins or any(
            login.startswith(f"github:{EXPECTED_OWNER}:") for login in owner_logins
        )
        if not has_expected_owner:
            shown = ", ".join(sorted(login for login in owner_logins if login)) or "none"
            raise PublishError(
                f"crates.io crate {crate} has no expected owner {EXPECTED_OWNER} "
                f"(current owners: {shown}); refusing to publish."
            )
        return True

    def state(self, crate: str, version: str) -> RegistryState:
        registered = self.check_identity(crate)
        if not registered:
            return RegistryState(registered=False, version_exists=False)

        result = self.get(f"crates/{crate}/{version}")
        if result is None:
            return RegistryState(registered=True, version_exists=False)
        metadata = result.get("version", {})
        if metadata.get("crate") != crate or metadata.get("num") != version:
            raise PublishError(
                f"crates.io version identity for {crate} {version} does not match the requested crate and version."
            )
        if metadata.get("yanked"):
            raise PublishError(f"crates.io version {crate} {version} is yanked; refusing to treat it as published.")
        return RegistryState(registered=True, version_exists=True)

    def wait_for_version(self, crate: str, version: str) -> None:
        for attempt in range(1, PROPAGATION_ATTEMPTS + 1):
            indexed_version = self.get(f"crates/{crate}/{version}")
            if indexed_version is not None:
                state = self.state(crate, version)
            else:
                state = RegistryState(registered=False, version_exists=False)
            if state.registered and state.version_exists:
                print(f"crates.io confirms {crate} {version} and its repository and owner identity.")
                return
            if attempt < PROPAGATION_ATTEMPTS:
                print(
                    f"Waiting for crates.io to index {crate} {version} "
                    f"({attempt}/{PROPAGATION_ATTEMPTS - 1}).",
                    flush=True,
                )
                self.sleep(PROPAGATION_DELAY_SECONDS)
        raise PublishError(
            f"Timed out waiting for crates.io to confirm {crate} {version}; inspect the registry before rerunning."
        )


def plan_publication(client_state: RegistryState, proxy_state: RegistryState) -> tuple[str, ...]:
    if proxy_state.version_exists and not client_state.version_exists:
        raise PublishError(
            "baffle-proxy version exists on crates.io but the matching baffle-client version does not; "
            "refusing to create an out-of-order release."
        )
    return tuple(
        crate
        for crate, state in (("baffle-client", client_state), ("baffle-proxy", proxy_state))
        if not state.version_exists
    )


def run_cargo(args: list[str], *, token: str | None = None) -> None:
    command = ["cargo", *args]
    env = os.environ.copy()
    env.pop("CARGO_REGISTRY_TOKEN", None)
    if token is not None:
        env["CARGO_REGISTRY_TOKEN"] = token
    print("$ " + " ".join(command), flush=True)
    result = subprocess.run(command, text=True, capture_output=True, env=env)
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    if result.returncode:
        if token is not None:
            diagnostics = f"{result.stdout}\n{result.stderr}".lower()
            if "already uploaded" in diagnostics or "already exists" in diagnostics:
                raise PublishError(
                    "crates.io reports that this package version already exists, but the registry preflight "
                    "did not confirm a matching version identity. Inspect the crate before rerunning."
                )
            raise PublishError(
                "cargo publish failed; review Cargo output above for package, registry, rate-limit, or "
                "authorization details. Check that CARGO_REGISTRY_TOKEN is valid and its crates.io account "
                "can publish this crate."
            )
        raise PublishError(f"cargo {' '.join(args)} failed with exit code {result.returncode}.")


def publish_release(tag: str, workspace: Path, registry: CratesIo, token: str) -> None:
    version = validate_tag_versions(tag, workspace)
    if not token.strip():
        raise PublishError("CARGO_REGISTRY_TOKEN is empty or missing from the trusted publishing step.")

    states = {
        "baffle-client": registry.state("baffle-client", version),
        "baffle-proxy": registry.state("baffle-proxy", version),
    }
    packages = plan_publication(states["baffle-client"], states["baffle-proxy"])
    uploaded_this_run: list[str] = []
    confirmed_this_run: list[str] = []
    already_published = [name for name, state in states.items() if state.version_exists]

    for name in already_published:
        print(f"{name} {version} is already published with the expected repository and owner; skipping.")

    try:
        for name in packages:
            if name == "baffle-proxy":
                # The registry client version must be visible before Cargo verifies the proxy package.
                registry.wait_for_version("baffle-client", version)
                run_cargo(["publish", "--dry-run", "--locked", "--package", name])

            print(f"Publishing {name} {version} to crates.io.")
            run_cargo(["publish", "--locked", "--package", name], token=token)
            uploaded_this_run.append(name)
            registry.wait_for_version(name, version)
            confirmed_this_run.append(name)
            print(f"Published and verified {name} {version}.")
    except PublishError as error:
        if uploaded_this_run:
            completed = [*already_published, *confirmed_this_run]
            pending_confirmation = [name for name in uploaded_this_run if name not in confirmed_this_run]
            remaining = [name for name in packages if name not in uploaded_this_run]
            details = []
            if completed:
                details.append("registry confirmed " + ", ".join(f"{name} {version}" for name in completed))
            if pending_confirmation:
                details.append(
                    "Cargo accepted the upload for "
                    + ", ".join(f"{name} {version}" for name in pending_confirmation)
                    + " but crates.io did not confirm it"
                )
            if remaining:
                details.append("not yet uploaded: " + ", ".join(f"{name} {version}" for name in remaining))
            print(
                "PARTIAL OR UNCONFIRMED RELEASE: "
                + "; ".join(details)
                + ". Re-run the failed publishing job in this run to verify existing versions "
                "and resume safely."
            )
        raise error

    complete = [*already_published, *confirmed_this_run]
    print("Crates.io release confirmed: " + ", ".join(f"{name} {version}" for name in complete) + ".")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    verify_parser = commands.add_parser("verify-release")
    verify_parser.add_argument("--repo", required=True)
    verify_parser.add_argument("--tag", required=True)
    verify_parser.add_argument("--release-sha", required=True)
    verify_parser.add_argument("--workspace", type=Path, default=Path.cwd())
    publish_parser = commands.add_parser("publish")
    publish_parser.add_argument("--tag", required=True)
    publish_parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)

    try:
        if args.command == "verify-release":
            verify_release(
                args.repo,
                args.tag,
                args.release_sha,
                args.workspace,
                os.environ.get("GH_TOKEN", ""),
            )
        else:
            publish_release(
                args.tag,
                args.workspace,
                CratesIo(token=os.environ.get("CARGO_REGISTRY_TOKEN", "")),
                os.environ.get("CARGO_REGISTRY_TOKEN", ""),
            )
    except PublishError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
