#!/usr/bin/env python3
"""Recover a merged Baffle Release Please PR that the action did not tag."""

from __future__ import annotations

import argparse
import base64
import html
import json
import os
import re
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

try:
    from .publish_crates import CratesIo, PublishError, plan_publication
except ImportError:  # Running as a script from the scripts directory.
    from publish_crates import CratesIo, PublishError, plan_publication


GITHUB_API = "https://api.github.com"
CRATES_API = "https://crates.io/api/v1"
EXPECTED_REPOSITORY = "dstoc/baffle"
RELEASE_PENDING = "autorelease: pending"
RELEASE_TAGGED = "autorelease: tagged"
FORCE_RUN = "release-please:force-run"
RELEASE_PLEASE_FOOTER = "This PR was generated with [Release Please]"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SUMMARY_RE = re.compile(r"<summary>(.*?)</summary>", re.DOTALL | re.IGNORECASE)
SUMMARY_VERSION_RE = re.compile(r"(?:^|\s)(?:v)?((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?)\s*$")


class RecoveryError(RuntimeError):
    """A release could not be recovered without guessing or overwriting."""


class GitHubApiError(RecoveryError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class GitHubApi:
    def __init__(
        self,
        repo: str,
        token: str,
        *,
        opener: Callable = urllib.request.urlopen,
    ):
        if repo != EXPECTED_REPOSITORY:
            raise RecoveryError(f"Refusing release recovery for unexpected repository {repo!r}.")
        if not token:
            raise RecoveryError("GH_TOKEN is missing; cannot verify or recover the GitHub Release.")
        self.repo = repo
        self.token = token
        self.opener = opener

    def request(self, method: str, path: str, body: dict | None = None) -> dict | list | None:
        url = f"{GITHUB_API}/repos/{self.repo}/{path.lstrip('/')}"
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "baffle-release-recovery/1",
                **({"Content-Type": "application/json"} if data is not None else {}),
            },
        )
        try:
            with self.opener(request, timeout=20) as response:
                raw = response.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as error:
            if error.code == 404 and method == "GET":
                return None
            detail = error.read().decode("utf-8", errors="replace")[:500]
            raise GitHubApiError(
                error.code,
                f"GitHub API {method} {path} failed with HTTP {error.code}: {detail}",
            ) from error
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            raise RecoveryError(f"GitHub API {method} {path} failed: {error}") from error

    def pending_release_prs(self) -> list[dict]:
        return self._merged_release_prs(RELEASE_PENDING)

    def tagged_release_prs(self) -> list[dict]:
        return self._merged_release_prs(RELEASE_TAGGED)

    def _merged_release_prs(self, label_name: str) -> list[dict]:
        matches: list[dict] = []
        page = 1
        while True:
            result = self.request(
                "GET",
                f"pulls?state=closed&base=main&per_page=100&page={page}",
            )
            if not isinstance(result, list):
                raise RecoveryError("GitHub returned an invalid pull request list.")
            matches.extend(
                pr
                for pr in result
                if pr.get("merged_at")
                and pr.get("base", {}).get("ref") == "main"
                and label_name in {label.get("name") for label in pr.get("labels", [])}
            )
            if len(result) < 100:
                break
            page += 1
        return matches

    def file_at(self, path: str, ref: str) -> str:
        encoded_path = urllib.parse.quote(path, safe="/")
        result = self.request(
            "GET",
            f"contents/{encoded_path}?ref={urllib.parse.quote(ref, safe='')}",
        )
        if not isinstance(result, dict) or result.get("encoding") != "base64":
            raise RecoveryError(f"Could not read {path} at release commit {ref}.")
        try:
            return base64.b64decode(result["content"], validate=False).decode("utf-8")
        except (KeyError, UnicodeDecodeError, ValueError) as error:
            raise RecoveryError(f"GitHub returned invalid contents for {path} at {ref}.") from error

    def tag_sha(self, tag: str) -> str | None:
        encoded_tag = urllib.parse.quote(tag, safe="")
        ref = self.request("GET", f"git/ref/tags/{encoded_tag}")
        if ref is None:
            return None
        if not isinstance(ref, dict):
            raise RecoveryError(f"GitHub returned an invalid tag reference for {tag}.")
        target = ref.get("object", {})
        for _ in range(5):
            object_type = target.get("type")
            object_sha = target.get("sha")
            if object_type == "commit" and isinstance(object_sha, str) and SHA_RE.fullmatch(object_sha):
                return object_sha
            if object_type != "tag" or not isinstance(object_sha, str):
                raise RecoveryError(f"Tag {tag} does not resolve to a commit.")
            annotated = self.request("GET", f"git/tags/{object_sha}")
            if not isinstance(annotated, dict):
                raise RecoveryError(f"Could not resolve annotated tag {tag}.")
            target = annotated.get("object", {})
        raise RecoveryError(f"Tag {tag} has too many nested annotated tag objects.")

    def release(self, tag: str) -> dict | None:
        encoded_tag = urllib.parse.quote(tag, safe="")
        result = self.request("GET", f"releases/tags/{encoded_tag}")
        if result is not None and not isinstance(result, dict):
            raise RecoveryError(f"GitHub returned an invalid Release object for {tag}.")
        return result

    def create_tag_ref(self, tag: str, sha: str) -> dict:
        ref_name = f"refs/tags/{tag}"
        result = self.request(
            "POST",
            "git/refs",
            {"ref": ref_name, "sha": sha},
        )
        if not isinstance(result, dict):
            raise RecoveryError(f"GitHub did not return the created tag reference {tag}.")
        object_ref = result.get("object", {})
        if (
            result.get("ref") != ref_name
            or not isinstance(object_ref, dict)
            or object_ref.get("type") != "commit"
            or not isinstance(object_ref.get("sha"), str)
            or object_ref["sha"].lower() != sha.lower()
        ):
            raise RecoveryError(f"GitHub returned an unexpected tag reference for {tag}.")
        return result

    def create_release(self, tag: str, notes: str) -> dict:
        result = self.request(
            "POST",
            "releases",
            {
                "tag_name": tag,
                "name": tag,
                "body": notes,
                "draft": False,
                "prerelease": False,
            },
        )
        if not isinstance(result, dict):
            raise RecoveryError(f"GitHub did not return the created Release {tag}.")
        return result

    def set_release_labels(self, pr: dict) -> None:
        labels = {label.get("name") for label in pr.get("labels", []) if label.get("name")}
        labels.discard(RELEASE_PENDING)
        labels.discard(FORCE_RUN)
        labels.add(RELEASE_TAGGED)
        self.request(
            "PUT",
            f"issues/{pr['number']}/labels",
            {"labels": sorted(labels)},
        )


def release_versions_from_pr(pr: dict) -> set[str]:
    body = pr.get("body") or ""
    if RELEASE_PLEASE_FOOTER not in body:
        raise RecoveryError("The pending merged PR does not have the Release Please footer.")
    versions: set[str] = set()
    for summary in SUMMARY_RE.findall(body):
        match = SUMMARY_VERSION_RE.search(" ".join(summary.split()))
        if match:
            versions.add(match.group(1))
    if not versions:
        raise RecoveryError("The pending Release Please PR has no parseable release version in its body.")
    for version in versions:
        if not VERSION_RE.fullmatch(version):
            raise RecoveryError(f"The pending Release Please PR contains invalid version {version!r}.")
    return versions


def release_version_from_pr(pr: dict) -> str:
    versions = release_versions_from_pr(pr)
    if len(versions) != 1:
        raise RecoveryError(f"The pending Release Please PR contains multiple versions: {sorted(versions)}.")
    return versions.pop()


def release_notes_from_changelog(changelog: str, version: str) -> str:
    heading = re.compile(rf"^## \[{re.escape(version)}\]\([^\n]+$", re.MULTILINE)
    match = heading.search(changelog)
    if not match:
        raise RecoveryError(f"CHANGELOG.md has no Release Please section for {version}.")
    end = re.search(r"^## ", changelog[match.end() :], re.MULTILINE)
    notes = changelog[match.end() : match.end() + end.start() if end else None].strip()
    if not notes:
        raise RecoveryError(f"CHANGELOG.md has an empty release section for {version}.")
    return notes


def validate_release_pr(pr: dict, github: GitHubApi) -> tuple[str, str, str]:
    number = pr.get("number")
    sha = pr.get("merge_commit_sha")
    if not isinstance(number, int) or not isinstance(sha, str) or not SHA_RE.fullmatch(sha):
        raise RecoveryError("The pending Release Please PR has no valid merge commit SHA.")
    allowed_release_branches = {
        "release-please--branches--main",
        "release-please--branches--main--components--baffle-proxy",
    }
    if pr.get("head", {}).get("ref") not in allowed_release_branches:
        raise RecoveryError("The pending PR branch is not Baffle's main Release Please branch.")
    pull_request_versions = release_versions_from_pr(pr)

    try:
        manifest = json.loads(github.file_at(".release-please-manifest.json", sha))
        config = json.loads(github.file_at("release-please-config.json", sha))
        root = tomllib.loads(github.file_at("Cargo.toml", sha))
        client = tomllib.loads(github.file_at("crates/baffle-client/Cargo.toml", sha))
        lock = tomllib.loads(github.file_at("Cargo.lock", sha))
        changelog = github.file_at("CHANGELOG.md", sha)
    except (json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        raise RecoveryError(f"Release metadata at {sha} is invalid: {error}") from error

    package_config = config.get("packages", {})
    if not isinstance(package_config, dict) or set(package_config) not in (
        {"."}, {".", "crates/baffle-client"}
    ):
        raise RecoveryError("Release config must manage the root package and may include the legacy client path.")
    if not isinstance(manifest, dict) or set(manifest) != set(package_config):
        raise RecoveryError("Release manifest paths do not match the configured Release Please packages.")
    if config.get("include-component-in-tag") is not False:
        raise RecoveryError("Release config no longer specifies the shared unprefixed tag format.")
    for path, package in package_config.items():
        if not isinstance(package, dict):
            raise RecoveryError(f"Release config for {path} is invalid.")
        expected_name = "baffle-proxy" if path == "." else "baffle-client"
        if package.get("package-name") != expected_name:
            raise RecoveryError(f"Release config for {path} does not manage {expected_name}.")
        include_component = package.get("include-component-in-tag", config["include-component-in-tag"])
        include_v = package.get("include-v-in-tag", config.get("include-v-in-tag", True))
        if include_component is not False or include_v is not True:
            raise RecoveryError(f"Release config for {path} no longer specifies the expected vX.Y.Z tag format.")
    if root.get("package", {}).get("name") != "baffle-proxy":
        raise RecoveryError(f"baffle-proxy Cargo metadata at {sha} has an unexpected package name.")
    if client.get("package", {}).get("name") != "baffle-client":
        raise RecoveryError(f"baffle-client Cargo metadata at {sha} has an unexpected package name.")
    cargo_versions = {
        root.get("package", {}).get("version"),
        client.get("package", {}).get("version"),
    }
    if not all(isinstance(value, str) for value in manifest.values()):
        raise RecoveryError("Release manifest versions must be strings.")
    manifest_versions = set(manifest.values())
    if len(cargo_versions) != 1 or len(manifest_versions) != 1 or cargo_versions != manifest_versions:
        raise RecoveryError(
            "Release manifest and both Cargo packages do not identify one synchronized version: "
            f"manifest={manifest!r}, Cargo={sorted(str(value) for value in cargo_versions)}."
        )
    version = next(iter(cargo_versions))
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise RecoveryError(f"Release metadata contains invalid version {version!r}.")
    if version not in pull_request_versions:
        raise RecoveryError(
            f"Release PR versions {sorted(pull_request_versions)} do not include the synchronized package version {version}."
        )
    tag = f"v{version}"
    dependency = root.get("dependencies", {}).get("baffle-client", {})
    if not isinstance(dependency, dict) or dependency.get("path") != "crates/baffle-client" or dependency.get("version") != version:
        raise RecoveryError(f"baffle-proxy's local baffle-client dependency at {sha} does not match {version}.")
    lock_versions = {
        package.get("name"): package.get("version")
        for package in lock.get("package", [])
        if package.get("name") in {"baffle-proxy", "baffle-client"}
    }
    if lock_versions != {"baffle-proxy": version, "baffle-client": version}:
        raise RecoveryError(f"Cargo.lock at {sha} does not contain both packages at {version}: {lock_versions!r}.")

    notes = release_notes_from_changelog(changelog, version)
    return version, tag, notes


def validate_existing_state(github: GitHubApi, tag: str, sha: str) -> tuple[str | None, dict | None]:
    tag_sha = github.tag_sha(tag)
    release = github.release(tag)
    if tag_sha and tag_sha.lower() != sha.lower():
        raise RecoveryError(f"Tag {tag} already points to {tag_sha}, not the Release Please merge SHA {sha}.")
    if release:
        if release.get("tag_name") != tag:
            raise RecoveryError(f"GitHub Release tag identity does not match {tag}.")
        if release.get("draft") is not False or release.get("prerelease") is not False:
            raise RecoveryError(f"GitHub Release {tag} is a draft or prerelease; refusing recovery.")
        if not tag_sha:
            raise RecoveryError(f"GitHub Release {tag} exists without a tag; refusing to repair it implicitly.")
    return tag_sha, release


def required_release_assets(tag: str) -> set[str]:
    return {
        f"baffle-proxy-{tag}-x86_64-unknown-linux-gnu.tar.gz",
        f"baffle-proxy-{tag}-aarch64-apple-darwin.tar.gz",
        "SHA256SUMS",
    }


def release_has_required_assets(release: dict | None, tag: str) -> bool:
    if not release:
        return False
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise RecoveryError(f"GitHub Release {tag} has an invalid asset list.")
    names = {asset.get("name") for asset in assets if isinstance(asset, dict)}
    return required_release_assets(tag).issubset(names)


def recover_pending_release(
    github: GitHubApi,
    registry: CratesIo,
    *,
    dry_run: bool = False,
) -> dict[str, str]:
    pending = github.pending_release_prs()
    is_pending = bool(pending)
    if pending:
        if len(pending) != 1:
            numbers = sorted(pr.get("number") for pr in pending)
            raise RecoveryError(f"Found multiple merged Release Please PRs still pending: {numbers}; refusing to choose.")
        pr = pending[0]
    else:
        tagged = github.tagged_release_prs()
        if not tagged:
            return {
                "release_created": "false",
                "tag_name": "",
                "sha": "",
                "package_binaries": "false",
                "publish_crates": "false",
            }
        latest_merge = max(pr.get("merged_at", "") for pr in tagged)
        latest = [pr for pr in tagged if pr.get("merged_at", "") == latest_merge]
        if len(latest) != 1:
            numbers = sorted(pr.get("number") for pr in latest)
            raise RecoveryError(f"Found multiple latest tagged Release Please PRs: {numbers}; refusing to choose.")
        pr = latest[0]

    version, tag, notes = validate_release_pr(pr, github)
    sha = pr["merge_commit_sha"]

    if not getattr(registry, "token", ""):
        raise RecoveryError(
            "CARGO_REGISTRY_TOKEN is empty or missing; cannot verify crates.io package ownership before recovery."
        )

    client_state = registry.state("baffle-client", version)
    proxy_state = registry.state("baffle-proxy", version)
    try:
        plan_publication(client_state, proxy_state)
    except PublishError as error:
        raise RecoveryError(f"Crates.io state blocks recovery: {error}") from error

    tag_sha, release = validate_existing_state(github, tag, sha)
    assets_complete = release_has_required_assets(release, tag)
    if release and not assets_complete and release.get("immutable") is True:
        raise RecoveryError(f"GitHub Release {tag} is immutable and is missing one or more required release assets.")

    crates_complete = client_state.version_exists and proxy_state.version_exists
    if not is_pending and assets_complete and crates_complete:
        print(f"Release {tag} at {sha} from merged PR #{pr['number']} already has both crates and all release assets.")
        return {
            "release_created": "false",
            "tag_name": "",
            "sha": "",
            "package_binaries": "false",
            "publish_crates": "false",
        }

    if not is_pending and (not client_state.registered or not proxy_state.registered):
        raise RecoveryError(
            f"Tagged release {tag} cannot be retried because crates.io does not report both expected crate registrations."
        )

    if dry_run:
        action = "would create" if not release else "would verify"
        print(f"Dry run: {action} {tag} at {sha} from merged PR #{pr['number']}; no GitHub writes made.")
        return {
            "release_created": "true",
            "tag_name": tag,
            "sha": sha,
            "package_binaries": str(not assets_complete).lower(),
            "publish_crates": str(not crates_complete).lower(),
        }

    if not release:
        if not tag_sha:
            tag_create_error: GitHubApiError | None = None
            try:
                github.create_tag_ref(tag, sha)
            except GitHubApiError as error:
                if error.status not in (409, 422):
                    raise
                tag_create_error = error
                # Another workflow may have created the ref after our preflight.
                # Continue only if it points to the exact verified merge SHA.
            tag_sha = github.tag_sha(tag)
            if not tag_sha and tag_create_error:
                raise tag_create_error
            if not tag_sha:
                raise RecoveryError(f"GitHub did not create the expected tag reference {tag} at {sha}.")
            if tag_sha.lower() != sha.lower():
                raise RecoveryError(f"Tag {tag} already points to {tag_sha}, not the Release Please merge SHA {sha}.")
        try:
            github.create_release(tag, notes)
        except GitHubApiError as error:
            if error.status not in (409, 422):
                raise
            # Another workflow may have created the release after our preflight.
            # Only continue when the resulting tag and Release exactly match.
        tag_sha, release = validate_existing_state(github, tag, sha)
        if not tag_sha or not release:
            raise RecoveryError(f"GitHub did not create the expected tag and Release {tag} at {sha}.")

    current_labels = {label.get("name") for label in pr.get("labels", [])}
    if RELEASE_TAGGED not in current_labels or RELEASE_PENDING in current_labels or FORCE_RUN in current_labels:
        github.set_release_labels(pr)

    print(
        f"Verified Release Please recovery for {tag} at {sha} from merged PR #{pr['number']}; "
        "the existing crates publisher and binary packager can now run safely."
    )
    if not is_pending:
        missing_crates = [
            name
            for name, state in (("baffle-client", client_state), ("baffle-proxy", proxy_state))
            if not state.version_exists
        ]
        existing_assets = {
            asset.get("name")
            for asset in (release or {}).get("assets", [])
            if isinstance(asset, dict)
        }
        missing_assets = sorted(required_release_assets(tag) - existing_assets)
        if missing_crates:
            print("Crates to publish: " + ", ".join(f"{name} {version}" for name in missing_crates) + ".")
        if missing_assets:
            print("Release assets to verify or publish: " + ", ".join(missing_assets) + ".")
    return {
        "release_created": "true",
        "tag_name": tag,
        "sha": sha,
        "package_binaries": str(not assets_complete).lower(),
        "publish_crates": str(not crates_complete).lower(),
    }


def write_outputs(values: dict[str, str], output_path: str | None) -> None:
    lines = "".join(f"{key}={value}\n" for key, value in values.items())
    if output_path:
        with Path(output_path).open("a", encoding="utf-8") as output:
            output.write(lines)
    else:
        sys.stdout.write(lines)


def report_failure(error: Exception, *, token: str = "", summary_path: str | None = None) -> None:
    detail = str(error)
    if token:
        detail = detail.replace(token, "[redacted]")

    annotation = detail.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::error title=Release recovery failed::{annotation}", file=sys.stderr)
    print(f"ERROR: {detail}", file=sys.stderr)

    if summary_path:
        try:
            with Path(summary_path).open("a", encoding="utf-8") as summary:
                summary.write("## Release recovery failed\n\n")
                summary.write("Inspect the error before retrying the recovery.\n\n")
                summary.write(f"<pre>{html.escape(detail)}</pre>\n")
        except OSError as summary_error:
            print(f"WARNING: could not write the job summary: {summary_error}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=os.environ.get("REPOSITORY", EXPECTED_REPOSITORY))
    parser.add_argument("--dry-run", action="store_true", help="verify the candidate without changing GitHub")
    args = parser.parse_args(argv)
    cargo_token = os.environ.get("CARGO_REGISTRY_TOKEN", "")

    try:
        github = GitHubApi(args.repo, os.environ.get("GH_TOKEN", ""))
        result = recover_pending_release(
            github,
            CratesIo(token=cargo_token, api=CRATES_API),
            dry_run=args.dry_run,
        )
        write_outputs(result, os.environ.get("GITHUB_OUTPUT"))
    except (RecoveryError, PublishError) as error:
        report_failure(
            error,
            token=cargo_token,
            summary_path=os.environ.get("GITHUB_STEP_SUMMARY"),
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
