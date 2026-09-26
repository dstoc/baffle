#!/usr/bin/env python3
"""Build release notices from the locked Linux release dependency graph."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TARGET = "x86_64-unknown-linux-gnu"
LEGAL_FILE_PREFIXES = (
    "license",
    "licence",
    "copying",
    "notice",
    "copyright",
    "patent",
)


def run_cargo(*args):
    return subprocess.run(
        ["cargo", *args],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout


def pinned_upstream_files(package):
    """Return license files omitted from a crate archive, with pinned sources."""
    name = package["name"]
    version = package["version"]

    if (name, version) == ("alloc-stdlib", "0.2.4"):
        repository = "https://github.com/dropbox/rust-alloc-no-stdlib"
        revision = "ae42d22078b98549e987d2f03d12df7b984fde47"
        vcs_path = "alloc-stdlib"
        files = [
            (
                ROOT / "licenses/third-party-upstream/alloc-stdlib-LICENSE.txt",
                f"{repository}/blob/{revision}/LICENSE",
                "c0c56f26d9c051cac4d200c34c84e7ae9aaa853e01a982a1df08b09931e518ae",
            )
        ]
    elif (name, version) == ("asn1-rs-impl", "0.2.0"):
        repository = "https://github.com/rusticata/asn1-rs"
        revision = "a20e5f7319c896737ad0f2557037817b91ad854f"
        vcs_path = "impl"
        files = [
            (
                ROOT / "licenses/third-party-upstream/asn1-rs-LICENSE-APACHE.txt",
                f"{repository}/blob/{revision}/LICENSE-APACHE",
                "a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2",
            ),
            (
                ROOT / "licenses/third-party-upstream/asn1-rs-LICENSE-MIT.txt",
                f"{repository}/blob/{revision}/LICENSE-MIT",
                "a5c61b93b6ee1d104af9920cf020ff3c7efe818e31fe562c72261847a728f513",
            ),
        ]
    elif name.startswith("rama-") and version == "0.4.0":
        repository = "https://github.com/plabayo/rama"
        revision = "e588bafbf58afe5cf2ef8a26735bec563e518344"
        vcs_path = name
        files = [
            (
                ROOT / "licenses/third-party-upstream/rama-LICENSE-APACHE.txt",
                f"{repository}/blob/{revision}/LICENSE-APACHE",
                "95bd3988beee069fa2848f648dab43cc6e0b2add2ad6bcb17360caf749802bcc",
            ),
            (
                ROOT / "licenses/third-party-upstream/rama-LICENSE-MIT.txt",
                f"{repository}/blob/{revision}/LICENSE-MIT",
                "1fa7e078de3f9165a1c6742359307711e91652f035dc37a32376ca0023483e63",
            ),
        ]
    else:
        return None

    if package.get("repository", "").removesuffix(".git") != repository:
        raise RuntimeError(f"Unexpected upstream repository for {name} {version}")

    manifest_dir = Path(package["manifest_path"]).parent
    vcs_path_file = manifest_dir / ".cargo_vcs_info.json"
    if not vcs_path_file.is_file():
        raise RuntimeError(f"Missing Cargo VCS pin for {name} {version}")
    vcs = json.loads(vcs_path_file.read_text(encoding="utf-8"))
    actual_revision = vcs.get("git", {}).get("sha1")
    actual_path = vcs.get("path_in_vcs")
    if (actual_revision, actual_path) != (revision, vcs_path):
        raise RuntimeError(
            f"Upstream source pin changed for {name} {version}: "
            f"expected {revision}:{vcs_path}, got {actual_revision}:{actual_path}"
        )
    for path, _, expected_digest in files:
        if not path.is_file():
            raise RuntimeError(f"Missing vendored upstream license file: {path}")
        actual_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual_digest != expected_digest:
            raise RuntimeError(f"Vendored upstream license file changed: {path}")
    return files


def legal_files(package):
    package_root = Path(package["manifest_path"]).parent
    paths = {
        path
        for path in package_root.rglob("*")
        if path.is_file()
        and not any(part.startswith(".git") for part in path.relative_to(package_root).parts)
        and path.name.lower().startswith(LEGAL_FILE_PREFIXES)
    }

    license_file = package.get("license_file")
    if license_file:
        path = Path(license_file)
        if not path.is_absolute():
            path = package_root / path
        if not path.is_file():
            raise RuntimeError(f"Missing declared license file for {package['name']}")
        paths.add(path)

    return sorted(paths, key=lambda path: path.as_posix())


def release_dependencies():
    metadata = json.loads(run_cargo("metadata", "--locked", "--format-version", "1"))
    by_name_version = {}
    for package in metadata["packages"]:
        by_name_version.setdefault((package["name"], package["version"]), []).append(package)

    tree = run_cargo(
        "tree",
        "--locked",
        "--target",
        TARGET,
        "--edges",
        "normal,build",
        "--package",
        "baffle-proxy",
        "--prefix",
        "none",
        "--format",
        "{p}",
    )

    workspace_members = set(metadata["workspace_members"])
    selected = {}
    for line in tree.splitlines():
        fields = line.split()
        if len(fields) < 2 or not fields[1].startswith("v"):
            raise RuntimeError(f"Could not parse cargo tree package line: {line}")
        key = (fields[0], fields[1][1:])
        candidates = by_name_version.get(key, [])
        if len(candidates) != 1:
            raise RuntimeError(f"Expected one Cargo metadata package for {key}, found {len(candidates)}")
        package = candidates[0]
        if package["id"] not in workspace_members:
            selected[package["id"]] = package

    if not selected:
        raise RuntimeError("Cargo reported no external release dependencies")
    return sorted(selected.values(), key=lambda p: (p["name"].casefold(), p["version"]))


def write_bundle(output_path, packages):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as output:
        output.write(
            (
                "Third-party notices for the Baffle x86_64-unknown-linux-gnu release\n"
                "\n"
                "This file covers every non-workspace package in baffle-proxy's locked "
                "normal and build dependency graph for this target. Cargo resolves the "
                "graph from Cargo.lock. Each package keeps its declared license. The "
                "MIT license in the archive root applies to Baffle's original code.\n"
            ).encode("utf-8")
        )

        for package in packages:
            package_name = package["name"]
            version = package["version"]
            license_expression = package.get("license")
            if not license_expression and not package.get("license_file"):
                raise RuntimeError(f"Missing license metadata for {package_name} {version}")

            shipped_files = legal_files(package)
            if shipped_files:
                source_files = [
                    (path, f"crate source file {path.relative_to(Path(package['manifest_path']).parent)}")
                    for path in shipped_files
                ]
            else:
                upstream_files = pinned_upstream_files(package)
                if not upstream_files:
                    raise RuntimeError(
                        f"No license or notice file found for {package_name} {version} "
                        f"({license_expression or package['license_file']})"
                    )
                source_files = [(path, origin) for path, origin, _ in upstream_files]

            output.write(
                (
                    f"\n\n{'=' * 78}\n"
                    f"Package: {package_name} {version}\n"
                    f"Declared license: {license_expression or package['license_file']}\n"
                    f"Cargo source: {package.get('source') or 'path dependency'}\n"
                    f"Repository: {package.get('repository') or '(not declared)'}\n"
                ).encode("utf-8")
            )
            for path, origin in source_files:
                body = path.read_bytes()
                if b"\x00" in body:
                    raise RuntimeError(f"License or notice file is not text: {path}")
                output.write(
                    (
                        f"\n----- BEGIN {path.name} ({origin}) -----\n"
                    ).encode("utf-8")
                )
                output.write(body)
                if not body.endswith(b"\n"):
                    output.write(b"\n")
                output.write(f"----- END {path.name} -----\n".encode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    packages = release_dependencies()
    output_path = args.output if args.output.is_absolute() else ROOT / args.output
    write_bundle(output_path, packages)
    print(f"Wrote notices for {len(packages)} locked release dependencies to {output_path}")


if __name__ == "__main__":
    main()
