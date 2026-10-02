import json
import re
import tomllib
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = (REPO_ROOT / "Cargo.toml", REPO_ROOT / "crates/baffle-client/Cargo.toml")
DEPENDENCY_SECTIONS = {"dependencies", "dev-dependencies", "build-dependencies"}


class ReleasePleaseManifestTests(unittest.TestCase):
    def test_release_workflow_validates_generated_pull_request(self):
        workflow = (REPO_ROOT / ".github/workflows/release-please.yml").read_text()
        ci_workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text()

        self.assertIn("id: release", workflow)
        self.assertIn(
            "googleapis/release-please-action@8b8fd2cc23b2e18957157a9d923d75aa0c6f6ad5",
            workflow,
        )
        self.assertIn(
            "RELEASE_PLEASE_ACTION_SHA: 8b8fd2cc23b2e18957157a9d923d75aa0c6f6ad5",
            ci_workflow,
        )
        self.assertIn("package-lock.json", ci_workflow)
        self.assertIn("scripts/test_release_please_version_selection.cjs", ci_workflow)
        self.assertLess(
            ci_workflow.index("scripts/test_release_please_version_selection.cjs"),
            ci_workflow.index("name: Run tests"),
        )
        self.assertIn("recover_release:", workflow)
        self.assertIn("type: boolean", workflow)
        self.assertIn("default: false", workflow)
        self.assertIn("actions: write", workflow)
        self.assertIn(
            "prs_created: ${{ steps.release.outputs.prs_created }}", workflow
        )
        self.assertIn("PRS_JSON: ${{ steps.release.outputs.prs }}", workflow)
        self.assertIn("PR_JSON: ${{ steps.release.outputs.pr }}", workflow)
        self.assertNotIn("fromJSON(steps.release.outputs.pr)", workflow)
        self.assertIn(
            "fromJSON(needs.release-please.outputs.pull_requests)", workflow
        )
        self.assertIn(
            "run: python3 -m unittest scripts.test_release_please_outputs", workflow
        )
        self.assertIn(
            "if: ${{ needs.release-please.result == 'success' && needs.release-please.outputs.prs_created == 'true' }}",
            workflow,
        )
        self.assertIn("cargo metadata --locked --format-version 1", workflow)
        self.assertIn("python3 scripts/sync_release_please_candidate.py", workflow)
        self.assertIn("crates/baffle-client/Cargo.toml", workflow)
        self.assertIn(
            "python3 -m unittest scripts.test_release_please_manifests scripts.test_release_please_candidate",
            workflow,
        )
        self.assertLess(
            workflow.index("python3 scripts/sync_release_please_candidate.py"),
            workflow.index("cargo metadata --locked --format-version 1"),
        )
        self.assertIn('git push origin "HEAD:${RELEASE_PR_BRANCH}"', workflow)
        self.assertIn(
            "name: Dispatch Rust CI for generated release candidate", workflow
        )
        self.assertIn("gh workflow run ci.yml", workflow)
        self.assertIn('--ref "$RELEASE_PR_BRANCH"', workflow)
        self.assertIn('--field ref="$candidate_sha"', workflow)
        self.assertIn("workflow_dispatch:\n    inputs:\n      ref:", ci_workflow)
        self.assertLess(
            workflow.index("name: Commit synchronized release candidate"),
            workflow.index("name: Dispatch Rust CI for generated release candidate"),
        )
        self.assertIn("needs.synchronize-release-candidates.result == 'skipped'", workflow)

    def test_release_creation_calls_reusable_binary_packaging_at_exact_sha(self):
        release_please = (REPO_ROOT / ".github/workflows/release-please.yml").read_text()
        self.assertIn("package-binaries:", release_please)
        self.assertIn("needs: [release-please, validate-release]", release_please)
        self.assertIn(
            "needs.release-please.outputs.release_created == 'true'",
            release_please,
        )
        self.assertIn("uses: ./.github/workflows/release.yml", release_please)
        self.assertIn("tag: ${{ needs.release-please.outputs.tag_name }}", release_please)
        self.assertIn("release_sha: ${{ needs.release-please.outputs.sha }}", release_please)
        self.assertIn("contents: write", release_please)
        self.assertIn("pull-requests: read", release_please)

        self.assertNotIn(
            "needs: [release-please, validate-release, package-binaries]",
            release_please,
            "crates.io publication must not wait for binary packaging",
        )

    def test_reusable_binary_workflow_builds_only_the_two_native_targets(self):
        workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("workflow_call:", workflow)
        self.assertIn("tag:\n        description: Exact Release Please tag to package\n        required: true", workflow)
        self.assertIn('push:\n    tags: ["v*"]', workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn('if [[ -n "$INPUT_TAG" ]]', workflow)
        self.assertIn("x86_64-unknown-linux-gnu", workflow)
        self.assertIn("aarch64-apple-darwin", workflow)
        self.assertNotIn("x86_64-apple-darwin", workflow)
        self.assertNotIn("macos-13", workflow)
        self.assertIn("EXPECTED_SHA: ${{ inputs.release_sha }}", workflow)
        self.assertIn("ref: ${{ github.workflow_sha }}", workflow)
        self.assertIn("path: source", workflow)
        self.assertIn("BAFFLE_SOURCE_DIR: ${{ github.workspace }}/source", workflow)
        self.assertIn("actions/download-artifact@v4", workflow)
        self.assertIn("SHA256SUMS", workflow)
        self.assertIn("Verify both Cargo packages match the release tag", workflow)
        self.assertIn("ref: ${{ github.workflow_sha }}", workflow)
        self.assertIn("release-tools/scripts/publish_crates.py verify-versions --tag", workflow)
        self.assertIn("gh release upload", workflow)
        self.assertNotIn("--clobber", workflow)

    def test_native_macos_checks_gate_the_required_ci_status(self):
        workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("runs-on: macos-15", workflow)
        self.assertIn('test "$(uname -m)" = arm64', workflow)
        self.assertIn("RUSTFLAGS: --cfg baffle_integration_test", workflow)
        self.assertIn("--test daemon_proxy", workflow)
        self.assertIn(
            "needs: [checks, namespace-integration, macos-unix-integration, verify-release-packages]",
            workflow,
        )
        self.assertIn("MACOS_RESULT: ${{ needs.macos-unix-integration.result }}", workflow)
        self.assertIn("PACKAGES_RESULT: ${{ needs.verify-release-packages.result }}", workflow)

    def test_ci_builds_and_verifies_both_native_release_archives(self):
        workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text()
        verifier = (REPO_ROOT / "scripts/verify-release-archives.sh").read_text()

        self.assertIn("release-packages:", workflow)
        self.assertIn("runner: ubuntu-24.04", workflow)
        self.assertIn("runner: macos-15", workflow)
        self.assertIn("x86_64-unknown-linux-gnu", workflow)
        self.assertIn("aarch64-apple-darwin", workflow)
        self.assertNotIn("x86_64-apple-darwin", workflow)
        self.assertIn("verify-release-packages:", workflow)
        self.assertIn("actions/download-artifact@v4", workflow)
        self.assertIn("scripts/verify-release-archives.sh", workflow)

        for required_path in (
            "./baffle",
            "./LICENSE",
            "./share/doc/baffle/README.md",
            "./share/doc/baffle/docs/releasing.md",
            "./share/doc/baffle/examples/daemon.toml",
            "./share/doc/baffle/licenses/THIRD-PARTY-NOTICES.txt",
            "./share/doc/baffle/licenses/webpki-root-certs-CDLA-Permissive-2.0.txt",
        ):
            self.assertIn(required_path, verifier)
        self.assertIn("ELF 64-bit", verifier)
        self.assertIn("Mach-O 64-bit", verifier)
        self.assertIn("sha256sum --check SHA256SUMS", verifier)

    def test_workspace_versions_and_local_client_dependency_stay_in_lockstep(self):
        root = tomllib.loads((REPO_ROOT / "Cargo.toml").read_text())
        client = tomllib.loads((REPO_ROOT / "crates/baffle-client/Cargo.toml").read_text())

        self.assertEqual(root["package"]["version"], client["package"]["version"])
        self.assertEqual(
            root["dependencies"]["baffle-client"],
            {"version": client["package"]["version"], "path": "crates/baffle-client"},
        )

        config = json.loads((REPO_ROOT / "release-please-config.json").read_text())
        manifest = json.loads((REPO_ROOT / ".release-please-manifest.json").read_text())
        self.assertEqual(config["release-type"], "rust")
        self.assertFalse(config["include-component-in-tag"])
        self.assertTrue(config["separate-pull-requests"])
        self.assertEqual(
            config["packages"],
            {
                ".": {
                    "package-name": "baffle-proxy",
                    "component": "baffle-proxy",
                    "changelog-path": "CHANGELOG.md",
                }
            },
        )
        self.assertNotIn("plugins", config)
        self.assertEqual(manifest, {".": root["package"]["version"]})
        self.assertIn("crates/baffle-client", root["workspace"]["members"])

        lockfile = tomllib.loads((REPO_ROOT / "Cargo.lock").read_text())
        lock_versions = {
            package["name"]: package["version"]
            for package in lockfile["package"]
            if package["name"] in {"baffle-proxy", "baffle-client"}
        }
        self.assertEqual(lock_versions, {
            "baffle-proxy": root["package"]["version"],
            "baffle-client": client["package"]["version"],
        })
        proxy_lock = next(
            package for package in lockfile["package"] if package["name"] == "baffle-proxy"
        )
        self.assertIn("baffle-client", proxy_lock["dependencies"])

    def test_cratesio_metadata_and_bounded_package_contents_are_configured(self):
        for manifest_path, package_name, readme in (
            (MANIFESTS[0], "baffle-proxy", "README.md"),
            (MANIFESTS[1], "baffle-client", "README.md"),
        ):
            manifest = tomllib.loads(manifest_path.read_text())
            package = manifest["package"]
            self.assertEqual(package["name"], package_name)
            self.assertEqual(package["license"], "MIT")
            self.assertEqual(package["repository"], "https://github.com/dstoc/baffle")
            self.assertEqual(package["readme"], readme)
            self.assertEqual(package["documentation"], f"https://docs.rs/{package_name}")
            self.assertTrue(package["description"])
            self.assertTrue(package["include"])
            self.assertTrue((manifest_path.parent / package["readme"]).is_file())
            self.assertTrue((manifest_path.parent / "LICENSE").is_file())

        root_license = (REPO_ROOT / "LICENSE").read_bytes()
        client_license = (REPO_ROOT / "crates/baffle-client/LICENSE").read_bytes()
        self.assertEqual(client_license, root_license)

        root_package = tomllib.loads((REPO_ROOT / "Cargo.toml").read_text())["package"]
        self.assertIn("LICENSE", root_package["include"])
        self.assertIn("!bench/**", root_package["include"])
        self.assertNotIn(".github/**", root_package["include"])
        client_package = tomllib.loads(MANIFESTS[1].read_text())["package"]
        self.assertIn("examples/**", client_package["include"])
        self.assertIn("LICENSE", client_package["include"])

    def test_rama_dependency_settings_are_preserved(self):
        manifest = tomllib.loads((REPO_ROOT / "Cargo.toml").read_text())

        self.assertEqual(
            manifest["dependencies"]["rama"],
            {
                "version": "=0.4.0",
                "default-features": False,
                "features": ["http-full", "boring"],
            },
        )

    def test_dependency_inline_tables_are_single_line(self):
        for manifest_path in MANIFESTS:
            section = None
            for line_number, line in enumerate(manifest_path.read_text().splitlines(), 1):
                header = re.match(r"^\s*\[([^]]+)\]\s*$", line)
                if header:
                    section = header.group(1).rsplit(".", 1)[-1]
                    continue

                if section not in DEPENDENCY_SECTIONS:
                    continue

                if re.match(r"^\s*[^#=]+\s*=\s*\{", line):
                    if not re.search(r"\}\s*(?:#.*)?$", line):
                        relative_path = manifest_path.relative_to(REPO_ROOT)
                        self.fail(
                            f"{relative_path}:{line_number}: dependency inline table "
                            "must close on its opening line"
                        )


if __name__ == "__main__":
    unittest.main()
