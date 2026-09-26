import io
import json
import subprocess
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from scripts import publish_crates


REPO_ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
RELEASE_VERSION = publish_crates.parse_manifest_versions(REPO_ROOT)["baffle-proxy"]
RELEASE_TAG = f"v{RELEASE_VERSION}"


class FakeResponse:
    def __init__(self, body):
        self.body = json.dumps(body).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.body


class FakeRegistry:
    def __init__(self, client=None, proxy=None):
        self.states = {
            "baffle-client": client or publish_crates.RegistryState(False, False),
            "baffle-proxy": proxy or publish_crates.RegistryState(False, False),
        }
        self.checked = []

    def state(self, crate, _version):
        self.checked.append(crate)
        return self.states[crate]

    def wait_for_version(self, crate, version):
        self.checked.append(f"wait:{crate}:{version}")


class PublishCratesTests(unittest.TestCase):
    def test_release_tag_requires_stable_three_part_semver(self):
        self.assertEqual(publish_crates.version_from_tag("v0.2.3"), "0.2.3")
        for tag in ("0.2.3", "v1.2", "v1.2.3-rc.1", "v01.2.3"):
            with self.subTest(tag=tag), self.assertRaises(publish_crates.PublishError):
                publish_crates.version_from_tag(tag)

    def test_checked_out_cargo_versions_match_release_tag(self):
        self.assertEqual(publish_crates.validate_tag_versions(RELEASE_TAG, REPO_ROOT), RELEASE_VERSION)
        with self.assertRaisesRegex(publish_crates.PublishError, "does not match"):
            wrong_version = "0.0.0" if RELEASE_VERSION != "0.0.0" else "0.0.1"
            publish_crates.validate_tag_versions(f"v{wrong_version}", REPO_ROOT)

    def test_release_verification_matches_github_release_and_tag_commit(self):
        completed = [
            subprocess.CompletedProcess([], 0, SHA + "\n", ""),
            subprocess.CompletedProcess([], 0, SHA + "\n", ""),
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 0, "", ""),
        ]
        with patch.object(
            publish_crates,
            "request_json",
            return_value={"tag_name": RELEASE_TAG, "draft": False, "prerelease": False},
        ), patch("scripts.publish_crates.subprocess.run", side_effect=completed) as run:
            self.assertEqual(
                publish_crates.verify_release("dstoc/baffle", RELEASE_TAG, SHA, REPO_ROOT, "gh-token"),
                RELEASE_VERSION,
            )
        self.assertEqual(
            run.call_args_list[0].args[0], ["git", "rev-parse", f"refs/tags/{RELEASE_TAG}^{{commit}}"]
        )
        self.assertEqual(run.call_args_list[1].args[0], ["git", "rev-parse", "HEAD"])
        self.assertEqual(run.call_args_list[3].args[0][-1], "refs/remotes/origin/main")

    def test_release_verification_rejects_a_github_prerelease(self):
        with patch.object(
            publish_crates,
            "request_json",
            return_value={"tag_name": RELEASE_TAG, "draft": False, "prerelease": True},
        ), patch("scripts.publish_crates.subprocess.run") as run:
            with self.assertRaisesRegex(publish_crates.PublishError, "prerelease"):
                publish_crates.verify_release("dstoc/baffle", RELEASE_TAG, SHA, REPO_ROOT, "gh-token")
        run.assert_not_called()

    def test_tag_versions_require_both_packages_and_registry_dependency_to_match(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "crates/baffle-client").mkdir(parents=True)
            (root / "Cargo.toml").write_text(
                '[package]\nname="baffle-proxy"\nversion="0.2.0"\n'
                '[dependencies]\nbaffle-client={version="0.1.0",path="crates/baffle-client"}\n'
            )
            (root / "crates/baffle-client/Cargo.toml").write_text(
                '[package]\nname="baffle-client"\nversion="0.2.0"\n'
            )
            with self.assertRaisesRegex(publish_crates.PublishError, "do not match"):
                publish_crates.parse_manifest_versions(root)

    def test_registry_check_rejects_a_crate_owned_by_a_different_project(self):
        def opener(request, timeout):
            self.assertEqual(timeout, 20)
            return FakeResponse({"crate": {"name": "baffle-client", "repository": "https://example.com/other"}})

        registry = publish_crates.CratesIo(opener=opener, sleep=lambda _seconds: None)
        with self.assertRaisesRegex(publish_crates.PublishError, "different repository"):
            registry.state("baffle-client", "0.2.0")

    def test_registry_check_requires_expected_repository_owner(self):
        responses = iter(
            [
                {"crate": {"name": "baffle-client", "repository": publish_crates.EXPECTED_REPOSITORY}},
                {"users": [{"login": "someone-else"}], "teams": []},
            ]
        )
        registry = publish_crates.CratesIo(
            opener=lambda _request, timeout: FakeResponse(next(responses)),
            sleep=lambda _seconds: None,
        )
        with self.assertRaisesRegex(publish_crates.PublishError, "expected owner"):
            registry.state("baffle-client", "0.2.0")

    def test_registry_check_accepts_matching_crate_owner_and_version(self):
        responses = iter(
            [
                {"crate": {"name": "baffle-client", "repository": publish_crates.EXPECTED_REPOSITORY}},
                {"users": [{"login": "dstoc"}], "teams": []},
                {"version": {"crate": "baffle-client", "num": "0.2.0", "yanked": False}},
            ]
        )
        seen_auth = []

        def opener(request, timeout):
            if request.full_url.endswith("/owners"):
                seen_auth.append(request.get_header("Authorization"))
            return FakeResponse(next(responses))

        registry = publish_crates.CratesIo(
            token="opaque-test-token",
            opener=opener,
            sleep=lambda _seconds: None,
        )
        self.assertEqual(
            registry.state("baffle-client", "0.2.0"),
            publish_crates.RegistryState(registered=True, version_exists=True),
        )
        self.assertEqual(seen_auth, ["opaque-test-token"])

    def test_unregistered_names_can_be_claimed_on_first_publish(self):
        def missing(_request, timeout):
            raise urllib.error.HTTPError("https://registry.test/crates/baffle-client", 404, "missing", {}, None)

        registry = publish_crates.CratesIo(
            opener=missing,
            sleep=lambda _seconds: None,
        )
        self.assertEqual(registry.state("baffle-client", "0.2.0"), publish_crates.RegistryState(False, False))

    def test_publication_order_is_client_then_proxy_and_proxy_needs_client(self):
        missing = publish_crates.RegistryState(False, False)
        self.assertEqual(publish_crates.plan_publication(missing, missing), ("baffle-client", "baffle-proxy"))
        partial = publish_crates.RegistryState(True, True)
        self.assertEqual(publish_crates.plan_publication(partial, missing), ("baffle-proxy",))
        with self.assertRaisesRegex(publish_crates.PublishError, "out-of-order"):
            publish_crates.plan_publication(missing, partial)

    def test_publish_records_success_and_skips_matching_versions(self):
        matching = publish_crates.RegistryState(True, True)
        registry = FakeRegistry(client=matching, proxy=matching)
        with patch.object(publish_crates, "run_cargo") as run_cargo:
            publish_crates.publish_release(RELEASE_TAG, REPO_ROOT, registry, "opaque-test-token")
        run_cargo.assert_not_called()

    def test_publish_checks_client_first_then_proxy_dry_run_and_publish(self):
        registry = FakeRegistry()
        calls = []
        with patch.object(publish_crates, "run_cargo", side_effect=lambda args, **_kwargs: calls.append(args)):
            publish_crates.publish_release(RELEASE_TAG, REPO_ROOT, registry, "opaque-test-token")
        self.assertEqual(
            calls,
            [
                ["publish", "--locked", "--package", "baffle-client"],
                ["publish", "--dry-run", "--locked", "--package", "baffle-proxy"],
                ["publish", "--locked", "--package", "baffle-proxy"],
            ],
        )

    def test_proxy_failure_after_client_reports_partial_release(self):
        registry = FakeRegistry()

        def fail_proxy_dry_run(args, **_kwargs):
            if args[-1] == "baffle-proxy" and "--dry-run" in args:
                raise publish_crates.PublishError("proxy packaging failed")

        with patch.object(publish_crates, "run_cargo", side_effect=fail_proxy_dry_run):
            with self.assertRaisesRegex(publish_crates.PublishError, "proxy packaging failed"):
                with patch("sys.stdout", new_callable=io.StringIO) as output:
                    publish_crates.publish_release(RELEASE_TAG, REPO_ROOT, registry, "opaque-test-token")
        self.assertIn("PARTIAL OR UNCONFIRMED RELEASE", output.getvalue())
        self.assertIn(f"baffle-client {RELEASE_VERSION}", output.getvalue())

    def test_proxy_failure_after_resumed_client_reports_partial_release(self):
        matching_client = publish_crates.RegistryState(True, True)
        registry = FakeRegistry(client=matching_client)

        def fail_proxy_dry_run(args, **_kwargs):
            if args[-1] == "baffle-proxy" and "--dry-run" in args:
                raise publish_crates.PublishError("proxy packaging failed")

        with patch.object(publish_crates, "run_cargo", side_effect=fail_proxy_dry_run):
            with self.assertRaisesRegex(publish_crates.PublishError, "proxy packaging failed"):
                with patch("sys.stdout", new_callable=io.StringIO) as output:
                    publish_crates.publish_release(RELEASE_TAG, REPO_ROOT, registry, "opaque-test-token")
        self.assertIn("PARTIAL OR UNCONFIRMED RELEASE", output.getvalue())
        self.assertIn(f"registry confirmed baffle-client {RELEASE_VERSION}", output.getvalue())
        self.assertIn(f"not yet uploaded: baffle-proxy {RELEASE_VERSION}", output.getvalue())

    def test_dry_run_does_not_receive_registry_token(self):
        observed = {}

        class Completed:
            returncode = 0
            stdout = ""
            stderr = ""

        def fake_run(_command, **kwargs):
            observed.update(kwargs["env"])
            return Completed()

        with patch.dict("os.environ", {"CARGO_REGISTRY_TOKEN": "ambient-test-token"}), patch(
            "scripts.publish_crates.subprocess.run", side_effect=fake_run
        ):
            publish_crates.run_cargo(["publish", "--dry-run"])
        self.assertNotIn("CARGO_REGISTRY_TOKEN", observed)

    def test_publish_command_receives_token_without_logging_it(self):
        observed = {}

        class Completed:
            returncode = 0
            stdout = ""
            stderr = ""

        def fake_run(_command, **kwargs):
            observed.update(kwargs["env"])
            return Completed()

        with patch("scripts.publish_crates.subprocess.run", side_effect=fake_run), patch(
            "sys.stdout", new_callable=io.StringIO
        ) as output:
            publish_crates.run_cargo(["publish"], token="opaque-test-token")
        self.assertEqual(observed["CARGO_REGISTRY_TOKEN"], "opaque-test-token")
        self.assertNotIn("opaque-test-token", output.getvalue())

    def test_workflow_exports_release_outputs_and_limits_secret_to_publish_step(self):
        workflow = (REPO_ROOT / ".github/workflows/release-please.yml").read_text()
        ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("release_created: ${{ steps.release.outputs.release_created }}", workflow)
        self.assertIn("tag_name: ${{ steps.release.outputs.tag_name }}", workflow)
        self.assertIn("sha: ${{ steps.release.outputs.sha }}", workflow)
        self.assertIn("needs.release-please.outputs.release_created == 'true'", workflow)
        self.assertIn("ref: ${{ needs.release-please.outputs.tag_name }}", workflow)
        self.assertIn("group: baffle-crates-io-publish", workflow)
        self.assertIn("validate-release:\n    needs: release-please", workflow)
        self.assertIn("uses: ./.github/workflows/ci.yml", workflow)
        self.assertIn("ref: ${{ needs.release-please.outputs.sha }}", workflow)
        self.assertIn("workflow_call:", ci)
        self.assertIn("ref: ${{ inputs.ref || github.sha }}", ci)
        namespace_job = ci.split("  namespace-integration:", 1)[1].split("  required-checks:", 1)[0]
        self.assertIn("ref: ${{ inputs.ref || github.sha }}", namespace_job)
        self.assertIn("needs: [release-please, validate-release]", workflow)
        self.assertIn("CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}", workflow)
        self.assertEqual(workflow.count("secrets.CARGO_REGISTRY_TOKEN"), 1)
        self.assertLess(
            workflow.index("name: Publish both crates to crates.io"),
            workflow.index("CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}"),
        )


if __name__ == "__main__":
    unittest.main()
