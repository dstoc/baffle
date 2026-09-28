import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import publish_crates, recover_pending_release


VERSION = "0.3.0"
TAG = f"v{VERSION}"
SHA = "a" * 40


def release_pr(number=47):
    return {
        "number": number,
        "title": "chore: release main",
        "head": {"ref": "release-please--branches--main"},
        "base": {"ref": "main"},
        "merged_at": "2026-09-28T11:55:43Z",
        "merge_commit_sha": SHA,
        "labels": [
            {"name": recover_pending_release.RELEASE_PENDING},
            {"name": recover_pending_release.FORCE_RUN},
        ],
        "body": (
            ":robot: I have created a release *beep* *boop*\n---\n"
            f"<details><summary>{VERSION}</summary>\n\nRelease notes.\n</details>\n\n---\n"
            + recover_pending_release.RELEASE_PLEASE_FOOTER
        ),
    }


class FakeGitHub:
    def __init__(self, prs=None, *, tag_sha=None, release=None, manifest=None):
        self.prs = [release_pr()] if prs is None else prs
        self.existing_tag_sha = tag_sha
        self.existing_release = release
        self.created = []
        self.created_tags = []
        self.github_writes = []
        self.events = []
        self.tag_create_error = None
        self.tag_after_create_error = None
        self.updated_labels = []
        self.manifest = manifest or {".": VERSION, "crates/baffle-client": VERSION}
        self.files = {
            ".release-please-manifest.json": json.dumps(self.manifest),
            "release-please-config.json": json.dumps(
                {
                    "include-component-in-tag": False,
                    "packages": {".": {}, "crates/baffle-client": {}},
                }
            ),
            "Cargo.toml": (
                '[package]\nname="baffle-proxy"\nversion="0.3.0"\n'
                '[dependencies.baffle-client]\nversion="0.3.0"\npath="crates/baffle-client"\n'
            ),
            "crates/baffle-client/Cargo.toml": '[package]\nname="baffle-client"\nversion="0.3.0"\n',
            "Cargo.lock": (
                'version = 4\n\n[[package]]\nname = "baffle-proxy"\nversion = "0.3.0"\n\n'
                '[[package]]\nname = "baffle-client"\nversion = "0.3.0"\n'
            ),
            "CHANGELOG.md": (
                "# Changelog\n\n## [0.3.0](https://example.test/compare) (2026-09-28)\n\n"
                "Verified notes.\n\n## [0.2.0](https://example.test/compare) (2026-09-27)\n\nOld notes.\n"
            ),
        }

    def pending_release_prs(self):
        return self.prs

    def file_at(self, path, _ref):
        return self.files[path]

    def tag_sha(self, _tag):
        self.events.append("tag_sha")
        return self.existing_tag_sha

    def release(self, _tag):
        self.events.append("release")
        return self.existing_release

    def create_tag_ref(self, tag, sha):
        self.events.append("create_tag_ref")
        self.github_writes.append("create_tag_ref")
        if self.tag_create_error:
            self.existing_tag_sha = self.tag_after_create_error
            raise self.tag_create_error
        self.created_tags.append((tag, sha))
        self.existing_tag_sha = sha
        return {"ref": f"refs/tags/{tag}", "object": {"type": "commit", "sha": sha}}

    def create_release(self, tag, notes):
        self.events.append("create_release")
        self.github_writes.append("create_release")
        self.created.append((tag, notes))
        self.existing_release = {"tag_name": tag, "draft": False, "prerelease": False}
        return self.existing_release

    def set_release_labels(self, pr):
        self.updated_labels.append(pr["number"])


class FakeRegistry:
    def __init__(self, states=None, *, token="test-token"):
        missing = publish_crates.RegistryState(False, False)
        self.states = states or {"baffle-client": missing, "baffle-proxy": missing}
        self.token = token
        self.checked = []

    def state(self, crate, _version):
        self.checked.append(crate)
        return self.states[crate]


class RecoverPendingReleaseTests(unittest.TestCase):
    def test_github_api_creates_tag_ref_and_release_without_target_commitish(self):
        requests = []

        class FakeResponse:
            def __init__(self, payload):
                self.payload = json.dumps(payload).encode()

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return self.payload

        def opener(request, timeout):
            requests.append(request)
            if request.full_url.endswith("/git/refs"):
                payload = {"ref": f"refs/tags/{TAG}", "object": {"type": "commit", "sha": SHA}}
            else:
                payload = {"tag_name": TAG}
            return FakeResponse(payload)

        github = recover_pending_release.GitHubApi("dstoc/baffle", "test-token", opener=opener)
        github.create_tag_ref(TAG, SHA)
        github.create_release(TAG, "Verified notes.")

        self.assertEqual([request.get_method() for request in requests], ["POST", "POST"])
        self.assertTrue(requests[0].full_url.endswith("/git/refs"))
        self.assertEqual(
            json.loads(requests[0].data),
            {"ref": f"refs/tags/{TAG}", "sha": SHA},
        )
        self.assertTrue(requests[1].full_url.endswith("/releases"))
        release_body = json.loads(requests[1].data)
        self.assertEqual(release_body["tag_name"], TAG)
        self.assertNotIn("target_commitish", release_body)

    def test_combined_component_summaries_accept_the_same_linked_version(self):
        pr = release_pr()
        pr["body"] = (
            "<details><summary>baffle-proxy: 0.3.0</summary>Proxy notes.</details>\n"
            "<details><summary>baffle-client: 0.3.0</summary>Client notes.</details>\n"
            + recover_pending_release.RELEASE_PLEASE_FOOTER
        )
        self.assertEqual(recover_pending_release.release_version_from_pr(pr), VERSION)

    def test_combined_pr_with_different_component_versions_is_rejected(self):
        pr = release_pr()
        pr["body"] = (
            "<details><summary>baffle-proxy: 0.3.0</summary>Proxy notes.</details>\n"
            "<details><summary>baffle-client: 0.4.0</summary>Client notes.</details>\n"
            + recover_pending_release.RELEASE_PLEASE_FOOTER
        )
        with self.assertRaisesRegex(recover_pending_release.RecoveryError, "multiple versions"):
            recover_pending_release.release_version_from_pr(pr)

    def test_no_pending_release_does_not_query_crates_or_write_github(self):
        github = FakeGitHub(prs=[])
        registry = FakeRegistry(token="")
        outputs = recover_pending_release.recover_pending_release(github, registry)
        self.assertEqual(outputs, {"release_created": "false", "tag_name": "", "sha": ""})
        self.assertEqual(registry.checked, [])
        self.assertEqual(github.created, [])

    def test_missing_registry_token_stops_before_checks_or_github_writes(self):
        github = FakeGitHub()
        registry = FakeRegistry(token="")

        with self.assertRaisesRegex(recover_pending_release.RecoveryError, "CARGO_REGISTRY_TOKEN is empty or missing"):
            recover_pending_release.recover_pending_release(github, registry)

        self.assertEqual(registry.checked, [])
        self.assertEqual(github.github_writes, [])

    def test_failure_details_are_sanitized_in_annotation_and_job_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            summary_path = Path(directory) / "summary.md"
            stderr = io.StringIO()
            with patch("sys.stderr", stderr):
                recover_pending_release.report_failure(
                    RuntimeError("crate API rejected token hidden-token\n<response>"),
                    token="hidden-token",
                    summary_path=str(summary_path),
                )

            output = stderr.getvalue()
            summary = summary_path.read_text(encoding="utf-8")

        self.assertIn("::error title=Release recovery failed::", output)
        self.assertIn("%0A", output)
        self.assertNotIn("hidden-token", output)
        self.assertNotIn("hidden-token", summary)
        self.assertIn("&lt;response&gt;", summary)

    def test_recovers_exact_merged_release_and_updates_pending_labels(self):
        github = FakeGitHub()
        registry = FakeRegistry()
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            outputs = recover_pending_release.recover_pending_release(github, registry)

        self.assertEqual(outputs, {"release_created": "true", "tag_name": TAG, "sha": SHA})
        self.assertEqual(github.created_tags, [(TAG, SHA)])
        self.assertEqual(github.created, [(TAG, "Verified notes.")])
        self.assertEqual(github.github_writes, ["create_tag_ref", "create_release"])
        tag_created_at = github.events.index("create_tag_ref")
        tag_verified_at = github.events.index("tag_sha", tag_created_at + 1)
        release_created_at = github.events.index("create_release")
        self.assertLess(tag_created_at, tag_verified_at)
        self.assertLess(tag_verified_at, release_created_at)
        self.assertEqual(github.updated_labels, [47])
        self.assertEqual(registry.checked, ["baffle-client", "baffle-proxy"])
        self.assertIn(f"{TAG} at {SHA}", output.getvalue())

    def test_existing_exact_tag_is_reused_before_creating_release(self):
        github = FakeGitHub(tag_sha=SHA)
        outputs = recover_pending_release.recover_pending_release(github, FakeRegistry())

        self.assertEqual(outputs["release_created"], "true")
        self.assertEqual(github.created_tags, [])
        self.assertEqual(github.created, [(TAG, "Verified notes.")])
        self.assertEqual(github.github_writes, ["create_release"])

    def test_tag_create_conflict_is_reused_only_when_ref_matches_verified_sha(self):
        github = FakeGitHub()
        github.tag_create_error = recover_pending_release.GitHubApiError(422, "ref already exists")
        github.tag_after_create_error = SHA

        outputs = recover_pending_release.recover_pending_release(github, FakeRegistry())

        self.assertEqual(outputs["release_created"], "true")
        self.assertEqual(github.created, [(TAG, "Verified notes.")])
        self.assertEqual(github.github_writes, ["create_tag_ref", "create_release"])

    def test_tag_create_conflict_with_wrong_ref_stops_before_release(self):
        github = FakeGitHub()
        github.tag_create_error = recover_pending_release.GitHubApiError(422, "ref already exists")
        github.tag_after_create_error = "b" * 40

        with self.assertRaisesRegex(recover_pending_release.RecoveryError, "not the Release Please merge SHA"):
            recover_pending_release.recover_pending_release(github, FakeRegistry())

        self.assertEqual(github.created, [])
        self.assertEqual(github.github_writes, ["create_tag_ref"])

    def test_existing_exact_release_is_idempotent(self):
        existing = {"tag_name": TAG, "draft": False, "prerelease": False}
        github = FakeGitHub(tag_sha=SHA, release=existing)
        registry = FakeRegistry()
        outputs = recover_pending_release.recover_pending_release(github, registry)
        self.assertEqual(outputs["release_created"], "true")
        self.assertEqual(github.created, [])
        self.assertEqual(github.updated_labels, [47])

    def test_dry_run_does_not_create_release_or_change_labels(self):
        github = FakeGitHub()
        outputs = recover_pending_release.recover_pending_release(github, FakeRegistry(), dry_run=True)
        self.assertEqual(outputs, {"release_created": "true", "tag_name": TAG, "sha": SHA})
        self.assertEqual(github.created, [])
        self.assertEqual(github.updated_labels, [])

    def test_wrong_existing_tag_is_never_overwritten(self):
        github = FakeGitHub(tag_sha="b" * 40)
        with self.assertRaisesRegex(recover_pending_release.RecoveryError, "not the Release Please merge SHA"):
            recover_pending_release.recover_pending_release(github, FakeRegistry())
        self.assertEqual(github.created, [])
        self.assertEqual(github.updated_labels, [])

    def test_inconsistent_release_manifest_stops_before_registry_or_github_writes(self):
        github = FakeGitHub(manifest={".": VERSION, "crates/baffle-client": "0.4.0"})
        registry = FakeRegistry()
        with self.assertRaisesRegex(recover_pending_release.RecoveryError, "does not identify both packages"):
            recover_pending_release.recover_pending_release(github, registry)
        self.assertEqual(registry.checked, [])
        self.assertEqual(github.created, [])

    def test_multiple_pending_release_prs_are_not_guessed(self):
        github = FakeGitHub(prs=[release_pr(47), release_pr(48)])
        with self.assertRaisesRegex(recover_pending_release.RecoveryError, "multiple merged"):
            recover_pending_release.recover_pending_release(github, FakeRegistry())
        self.assertEqual(github.created, [])

    def test_proxy_only_crates_io_publication_stops_before_release_creation(self):
        client_missing = publish_crates.RegistryState(False, False)
        proxy_exists = publish_crates.RegistryState(True, True)
        registry = FakeRegistry({"baffle-client": client_missing, "baffle-proxy": proxy_exists})
        github = FakeGitHub()
        with self.assertRaisesRegex(recover_pending_release.RecoveryError, "out-of-order"):
            recover_pending_release.recover_pending_release(github, registry)
        self.assertEqual(github.created, [])
        self.assertEqual(github.updated_labels, [])


if __name__ == "__main__":
    unittest.main()
