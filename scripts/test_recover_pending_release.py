import io
import json
import unittest
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
        return self.existing_tag_sha

    def release(self, _tag):
        return self.existing_release

    def create_release(self, tag, sha, notes):
        self.created.append((tag, sha, notes))
        self.existing_tag_sha = sha
        self.existing_release = {"tag_name": tag, "draft": False, "prerelease": False}
        return self.existing_release

    def set_release_labels(self, pr):
        self.updated_labels.append(pr["number"])


class FakeRegistry:
    def __init__(self, states=None):
        missing = publish_crates.RegistryState(False, False)
        self.states = states or {"baffle-client": missing, "baffle-proxy": missing}
        self.checked = []

    def state(self, crate, _version):
        self.checked.append(crate)
        return self.states[crate]


class RecoverPendingReleaseTests(unittest.TestCase):
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
        registry = FakeRegistry()
        outputs = recover_pending_release.recover_pending_release(github, registry)
        self.assertEqual(outputs, {"release_created": "false", "tag_name": "", "sha": ""})
        self.assertEqual(registry.checked, [])
        self.assertEqual(github.created, [])

    def test_recovers_exact_merged_release_and_updates_pending_labels(self):
        github = FakeGitHub()
        registry = FakeRegistry()
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            outputs = recover_pending_release.recover_pending_release(github, registry)

        self.assertEqual(outputs, {"release_created": "true", "tag_name": TAG, "sha": SHA})
        self.assertEqual(github.created, [(TAG, SHA, "Verified notes.")])
        self.assertEqual(github.updated_labels, [47])
        self.assertEqual(registry.checked, ["baffle-client", "baffle-proxy"])
        self.assertIn(f"{TAG} at {SHA}", output.getvalue())

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
