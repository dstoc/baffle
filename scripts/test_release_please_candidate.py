import json
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

from scripts.sync_release_please_candidate import CandidateError, synchronize_candidate


class ReleasePleaseCandidateTests(unittest.TestCase):
    def make_candidate(self, root: Path, version: str = "1.0.0") -> None:
        (root / "crates/baffle-client/src").mkdir(parents=True)
        (root / "src").mkdir()
        (root / "Cargo.toml").write_text(
            f'[package]\nname = "baffle-proxy"\nversion = "{version}"\n'
            '[workspace]\nmembers = ["crates/baffle-client"]\nresolver = "3"\n'
            '[dependencies]\nbaffle-client = { version = "0.2.0", path = "crates/baffle-client" }\n'
        )
        (root / "crates/baffle-client/Cargo.toml").write_text(
            '[package]\nname = "baffle-client"\nversion = "0.4.0"\n'
        )
        (root / "src/lib.rs").write_text("pub fn proxy() {}\n")
        (root / "crates/baffle-client/src/lib.rs").write_text("pub fn client() {}\n")
        (root / ".release-please-manifest.json").write_text(
            f'{{\n  ".": "{version}",\n  "crates/baffle-client": "0.4.0"\n}}\n'
        )
        (root / "Cargo.lock").write_text(
            'version = 4\n\n'
            '[[package]]\nname = "baffle-client"\nversion = "0.4.0"\n\n'
            f'[[package]]\nname = "baffle-proxy"\nversion = "{version}"\n'
            'dependencies = [\n "baffle-client",\n]\n\n'
            '[[package]]\nname = "unrelated"\nversion = "1.2.3"\n'
        )

    def test_generated_candidate_uses_the_root_version_for_both_crates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_candidate(root)

            self.assertTrue(synchronize_candidate(root))
            self.assertFalse(synchronize_candidate(root))

            root_manifest = tomllib.loads((root / "Cargo.toml").read_text())
            client_manifest = tomllib.loads(
                (root / "crates/baffle-client/Cargo.toml").read_text()
            )
            self.assertEqual(root_manifest["package"]["version"], "1.0.0")
            self.assertEqual(client_manifest["package"]["version"], "1.0.0")
            self.assertEqual(
                root_manifest["dependencies"]["baffle-client"],
                {"version": "1.0.0", "path": "crates/baffle-client"},
            )
            self.assertEqual(
                json.loads((root / ".release-please-manifest.json").read_text()),
                {".": "1.0.0"},
            )

            lockfile = tomllib.loads((root / "Cargo.lock").read_text())
            local_versions = {
                package["name"]: package["version"]
                for package in lockfile["package"]
                if package["name"] in {"baffle-proxy", "baffle-client"}
            }
            self.assertEqual(local_versions, {
                "baffle-proxy": "1.0.0",
                "baffle-client": "1.0.0",
            })
            self.assertEqual(
                next(package["version"] for package in lockfile["package"] if package["name"] == "unrelated"),
                "1.2.3",
            )

            metadata = subprocess.run(
                [
                    "cargo",
                    "metadata",
                    "--locked",
                    "--format-version",
                    "1",
                    "--manifest-path",
                    str(root / "Cargo.toml"),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            packages = json.loads(metadata.stdout)["packages"]
            self.assertEqual(
                {package["name"]: package["version"] for package in packages},
                {"baffle-proxy": "1.0.0", "baffle-client": "1.0.0"},
            )

    def test_release_output_fixtures_sync_patch_minor_and_breaking_changes(self):
        config = json.loads((Path(__file__).resolve().parents[1] / "release-please-config.json").read_text())
        self.assertEqual(set(config["packages"]), {"."})
        fixtures = (
            ("patch in client", "0.3.1", ("crates/baffle-client/src/lib.rs",)),
            ("minor in proxy", "0.4.0", ("src/lib.rs",)),
            ("breaking client only", "1.0.0", ("crates/baffle-client/src/lib.rs",)),
            ("breaking changes in both crates", "1.0.0", ("src/lib.rs", "crates/baffle-client/src/lib.rs")),
        )
        for scenario, version, changed_paths in fixtures:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.make_candidate(root, version)
                for path in changed_paths:
                    (root / path).write_text(f"// {scenario}\n")
                synchronize_candidate(root)

                root_manifest = tomllib.loads((root / "Cargo.toml").read_text())
                client_manifest = tomllib.loads((root / "crates/baffle-client/Cargo.toml").read_text())
                release_manifest = json.loads((root / ".release-please-manifest.json").read_text())
                self.assertEqual(root_manifest["package"]["version"], version)
                self.assertEqual(client_manifest["package"]["version"], version)
                self.assertEqual(root_manifest["dependencies"]["baffle-client"]["version"], version)
                self.assertEqual(release_manifest, {".": version})

    def test_manifest_and_root_cargo_version_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_candidate(root, "1.0.0")
            manifest = root / ".release-please-manifest.json"
            manifest.write_text('{".": "0.4.0"}\n')

            with self.assertRaisesRegex(CandidateError, "root manifest and Cargo package disagree"):
                synchronize_candidate(root)


if __name__ == "__main__":
    unittest.main()
