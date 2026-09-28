import json
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

from scripts.sync_release_please_candidate import CandidateError, synchronize_candidate


class ReleasePleaseCandidateTests(unittest.TestCase):
    def make_candidate(self, root: Path) -> None:
        (root / "crates/baffle-client/src").mkdir(parents=True)
        (root / "src").mkdir()
        (root / "Cargo.toml").write_text(
            '[package]\nname = "baffle-proxy"\nversion = "0.3.0"\n'
            '[workspace]\nmembers = ["crates/baffle-client"]\nresolver = "3"\n'
            '[dependencies]\nbaffle-client = { version = "0.2.0", path = "crates/baffle-client" }\n'
        )
        (root / "crates/baffle-client/Cargo.toml").write_text(
            '[package]\nname = "baffle-client"\nversion = "0.3.0"\n'
        )
        (root / "src/lib.rs").write_text("pub fn proxy() {}\n")
        (root / "crates/baffle-client/src/lib.rs").write_text("pub fn client() {}\n")
        (root / ".release-please-manifest.json").write_text(
            '{\n  ".": "0.3.0",\n  "crates/baffle-client": "0.2.0"\n}\n'
        )
        (root / "Cargo.lock").write_text(
            'version = 4\n\n'
            '[[package]]\nname = "baffle-client"\nversion = "0.2.0"\n\n'
            '[[package]]\nname = "baffle-proxy"\nversion = "0.3.0"\n'
            'dependencies = [\n "baffle-client",\n]\n\n'
            '[[package]]\nname = "unrelated"\nversion = "1.2.3"\n'
        )

    def test_generated_candidate_is_repaired_and_metadata_accepts_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_candidate(root)

            self.assertTrue(synchronize_candidate(root))
            self.assertFalse(synchronize_candidate(root))

            root_manifest = tomllib.loads((root / "Cargo.toml").read_text())
            client_manifest = tomllib.loads(
                (root / "crates/baffle-client/Cargo.toml").read_text()
            )
            self.assertEqual(root_manifest["package"]["version"], "0.3.0")
            self.assertEqual(client_manifest["package"]["version"], "0.3.0")
            self.assertEqual(
                root_manifest["dependencies"]["baffle-client"],
                {"version": "0.3.0", "path": "crates/baffle-client"},
            )
            self.assertEqual(
                json.loads((root / ".release-please-manifest.json").read_text()),
                {".": "0.3.0", "crates/baffle-client": "0.3.0"},
            )

            lockfile = tomllib.loads((root / "Cargo.lock").read_text())
            local_versions = {
                package["name"]: package["version"]
                for package in lockfile["package"]
                if package["name"] in {"baffle-proxy", "baffle-client"}
            }
            self.assertEqual(local_versions, {
                "baffle-proxy": "0.3.0",
                "baffle-client": "0.3.0",
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
                {"baffle-proxy": "0.3.0", "baffle-client": "0.3.0"},
            )

    def test_candidate_with_different_package_versions_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_candidate(root)
            client_manifest = root / "crates/baffle-client/Cargo.toml"
            client_manifest.write_text(client_manifest.read_text().replace("0.3.0", "0.2.0"))

            with self.assertRaisesRegex(CandidateError, "package versions differ"):
                synchronize_candidate(root)


if __name__ == "__main__":
    unittest.main()
