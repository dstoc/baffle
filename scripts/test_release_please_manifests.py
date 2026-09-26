import json
import re
import tomllib
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = (REPO_ROOT / "Cargo.toml", REPO_ROOT / "crates/baffle-client/Cargo.toml")
DEPENDENCY_SECTIONS = {"dependencies", "dev-dependencies", "build-dependencies"}


class ReleasePleaseManifestTests(unittest.TestCase):
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
        self.assertEqual(
            config["packages"],
            {
                ".": {
                    "package-name": "baffle-proxy",
                    "component": "baffle-proxy",
                    "changelog-path": "CHANGELOG.md",
                },
                "crates/baffle-client": {
                    "package-name": "baffle-client",
                    "component": "baffle-client",
                    "skip-changelog": True,
                },
            },
        )
        self.assertEqual(
            config["plugins"],
            [
                {"type": "cargo-workspace", "merge": False},
                {
                    "type": "linked-versions",
                    "groupName": "baffle",
                    "components": ["baffle-proxy", "baffle-client"],
                },
            ],
        )
        self.assertEqual(
            manifest,
            {
                ".": root["package"]["version"],
                "crates/baffle-client": client["package"]["version"],
            },
        )
        self.assertEqual(manifest["."], manifest["crates/baffle-client"])
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
