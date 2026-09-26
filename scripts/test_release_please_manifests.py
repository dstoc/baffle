import re
import tomllib
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = (REPO_ROOT / "Cargo.toml", REPO_ROOT / "crates/baffle-client/Cargo.toml")
DEPENDENCY_SECTIONS = {"dependencies", "dev-dependencies", "build-dependencies"}


class ReleasePleaseManifestTests(unittest.TestCase):
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
