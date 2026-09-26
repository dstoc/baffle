import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_SCRIPT = REPO_ROOT / "scripts" / "package-release.sh"


class PackageReleaseTests(unittest.TestCase):
    def run_packager(self, tag: str) -> tuple[subprocess.CompletedProcess[str], bool]:
        with tempfile.TemporaryDirectory() as temporary_dir:
            output_dir = Path(temporary_dir) / "dist"
            result = subprocess.run(
                [str(PACKAGE_SCRIPT), tag, str(output_dir)],
                cwd=REPO_ROOT,
                capture_output=True,
                check=False,
                text=True,
            )
            return result, output_dir.exists()

    def test_rejects_non_stable_tag_before_build(self) -> None:
        result, output_dir_exists = self.run_packager("v0.1.0-rc.1")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Expected a stable vX.Y.Z release tag", result.stderr)
        self.assertFalse(output_dir_exists)

    def test_rejects_tag_that_does_not_match_cargo_version(self) -> None:
        result, output_dir_exists = self.run_packager("v99.99.99")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match baffle-proxy Cargo version", result.stderr)
        self.assertFalse(output_dir_exists)


if __name__ == "__main__":
    unittest.main()
