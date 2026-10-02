import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_SCRIPT = REPO_ROOT / "scripts" / "package-release.sh"


class PackageReleaseTests(unittest.TestCase):
    def run_packager(
        self, tag: str, target: str = "x86_64-unknown-linux-gnu"
    ) -> tuple[subprocess.CompletedProcess[str], bool]:
        with tempfile.TemporaryDirectory() as temporary_dir:
            output_dir = Path(temporary_dir) / "dist"
            result = subprocess.run(
                [str(PACKAGE_SCRIPT), tag, target, str(output_dir)],
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
        self.assertIn("does not match the checked-out Cargo versions", result.stderr)
        self.assertFalse(output_dir_exists)

    def test_rejects_the_incident_v0_4_tag_for_the_1_0_workspace(self) -> None:
        result, output_dir_exists = self.run_packager("v0.4.0")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Tag v0.4.0 does not match the checked-out Cargo versions", result.stderr)
        self.assertFalse(output_dir_exists)

    def test_rejects_unsupported_release_target(self) -> None:
        result, output_dir_exists = self.run_packager("v0.2.0", "x86_64-apple-darwin")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsupported release target", result.stderr)
        self.assertFalse(output_dir_exists)

    def test_rejects_cross_platform_relabeling(self) -> None:
        if not sys.platform.startswith("linux"):
            self.skipTest("this assertion checks Linux runner target matching")

        result, output_dir_exists = self.run_packager("v0.2.0", "aarch64-apple-darwin")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be built on Apple Silicon macOS", result.stderr)
        self.assertFalse(output_dir_exists)


if __name__ == "__main__":
    unittest.main()
