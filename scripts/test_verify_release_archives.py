import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
VERIFY_SCRIPT = REPO_ROOT / "scripts" / "verify-release-archives.sh"
TAG = "v1.0.0"
TARGET_ARCHIVES = [
    f"baffle-proxy-{TAG}-x86_64-unknown-linux-gnu.tar.gz",
    f"baffle-proxy-{TAG}-aarch64-unknown-linux-gnu.tar.gz",
    f"baffle-proxy-{TAG}-aarch64-apple-darwin.tar.gz",
]
REQUIRED_FILES = {
    "./LICENSE": b"MIT\n",
    "./share/doc/baffle/README.md": b"Baffle docs\n",
    "./share/doc/baffle/docs/releasing.md": b"Release docs\n",
    "./share/doc/baffle/examples/daemon.toml": b"[daemon]\n",
    "./share/doc/baffle/licenses/THIRD-PARTY-NOTICES.txt": b"Notices\n",
    "./share/doc/baffle/licenses/webpki-root-certs-CDLA-Permissive-2.0.txt": b"License\n",
}


class VerifyReleaseArchivesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.dist = self.root / "dist"
        self.dist.mkdir()
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.write_mock_tool(
            "file",
            """#!/usr/bin/env python3
from pathlib import Path
import sys

path = Path(sys.argv[-1])
architecture = {
    b"x86": "ELF 64-bit LSB pie executable, x86-64",
    b"arm": "ELF 64-bit LSB pie executable, ARM aarch64",
    b"mac": "Mach-O 64-bit arm64 executable",
}.get(path.read_bytes(), "unknown executable format")
print(f"{path}: {architecture}")
""",
        )
        self.write_mock_tool(
            "readelf",
            """#!/usr/bin/env python3
import sys

if "-l" in sys.argv:
    print("[Requesting program interpreter: /lib/ld-linux-aarch64.so.1]")
elif "--version-info" in sys.argv:
    print("Name: GLIBC_2.17")
    print("Name: GLIBC_2.34")
else:
    raise SystemExit(2)
""",
        )

    def tearDown(self):
        self.temporary.cleanup()

    def write_mock_tool(self, name, source):
        path = self.tools / name
        path.write_text(source, encoding="utf-8")
        path.chmod(0o755)

    def create_archive(
        self,
        filename,
        executable,
        *,
        arm_glibc_record=False,
        glibc_symbol="GLIBC_2.34",
    ):
        archive_path = self.dist / filename
        with tarfile.open(archive_path, "w:gz") as archive:
            files = dict(REQUIRED_FILES)
            files["./baffle"] = executable
            if arm_glibc_record:
                files["./share/doc/baffle/GLIBC-ABI.txt"] = (
                    b"Executable: baffle\n"
                    + b"Linkage: dynamically linked to glibc\n"
                    + f"Minimum required glibc symbol version: {glibc_symbol}\n".encode()
                )
            for name, data in sorted(files.items()):
                info = tarfile.TarInfo(name)
                info.mode = 0o755 if name == "./baffle" else 0o644
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return archive_path

    def create_complete_set(
        self, *, arm_executable=b"arm", arm_glibc_symbol="GLIBC_2.34"
    ):
        self.create_archive(TARGET_ARCHIVES[0], b"x86")
        self.create_archive(
            TARGET_ARCHIVES[1],
            arm_executable,
            arm_glibc_record=True,
            glibc_symbol=arm_glibc_symbol,
        )
        self.create_archive(TARGET_ARCHIVES[2], b"mac")

    def run_verifier(self):
        environment = os.environ.copy()
        environment["PATH"] = f"{self.tools}:{environment['PATH']}"
        return subprocess.run(
            [str(VERIFY_SCRIPT), TAG, str(self.dist)],
            cwd=REPO_ROOT,
            capture_output=True,
            check=False,
            text=True,
            env=environment,
        )

    def test_verifies_three_archives_and_combined_checksums(self):
        self.create_complete_set()

        result = self.run_verifier()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("minimum required symbol version: GLIBC_2.34", result.stdout)
        checksum_lines = (self.dist / "SHA256SUMS").read_text().splitlines()
        self.assertEqual(len(checksum_lines), 3)
        self.assertEqual(
            {line.split(maxsplit=1)[1].lstrip("* ") for line in checksum_lines},
            set(TARGET_ARCHIVES),
        )

    def test_rejects_missing_arm64_archive(self):
        self.create_complete_set()
        (self.dist / TARGET_ARCHIVES[1]).unlink()

        result = self.run_verifier()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Expected exactly 3 release archives", result.stderr)

    def test_rejects_extra_archive(self):
        self.create_complete_set()
        self.create_archive(f"baffle-proxy-{TAG}-riscv64-unknown-linux-gnu.tar.gz", b"x86")

        result = self.run_verifier()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Expected exactly 3 release archives", result.stderr)

    def test_rejects_wrong_arm64_architecture(self):
        self.create_complete_set(arm_executable=b"x86")

        result = self.run_verifier()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Wrong Linux ARM64 executable architecture", result.stderr)

    def test_rejects_glibc_record_that_does_not_match_executable(self):
        self.create_complete_set(arm_glibc_symbol="GLIBC_2.17")

        result = self.run_verifier()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not report its executable's glibc symbol requirement", result.stderr)


if __name__ == "__main__":
    unittest.main()
