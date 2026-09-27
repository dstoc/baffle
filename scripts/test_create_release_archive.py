import importlib.util
import os
from pathlib import Path
import tarfile
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_SCRIPT = REPO_ROOT / "scripts" / "create-release-archive.py"
SPEC = importlib.util.spec_from_file_location("release_archive", ARCHIVE_SCRIPT)
assert SPEC is not None and SPEC.loader is not None
RELEASE_ARCHIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE_ARCHIVE)


class ReleaseArchiveTests(unittest.TestCase):
    def test_archive_metadata_and_compression_are_reproducible(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage = root / "stage"
            (stage / "share/doc/baffle").mkdir(parents=True)
            executable = stage / "baffle"
            executable.write_bytes(b"native executable fixture")
            executable.chmod(0o755)
            (stage / "LICENSE").write_text("MIT\n", encoding="utf-8")
            (stage / "share/doc/baffle/README.md").write_text(
                "release docs\n", encoding="utf-8"
            )
            first = root / "first.tar.gz"
            second = root / "second.tar.gz"

            RELEASE_ARCHIVE.create_archive(stage, first)
            os.utime(executable, (123456789, 123456789))
            RELEASE_ARCHIVE.create_archive(stage, second)

            self.assertEqual(first.read_bytes(), second.read_bytes())
            with tarfile.open(first, "r:gz") as archive:
                self.assertEqual(
                    archive.getnames(),
                    [
                        "./LICENSE",
                        "./baffle",
                        "./share",
                        "./share/doc",
                        "./share/doc/baffle",
                        "./share/doc/baffle/README.md",
                    ],
                )
                self.assertEqual(archive.getmember("./baffle").mode & 0o777, 0o755)
                self.assertEqual(archive.getmember("./LICENSE").mode & 0o777, 0o644)
                self.assertEqual(archive.getmember("./baffle").mtime, 0)
                self.assertEqual(archive.getmember("./baffle").uid, 0)
                self.assertEqual(archive.extractfile("./LICENSE").read(), b"MIT\n")


if __name__ == "__main__":
    unittest.main()
