import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from benchmark_builds import (
    native_versions,
    paired_backend_order,
    unique_dependency_entries,
)


class PairedBackendOrderTests(unittest.TestCase):
    def test_alternates_backend_order_between_repeats(self):
        backends = ["hudsucker", "rama"]
        self.assertEqual(paired_backend_order(backends, 0), ["hudsucker", "rama"])
        self.assertEqual(paired_backend_order(backends, 1), ["rama", "hudsucker"])
        self.assertEqual(paired_backend_order(backends, 2), ["hudsucker", "rama"])
        self.assertEqual(backends, ["hudsucker", "rama"])

    def test_one_backend_keeps_its_order(self):
        self.assertEqual(paired_backend_order(["rama"], 1), ["rama"])


class DependencyEntryTests(unittest.TestCase):
    def test_repeat_node_marker_does_not_count_as_a_second_package(self):
        entries = unique_dependency_entries([
            "serde v1.0.0",
            "serde v1.0.0 (*)",
            "tokio v1.2.3",
            "",
        ])

        self.assertEqual(entries, ["serde v1.0.0", "tokio v1.2.3"])


class NativeVersionTests(unittest.TestCase):
    def test_records_libclang_library_separately_from_driver(self):
        with tempfile.TemporaryDirectory() as directory:
            library = Path(directory) / "libclang.so"
            library.touch()

            def fake_command(args, *, check=True):
                if args[0] == "clang":
                    return subprocess.CompletedProcess(args, 127, "", "not found")
                return subprocess.CompletedProcess(args, 0, f"{args[0]} version 1", "")

            with (
                patch.dict(os.environ, {"LIBCLANG_PATH": directory}),
                patch("benchmark_builds.command", side_effect=fake_command),
            ):
                versions = native_versions()

        self.assertEqual(versions["clang_driver"], "unavailable")
        self.assertEqual(versions["libclang"], str(library.resolve()))


if __name__ == "__main__":
    unittest.main()
