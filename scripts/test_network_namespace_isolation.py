import contextlib
import importlib.util
import io
from pathlib import Path
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("check-network-namespace-isolation.py")
SPEC = importlib.util.spec_from_file_location("network_namespace_check", SCRIPT)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class ParseListenerRowsTests(unittest.TestCase):
    def test_parses_ipv4_and_ipv6_listeners_owned_by_daemon(self):
        output = """LISTEN 0 128 127.0.0.1:43123 0.0.0.0:* users:((\"baffle\",pid=42,fd=8))
LISTEN 0 128 [::1]:43124 [::]:* users:((\"baffle\",pid=42,fd=9))
LISTEN 0 128 127.0.0.1:43125 0.0.0.0:* users:((\"other\",pid=99,fd=4))
"""

        self.assertEqual(
            CHECK.parse_listener_rows(42, output),
            [("127.0.0.1", 43123), ("::1", 43124)],
        )


class NamespaceInvariantTests(unittest.TestCase):
    def run_check(self, namespaces, listeners):
        output = io.StringIO()
        error = io.StringIO()
        with (
            mock.patch.object(CHECK.sys, "argv", [str(SCRIPT), "42", "84"]),
            mock.patch.object(CHECK.os, "readlink", side_effect=namespaces),
            mock.patch.object(CHECK, "listener_rows", return_value=listeners),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(error),
        ):
            CHECK.main()
        return output.getvalue()

    def test_passes_for_separate_namespaces_without_tcp_listeners(self):
        output = self.run_check(["net:[100]", "net:[200]"], [])

        self.assertIn("different network namespaces", output)
        self.assertIn("Baffle has no internal TCP listeners", output)

    def test_fails_when_namespaces_are_shared(self):
        with (
            self.assertRaises(SystemExit),
            mock.patch.object(CHECK.sys, "argv", [str(SCRIPT), "42", "84"]),
            mock.patch.object(CHECK.os, "readlink", side_effect=["net:[100]", "net:[100]"]),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            CHECK.main()

    def test_fails_when_baffle_has_any_tcp_listener(self):
        with self.assertRaises(SystemExit):
            self.run_check(["net:[100]", "net:[200]"], [("127.0.0.1", 43123)])


if __name__ == "__main__":
    unittest.main()
