import re
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = REPO_ROOT / ".github/workflows"


class NetworkNamespaceWorkflowTests(unittest.TestCase):
    def test_namespace_integration_has_one_definition_in_ci(self):
        definitions = []
        for workflow in WORKFLOWS_DIR.glob("*.yml"):
            content = workflow.read_text()
            if re.search(r"^  namespace-integration:\s*$", content, re.MULTILINE):
                definitions.append(workflow.name)

        self.assertEqual(["ci.yml"], definitions)

        ci_workflow = (WORKFLOWS_DIR / "ci.yml").read_text()
        namespace_job = ci_workflow.split("  namespace-integration:", 1)[1].split(
            "\n  macos-unix-integration:", 1
        )[0]
        self.assertIn("name: Network namespace integration", namespace_job)
        self.assertIn(
            "run: sudo python3 scripts/test-network-namespace-isolation.py --binary target/debug/baffle",
            namespace_job,
        )

    def test_namespace_integration_uses_ci_triggers(self):
        ci_workflow = (WORKFLOWS_DIR / "ci.yml").read_text()

        for trigger in (
            "  workflow_call:",
            "  push:\n    branches: [main]",
            "  pull_request:",
            "  workflow_dispatch:",
        ):
            self.assertIn(trigger, ci_workflow)


if __name__ == "__main__":
    unittest.main()
