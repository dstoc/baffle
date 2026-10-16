import json
import unittest

from scripts.release_please_outputs import OutputError, pull_request_branches


RELEASE_BRANCH = "release-please--branches--main--components--baffle-proxy"


class ReleasePleaseOutputTests(unittest.TestCase):
    def test_current_single_package_pull_request_payload(self):
        branches = pull_request_branches(
            "true",
            json.dumps([{"headBranchName": RELEASE_BRANCH}]),
            json.dumps({"headBranchName": RELEASE_BRANCH}),
        )
        self.assertEqual(branches, [{"headBranchName": RELEASE_BRANCH}])

    def test_multiple_release_pull_requests_are_rejected(self):
        with self.assertRaisesRegex(OutputError, "single-package Release Please config"):
            pull_request_branches(
                "true",
                json.dumps(
                    [
                        {"headBranchName": "release-please--components--client"},
                        {"headBranchName": "release-please--components--proxy"},
                    ]
                ),
                "",
            )

    def test_single_pull_request_output_is_fallback_when_prs_is_absent(self):
        branches = pull_request_branches(
            "true", "", json.dumps({"headBranchName": RELEASE_BRANCH})
        )
        self.assertEqual(branches, [{"headBranchName": RELEASE_BRANCH}])

    def test_no_pull_request_with_empty_or_absent_outputs(self):
        self.assertEqual(pull_request_branches("false", "", ""), [])
        self.assertEqual(pull_request_branches("false", None, None), [])

    def test_created_pull_request_requires_a_branch_payload(self):
        with self.assertRaisesRegex(OutputError, "no pull request payload"):
            pull_request_branches("true", "", "")


if __name__ == "__main__":
    unittest.main()
