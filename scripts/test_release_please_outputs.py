import json
import unittest

from scripts.release_please_outputs import OutputError, pull_request_branches


class ReleasePleaseOutputTests(unittest.TestCase):
    def test_single_pull_request_payload(self):
        branches = pull_request_branches(
            "true",
            json.dumps([{"headBranchName": "release-please--branches--main"}]),
            json.dumps({"headBranchName": "release-please--branches--main"}),
        )
        self.assertEqual(branches, [{"headBranchName": "release-please--branches--main"}])

    def test_documented_multi_pull_request_output(self):
        branches = pull_request_branches(
            "true",
            json.dumps(
                [
                    {"headBranchName": "release-please--components--client"},
                    {"headBranchName": "release-please--components--proxy"},
                ]
            ),
            "",
        )
        self.assertEqual(
            branches,
            [
                {"headBranchName": "release-please--components--client"},
                {"headBranchName": "release-please--components--proxy"},
            ],
        )

    def test_single_pull_request_output_is_fallback_when_prs_is_absent(self):
        branches = pull_request_branches(
            "true", "", json.dumps({"headBranchName": "release-please--branches--main"})
        )
        self.assertEqual(branches, [{"headBranchName": "release-please--branches--main"}])

    def test_no_pull_request_with_empty_or_absent_outputs(self):
        self.assertEqual(pull_request_branches("false", "", ""), [])
        self.assertEqual(pull_request_branches("false", None, None), [])

    def test_created_pull_request_requires_a_branch_payload(self):
        with self.assertRaisesRegex(OutputError, "no pull request payload"):
            pull_request_branches("true", "", "")


if __name__ == "__main__":
    unittest.main()
