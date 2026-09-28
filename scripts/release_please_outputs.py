"""Normalize optional Release Please pull-request outputs for workflow matrix use."""

import json
import os
import sys


class OutputError(ValueError):
    """The Release Please pull-request outputs do not match the documented shape."""


def _decode_json(raw, output_name):
    if raw is None or not raw.strip():
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as error:
        raise OutputError(f"Release Please {output_name} output is not valid JSON") from error


def pull_request_branches(prs_created, prs_json, pr_json):
    """Return normalized branch records from Release Please v4 action outputs."""
    if prs_created != "true":
        return []

    prs = _decode_json(prs_json, "prs")
    pr = _decode_json(pr_json, "pr")

    if prs is None or prs == []:
        candidates = [pr] if isinstance(pr, dict) else []
    elif isinstance(prs, list):
        candidates = prs
    else:
        raise OutputError("Release Please prs output must be a JSON array")

    if not candidates:
        raise OutputError("prs_created is true but no pull request payload was provided")

    branches = []
    seen = set()
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise OutputError("Release Please pull request entries must be JSON objects")
        branch = candidate.get("headBranchName")
        if not isinstance(branch, str) or not branch.strip():
            raise OutputError("Release Please pull request is missing headBranchName")
        if branch not in seen:
            branches.append({"headBranchName": branch})
            seen.add(branch)
    return branches


def main():
    try:
        branches = pull_request_branches(
            os.environ.get("PRS_CREATED", ""),
            os.environ.get("PRS_JSON", ""),
            os.environ.get("PR_JSON", ""),
        )
    except OutputError as error:
        print(error, file=sys.stderr)
        return 1

    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"pull_requests={json.dumps(branches, separators=(',', ':'))}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
