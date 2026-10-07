#!/usr/bin/env python3
"""
Combine one CI run's code and history reports into a single result.json.

    python3 ci/ci_result.py <results-dir> <code-exit> <history-exit> <scope>

Reads <results-dir>/code.json and history.json (written by `--json-out`) and
writes <results-dir>/result.json. The workflow uploads it with the run's
artifacts; the dashboard's "CI runs" tab and the pull-request comment
(ci/pr_comment.py) read it. Values are already masked. Stdlib only.
"""
import json
import os
import sys
from pathlib import Path

MAX_FINDINGS = 100
SCHEMA = 1


def _load(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _finding(f: dict, source: str) -> dict:
    keep = ("rule_id", "description", "severity", "file_path", "line_number", "value_masked",
            "status", "gating", "commit", "author", "still_present")
    return {"source": source, **{k: f.get(k) for k in keep if k in f}}


def build(results_dir: Path, code_rc: int, history_rc: int, scope: str) -> dict:
    code, history = _load(results_dir / "code.json"), _load(results_dir / "history.json")
    findings = ([_finding(f, "code") for f in code.get("findings", [])]
                + [_finding(f, "history") for f in history.get("findings", [])])
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (not f.get("gating"), order.get(f.get("severity"), 9)))

    if 2 in (code_rc, history_rc):
        status = "error"
    elif code_rc or history_rc:
        status = "blocked"
    else:
        status = "passed"

    env = os.environ.get
    repo = env("GITHUB_REPOSITORY", "")
    run_id = env("GITHUB_RUN_ID", "")
    pr = env("PR_NUMBER", "")
    meta = {**history, **code}   # commit author / times: same commit for both scans
    return {
        "schema": SCHEMA,
        "tool": "secret-sentinel",
        "repository": repo,
        "event": env("GITHUB_EVENT_NAME", ""),
        "branch": env("GITHUB_HEAD_REF") or env("GITHUB_REF_NAME", ""),
        "pr_number": int(pr) if pr.isdigit() else None,
        # On a pull request GITHUB_SHA is GitHub's temporary merge commit; the
        # PR head is the commit people recognise.
        "sha": env("PR_HEAD_SHA") or env("GITHUB_SHA", ""),
        "run_id": int(run_id) if run_id.isdigit() else None,
        "run_url": (f"{env('GITHUB_SERVER_URL', 'https://github.com')}/{repo}/actions/runs/{run_id}"
                    if repo and run_id else None),
        "scope": scope,
        "fail_on": code.get("fail_on") or history.get("fail_on") or env("SENTINEL_FAIL_ON", "high"),
        "status": status,
        "code_exit": code_rc,
        "history_exit": history_rc,
        "commit_author": meta.get("commit_author"),
        "commit_time": meta.get("commit_time"),
        "scanned_at": meta.get("scanned_at"),
        "counts": {
            "total": len(findings),
            "gating": sum(1 for f in findings if f.get("gating")),
            "baselined": sum(1 for f in findings if f.get("status") == "baselined"),
        },
        "findings": findings[:MAX_FINDINGS],
        "truncated": len(findings) > MAX_FINDINGS,
    }


def main(argv) -> int:
    if len(argv) != 5:
        print(__doc__, file=sys.stderr)
        return 2
    results_dir = Path(argv[1])
    result = build(results_dir, int(argv[2]), int(argv[3]), argv[4])
    (results_dir / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"result: {result['status']}, {result['counts']['gating']} blocking finding(s) "
          f"-> {results_dir / 'result.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
