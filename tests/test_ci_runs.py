"""
CI results outside GitHub: result.json (ci/ci_result.py), the pull-request
comment (ci/pr_comment.py), and the dashboard's CI runs tab (pipeline.sync_ci_runs
and its API), against a fake GitHub Actions API.

Run:  python3 -m tests.test_ci_runs      (needs git and fastapi; no network)
"""
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAILURES = []
STRIPE = "sk_live_" + "51HxYzAbCdEfGhIjKlMnOpQr"


def check(label, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}" + (f"  ({detail})" if detail and not cond else ""))
    if not cond:
        FAILURES.append(label)


def git(root, *a):
    return subprocess.run(["git", "-C", str(root), *a], capture_output=True, text=True, check=True).stdout.strip()


def run_py(script, *args, env=None):
    proc = subprocess.run([sys.executable, str(ROOT / script), *args], capture_output=True, text=True,
                          env={**os.environ, **(env or {})})
    return proc.returncode, proc.stdout + proc.stderr


def blocked_result(pr=4, sha="a" * 40):
    return {"schema": 1, "tool": "secret-sentinel", "repository": "acme/shop", "event": "pull_request",
            "branch": "feature/pay", "pr_number": pr, "sha": sha, "run_url": "https://github.com/acme/shop/actions/runs/1",
            "scope": "changes since 0bf04893d705", "fail_on": "high", "status": "blocked",
            "commit_author": "Priya Shah", "scanned_at": "30 Sep 2026, 08:00 PM UTC",
            "counts": {"total": 1, "gating": 1, "baselined": 0},
            "findings": [{"source": "code", "rule_id": "stripe-key", "description": "Stripe API Key",
                          "severity": "high", "file_path": "pay.py", "line_number": 2,
                          "value_masked": "sk_l************…OpQr", "status": "new", "gating": True}]}


def passed_result(sha="b" * 40):
    return {**blocked_result(sha=sha), "status": "passed", "counts": {"total": 0, "gating": 0, "baselined": 0},
            "findings": []}


def test_result_file():
    print("1) result.json combines both scans")
    from app.cli import main as cli
    repo = Path(tempfile.mkdtemp()) / "shop"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.email", "priya@example.com")
    git(repo, "config", "user.name", "Priya Shah")
    (repo / "pay.py").write_text(f'KEY = "{STRIPE}"\n')
    git(repo, "add", "-A")
    git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-qm", "Add payments")
    out = Path(tempfile.mkdtemp())
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        code_rc = cli(["scan-path", str(repo), "--annotations", "off", "--json-out", str(out / "code.json")])
        hist_rc = cli(["scan-history", str(repo), "--annotations", "off", "--json-out", str(out / "history.json")])
    check("both scans exit 1", code_rc == 1 and hist_rc == 1, (code_rc, hist_rc))
    code = json.loads((out / "code.json").read_text())
    check("--json-out records the gate", code["blocked"] is True and code["findings"][0]["gating"] is True, code)
    rc, log = run_py("ci/ci_result.py", str(out), str(code_rc), str(hist_rc), "full", env={
        "GITHUB_REPOSITORY": "acme/shop", "GITHUB_EVENT_NAME": "pull_request", "GITHUB_RUN_ID": "77",
        "PR_NUMBER": "4", "PR_HEAD_SHA": "c" * 40, "GITHUB_HEAD_REF": "feature/pay"})
    r = json.loads((out / "result.json").read_text())
    check("status blocked", r["status"] == "blocked", r["status"])
    check("PR number, head sha and branch", (r["pr_number"], r["sha"], r["branch"]) == (4, "c" * 40, "feature/pay"), r)
    check("run URL", r["run_url"] == "https://github.com/acme/shop/actions/runs/77", r["run_url"])
    check("commit author carried over", r["commit_author"] == "Priya Shah", r["commit_author"])
    check("findings from both scans, blocking first", [f["source"] for f in r["findings"]] == ["code", "history"]
          and r["counts"]["gating"] == 2, r["findings"])
    check("values stay masked", STRIPE not in (out / "result.json").read_text())
    run_py("ci/ci_result.py", str(out), "0", "2", "full")
    check("exit 2 -> error", json.loads((out / "result.json").read_text())["status"] == "error")
    run_py("ci/ci_result.py", str(out), "0", "0", "full")
    check("both 0 -> passed", json.loads((out / "result.json").read_text())["status"] == "passed")


def test_pr_comment(gh):
    print("2) Pull-request comment")
    tmp = Path(tempfile.mkdtemp())
    res = tmp / "result.json"
    env = {"GITHUB_REPOSITORY": "acme/shop", "PR_NUMBER": "4", "GITHUB_TOKEN": "t",
           "GITHUB_API_URL": f"http://127.0.0.1:{gh.port}/api"}
    comments = lambda: gh.comments.get("acme/shop#4", [])

    res.write_text(json.dumps(passed_result()))
    rc, log = run_py("ci/pr_comment.py", str(res), env=env)
    check("clean PR with no earlier comment: stays quiet", rc == 0 and comments() == [], log)

    res.write_text(json.dumps(blocked_result()))
    rc, log = run_py("ci/pr_comment.py", str(res), env=env)
    body = comments()[0]["body"] if comments() else ""
    check("blocked scan posts one comment", rc == 0 and len(comments()) == 1, log)
    check("comment names the secret and links the line",
          "Stripe API Key" in body and "/acme/shop/blob/" + "a" * 40 + "/pay.py#L2" in body, body)
    check("comment shows the masked value only", "sk_l************…OpQr" in body and STRIPE not in body)
    check("comment tells people what to do", "rotate each key" in body and ".sentinelignore" in body)

    rc, log = run_py("ci/pr_comment.py", str(res), env=env)
    check("next push updates the same comment", len(comments()) == 1 and "updated" in log, log)

    res.write_text(json.dumps(passed_result()))
    rc, log = run_py("ci/pr_comment.py", str(res), env=env)
    check("clean push turns it into 'resolved'", len(comments()) == 1 and "no new secrets" in comments()[0]["body"], log)

    gh.comments_forbidden = True
    res.write_text(json.dumps(blocked_result()))
    rc, log = run_py("ci/pr_comment.py", str(res), env=env)
    gh.comments_forbidden = False
    check("fork PR (read-only token): warns, exit 0", rc == 0 and "Could not comment" in log, log)

    rc, log = run_py("ci/pr_comment.py", str(res), env={**env, "PR_NUMBER": ""})
    check("not a pull request: no-op", rc == 0 and "not a pull request" in log, log)
    rc, log = run_py("ci/pr_comment.py", str(tmp / "missing.json"), env=env)
    check("missing result: warns, exit 0", rc == 0 and "no scan result" in log, log)


def test_sync(gh):
    print("3) Dashboard: CI runs read back from GitHub Actions")
    from app import db, pipeline
    repo_id = db.upsert_repo("https://github.com/acme/shop", "acme", "shop", "main")

    blocked_run = gh.add_run("acme", "shop", result=blocked_result(), event="pull_request", branch="feature/pay",
                             pr=4, created_at="2026-09-30T10:05:00Z")
    gh.add_run("acme", "shop", result=passed_result(), created_at="2026-09-30T10:04:00Z")
    running = gh.add_run("acme", "shop", status="in_progress", created_at="2026-09-30T10:06:00Z")
    gh.add_run("acme", "shop", status="completed", conclusion="failure", created_at="2020-01-01T00:00:00Z")
    gh.add_run("acme", "shop", result=passed_result(), workflow="Unit tests")

    r = pipeline.sync_ci_runs(repo_id, force=True)
    runs = {x["run_id"]: x for x in db.list_ci_runs(repo_id)}
    check("only the Secret scan workflow's runs are stored", r["runs"] == 4 and len(runs) == 4, r)
    check("blocked PR run: gate, PR, findings", runs[blocked_run]["gate"] == "blocked"
          and runs[blocked_run]["pr_number"] == 4 and runs[blocked_run]["gating_count"] == 1, runs[blocked_run])
    check("in-progress run shown as running", runs[running]["gate"] == "running", runs[running]["gate"])
    old = [x for x in runs.values() if x["run_created_at"].startswith("2020")][0]
    check("old run without an artifact: gate from its conclusion, not re-polled",
          old["gate"] == "failed" and old["has_result"] == 1, old)
    check("first sync replays no alerts", not any(a["kind"] == "ci_blocked" for a in db.list_alerts(repo_id)))
    check("token never sent to artifact storage", gh.blob_auth_headers and not any(gh.blob_auth_headers),
          gh.blob_auth_headers)

    r = pipeline.sync_ci_runs(repo_id)
    check("throttled right after a sync", r.get("skipped") == "recently synced", r)

    gh.set_run_result(running, blocked_result(pr=None, sha="d" * 40) | {"event": "push", "branch": "main"})
    new_run = gh.add_run("acme", "shop", result=passed_result(), created_at="2026-09-30T10:07:00Z")
    r = pipeline.sync_ci_runs(repo_id, force=True)
    runs = {x["run_id"]: x for x in db.list_ci_runs(repo_id)}
    check("finished run picks up its result", runs[running]["gate"] == "blocked" and runs[running]["has_result"] == 1,
          runs[running])
    check("new run appears", new_run in runs)
    alerts = [a for a in db.list_alerts(repo_id) if a["kind"] == "ci_blocked"]
    check("a newly blocked run raises one alert", len(alerts) == 1 and r["blocked_alerts"] == 1, alerts)
    check("alert names the secret, commit and run link", alerts and "Stripe API Key" in alerts[0]["message"]
          and "ddddddd" in alerts[0]["message"] and "/actions/runs/" in alerts[0]["message"], alerts)
    r = pipeline.sync_ci_runs(repo_id, force=True)
    check("no duplicate alert on the next sync", len([a for a in db.list_alerts(repo_id) if a["kind"] == "ci_blocked"]) == 1)

    gh.actions_forbidden = True
    pipeline.sync_ci_runs(repo_id, force=True)
    err = db.get_repo(repo_id)["ci_error"] or ""
    check("no Actions access: error stored with the fix", "Actions: Read" in err, err)
    gh.actions_forbidden = False
    pipeline.sync_ci_runs(repo_id, force=True)
    check("error clears once access works", db.get_repo(repo_id)["ci_error"] is None)
    return repo_id


def test_api(repo_id):
    print("4) API and page")
    from fastapi.testclient import TestClient
    from app import db, main as srv
    client = TestClient(srv.app)
    runs = client.get("/api/ci-runs").json()
    check("/api/ci-runs lists runs newest first with findings",
          len(runs) == 5 and isinstance(runs[0]["findings"], list)
          and runs[0]["run_created_at"] >= runs[-1]["run_created_at"], [r["run_created_at"] for r in runs])
    check("/api/ci-runs?repo_id filters", len(client.get(f"/api/ci-runs?repo_id={repo_id}").json()) == 5)
    s = client.get("/api/ci-summary").json()
    check("/api/ci-summary counts", s["repos_reporting"] == 1 and s["last_run"]["gate"] == "passed"
          and s["blocked_7d"] >= 0, s)
    check("/api/ci-sync (throttled) answers", client.post(f"/api/ci-sync?repo_id={repo_id}").status_code == 200)
    check("/api/ci-sync unknown repo -> 404", client.post("/api/ci-sync?repo_id=999").status_code == 404)
    check("/api/status names the workflow", client.get("/api/status").json()["ci_workflow"] == "Secret scan")
    page = client.get("/dashboard").text
    check("dashboard has the CI runs tab", 'id="tab-ci"' in page and "/api/ci-runs" in page)
    home = client.get("/").text
    check("start page reads the live CI summary", "/api/ci-summary" in home)
    db.delete_repo(repo_id)
    check("removing a repo removes its CI runs", client.get("/api/ci-runs").json() == [])


def main():
    for k in ("GITHUB_ACTIONS", "GITHUB_STEP_SUMMARY", "GITHUB_SHA", "GITHUB_REPOSITORY", "GITHUB_RUN_ID",
              "GITHUB_EVENT_NAME", "GITHUB_HEAD_REF", "GITHUB_REF_NAME", "PR_NUMBER", "PR_HEAD_SHA",
              "SMTP_HOST", "SLACK_WEBHOOK_URL", "SENTINEL_CI_WORKFLOW"):
        os.environ.pop(k, None)
    from app import db, history_scan
    from tests.git_backed_github import GitBackedGitHub
    tmp = Path(tempfile.mkdtemp())
    db.DB_PATH = tmp / "ci.db"
    history_scan.MIRROR_DIR = tmp / "mirrors"
    db.init_db()
    gh = GitBackedGitHub(tmp / "remote")
    gh.start()
    try:
        test_result_file()
        test_pr_comment(gh)
        repo_id = test_sync(gh)
        test_api(repo_id)
    finally:
        gh.stop()
    print(f"\n{'ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
