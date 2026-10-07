"""
Try the dashboard without GitHub: a fake GitHub backed by local git repos,
with a demo repository whose history already contains leaked secrets.

    python3 -m tests.demo_server            # then open http://localhost:8000/dashboard
    python3 -m tests.demo_server --port 8080

Paste https://github.com/acme/payments into the dashboard; its CI runs tab
shows a few seeded GitHub Actions runs (blocked and passed). To see the
dashboard react to a push, commit into the printed repo path, e.g.

    cd <repo path> && echo 'TOKEN = "ghp_...36 chars..."' > leak.py && git add -A && git commit -m leak

then click Rescan (or wait for the poll, every 20 s here). Everything lives in
a temporary directory: no real GitHub calls, no emails, no changes to data/.
"""
import argparse
import os
import tempfile
from pathlib import Path


def build_demo(gh) -> Path:
    repo = gh.create_repo("acme", "payments")
    gh.commit(repo, {"app.py": "import os\n\nDB = os.environ['DATABASE_URL']\n",
                     "README.md": "# payments\n"}, "Initial commit")
    gh.commit(repo, {".env": "DATABASE_URL=postgres://admin:Pr0dPassw0rd9@db.internal:5432/payments\n"},
              "Add local config", author="Bob Ops <bob@example.com>")
    gh.commit(repo, {"billing.py": 'STRIPE_KEY = "sk_live_' + "51HxYzAbCdEfGhIjKlMnOpQr" + '"\n'},
              "Wire up Stripe", author="Carol Dev <carol@example.com>")
    gh.commit(repo, {".env": None}, "Remove .env", author="Bob Ops <bob@example.com>")
    gh.commit(repo, {"deploy.sh": "#!/bin/sh\nexport AWS_ACCESS_KEY_ID=AKIA" + "QYLPMN5HHHFPZAM2\n"},
              "Add deploy script", author="Eve Ops <eve@example.com>")
    return repo


def seed_ci_runs(gh, repo) -> None:
    """A few Secret scan runs, as GitHub Actions would report them, so the
    dashboard's CI runs tab and the start page have something to show."""
    import subprocess
    from datetime import datetime, timedelta, timezone
    shas = subprocess.run(["git", "-C", str(repo), "log", "--format=%H"], capture_output=True,
                          text=True, check=True).stdout.split()
    now = datetime.now(timezone.utc)
    at = lambda minutes: (now - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    finding = lambda desc, rule, sev, path, line, masked, source="code": {
        "source": source, "rule_id": rule, "description": desc, "severity": sev, "file_path": path,
        "line_number": line, "value_masked": masked, "status": "new", "gating": True}
    base = {"schema": 1, "tool": "secret-sentinel", "repository": "acme/payments", "fail_on": "high",
            "scanned_at": "just now"}
    runs = [
        (95, "push", "main", shas[-1], None, "Initial commit", "passed", "Alice Dev", [], "full scan"),
        (70, "pull_request", "feature/billing", shas[1], 7, "Wire up Stripe", "blocked", "Carol Dev",
         [finding("Stripe API Key", "stripe-key", "high", "billing.py", 1, "sk_l************…OpQr")],
         "changes since 1c2d3e4f5a6b"),
        (40, "push", "main", shas[0], None, "Add deploy script", "blocked", "Eve Ops",
         [finding("AWS Access Key ID", "aws-access-key-id", "critical", "deploy.sh", 2, "AKIA************ZAM2"),
          finding("AWS Access Key ID", "aws-access-key-id", "critical", "deploy.sh", 2, "AKIA************ZAM2",
                  "history")], "changes since 6ab51b1c2d3e"),
        (12, "pull_request", "docs/readme", shas[0], 9, "Update README", "passed", "Dan Lee", [],
         "changes since a2b3b3adebae"),
    ]
    for minutes, event, branch, sha, pr, title, status, author, found, scope in runs:
        result = {**base, "event": event, "branch": branch, "pr_number": pr, "sha": sha, "scope": scope,
                  "status": status, "commit_author": author,
                  "counts": {"total": len(found), "gating": len(found), "baselined": 0}, "findings": found}
        run_id = gh.add_run("acme", "payments", result=result, event=event, branch=branch, sha=sha, pr=pr,
                            created_at=at(minutes), title=title, actor=author.split()[0].lower())
        result["run_url"] = f"https://github.com/acme/payments/actions/runs/{run_id}"
        gh.set_run_result(run_id, result)
    gh.add_run("acme", "payments", status="in_progress", event="pull_request", branch="feature/refunds",
               sha=shas[0], pr=11, created_at=at(1), title="Add refunds", actor="priya")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="sentinel-demo-"))
    # Set before importing the app: .env never overrides variables already set,
    # so a real SMTP/Slack config in .env is not used by the demo.
    from tests.git_backed_github import GitBackedGitHub
    gh = GitBackedGitHub(tmp / "remote")
    gh.start()
    for k in ("SMTP_HOST", "SLACK_WEBHOOK_URL", "ALERT_WEBHOOK_URL", "GITHUB_TOKEN", "GITHUB_WEBHOOK_SECRET"):
        os.environ[k] = ""
    os.environ.setdefault("POLL_INTERVAL_SECONDS", "20")
    repo = build_demo(gh)
    seed_ci_runs(gh, repo)

    import uvicorn
    from app import db, history_scan, main as app_main
    db.DB_PATH = tmp / "demo.db"
    history_scan.MIRROR_DIR = tmp / "mirrors"

    print(f"\nDemo repository: https://github.com/acme/payments  (served from {repo})")
    print(f"Dashboard:       http://localhost:{args.port}/dashboard\n")
    uvicorn.run(app_main.app, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
