"""
Git-history scanning tests: secrets that were committed and later deleted must
still be found, attributed to the commit/author that introduced them, and
marked as no longer present in the current code.

Run:  python3 -m tests.test_history      (needs git; no other dependencies)
"""
import json
import subprocess
import tempfile
from pathlib import Path

FAILURES = []


def check(label, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}" + (f"  ({detail})" if detail and not cond else ""))
    if not cond:
        FAILURES.append(label)


def build_repo() -> Path:
    """A repo whose history contains secrets that were later deleted."""
    root = Path(tempfile.mkdtemp()) / "demo"
    root.mkdir()
    git = lambda *a, **kw: subprocess.run(["git", "-C", str(root), *a], capture_output=True, check=True, **kw)
    git("init", "-q", "-b", "main")
    git("config", "user.email", "alice@example.com")
    git("config", "user.name", "Alice Dev")

    # c1: a DB URL with credentials
    (root / ".env").write_text("DATABASE_URL=postgres://admin:SuperSecret1@db.prod:5432/app\n")
    (root / "app.py").write_text("import os\nprint('hi')\n")
    git("add", "-A"); git("commit", "-qm", "Add initial config")

    # c2: a Stripe key and an AWS key, by a different author
    git("config", "user.email", "bob@example.com")
    git("config", "user.name", "Bob Ops")
    (root / "deploy.sh").write_text(
        "#!/bin/sh\nexport STRIPE_KEY=sk_live_51HxYzAbCdEfGhIjKlMn\n"
        "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
    git("add", "-A"); git("commit", "-qm", "Add deploy script")

    # c3: delete .env entirely (secret leaves the code, stays in history)
    git("rm", "-q", ".env")
    git("commit", "-qm", "Remove .env from the repo")

    # c4: edit the Stripe key out of deploy.sh, keep the AWS one
    (root / "deploy.sh").write_text(
        "#!/bin/sh\nexport STRIPE_KEY=$STRIPE_KEY\n"
        "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
    git("add", "-A"); git("commit", "-qm", "Read Stripe key from the environment")

    # c5: a secret that is still present in the current code
    (root / "settings.yml").write_text("api_key: aB3xK9mQ7pL2wR5tY8uI\n")
    git("add", "-A"); git("commit", "-qm", "Add settings")
    return root


def main():
    import os
    from app import db, history_scan, pipeline

    if not history_scan.git_available():
        print("git not available — skipping")
        return 0

    tmp = Path(tempfile.mkdtemp())
    db.DB_PATH = tmp / "hist.db"
    history_scan.MIRROR_DIR = tmp / "mirrors"
    db.init_db()
    for k in ("SLACK_WEBHOOK_URL", "ALERT_WEBHOOK_URL", "SMTP_HOST", "GITHUB_TOKEN"):
        os.environ.pop(k, None)

    repo_root = build_repo()
    repo_id = db.upsert_repo("https://github.com/acme/demo", "acme", "demo", "main")

    print("1) Scan the full git history")
    result = pipeline.run_history_scan(repo_id, clone_url=f"file://{repo_root}")
    check("scan completes", result["state"] == "done", result)
    check("walked all 5 commits", result["total_commits"] == 5, result["total_commits"])
    check("current tree was readable", result["head_tree_readable"])

    rows = db.list_history_findings(repo_id)
    by_rule = {r["rule_id"]: r for r in rows}
    print(f"     found {len(rows)} secrets: {sorted(by_rule)}")

    print("2) Every secret ever committed is found — including deleted ones")
    for rule in ("db-url-with-credentials", "stripe-key", "aws-access-key-id"):
        check(f"finds {rule}", rule in by_rule, sorted(by_rule))
    check("finds the still-present api_key",
          any(r["file_path"] == "settings.yml" for r in rows), [r["file_path"] for r in rows])
    check("at least 4 distinct secrets", len(rows) >= 4, len(rows))

    print("3) Deleted-vs-present status")
    dburl = by_rule.get("db-url-with-credentials", {})
    check("deleted .env secret marked NOT present", dburl.get("still_present") == 0, dburl.get("still_present"))
    check("deleted .env secret records the removing commit", bool(dburl.get("removed_commit_sha")),
          dburl.get("removed_commit_sha"))
    stripe = by_rule.get("stripe-key", {})
    check("edited-out Stripe key marked NOT present", stripe.get("still_present") == 0, stripe.get("still_present"))
    aws = by_rule.get("aws-access-key-id", {})
    check("AWS key still in code marked present", aws.get("still_present") == 1, aws.get("still_present"))
    stats = db.history_stats(repo_id)
    check("stats split present/history-only", stats["history_only"] >= 2 and stats["present"] >= 2, stats)

    print("4) Commit attribution")
    check("DB URL attributed to Alice", dburl.get("first_author_name") == "Alice Dev", dburl.get("first_author_name"))
    check("Stripe key attributed to Bob", stripe.get("first_author_name") == "Bob Ops", stripe.get("first_author_name"))
    check("introducing commit subject recorded",
          dburl.get("first_commit_subject") == "Add initial config", dburl.get("first_commit_subject"))
    check("introducing commit sha recorded", len(dburl.get("first_commit_sha") or "") == 40,
          dburl.get("first_commit_sha"))
    check("commit date recorded", bool(dburl.get("first_commit_date")), dburl.get("first_commit_date"))
    check("file path recorded", dburl.get("file_path") == ".env", dburl.get("file_path"))
    check("line number recorded", dburl.get("line_number") == 1, dburl.get("line_number"))
    check("value is masked", "SuperSecret1" not in (dburl.get("matched_text") or ""), dburl.get("matched_text"))

    print("5) Per-secret commit trail")
    commits = json.loads(dburl["commits_json"])
    actions = {c["action"] for c in commits}
    check("commit trail has both add and remove", actions == {"added", "removed"}, actions)
    check("trail entries carry author + subject",
          all(c.get("author_name") and c.get("subject") for c in commits), commits[:2])
    check("occurrences counted", dburl.get("occurrences", 0) >= 2, dburl.get("occurrences"))

    print("6) Re-running updates in place (no duplicates)")
    again = pipeline.run_history_scan(repo_id, clone_url=f"file://{repo_root}")
    check("no new records on rescan", again["new_records"] == 0, again["new_records"])
    check("row count unchanged", len(db.list_history_findings(repo_id)) == len(rows), len(db.list_history_findings(repo_id)))
    check("mirror was reused (fetch, not re-clone)", (history_scan.MIRROR_DIR / "acme__demo.git").exists())

    print("7) A new commit adding a secret is picked up")
    subprocess.run(["git", "-C", str(repo_root), "config", "user.email", "eve@example.com"], check=True)
    subprocess.run(["git", "-C", str(repo_root), "config", "user.name", "Eve"], check=True)
    sendgrid_key = "SG." + "aB3xK9mQ7pL2wR5tY8uI3o"[:22] + "." + ("kP7mN2qR9tL4wX6yZ8vC3bF5hJ1dG0sA7eU" + "xYz12345")[:43]
    (repo_root / "extra.env").write_text(f"SENDGRID_KEY={sendgrid_key}\n")
    subprocess.run(["git", "-C", str(repo_root), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_root), "commit", "-qm", "oops"], check=True, capture_output=True)
    third = pipeline.run_history_scan(repo_id, clone_url=f"file://{repo_root}")
    check("new history secret detected", third["new_records"] == 1, third["new_records"])
    newrow = [r for r in db.list_history_findings(repo_id) if r["rule_id"] == "sendgrid-key"]
    check("new secret attributed to Eve", newrow and newrow[0]["first_author_name"] == "Eve",
          newrow[0]["first_author_name"] if newrow else None)
    check("alert recorded for history findings",
          any(a["kind"] == "history_secret" for a in db.list_alerts(repo_id)), db.list_alerts(repo_id)[:2])

    print("8) Presence filters used by the UI")
    only_hist = db.list_history_findings(repo_id, presence="history_only")
    present = db.list_history_findings(repo_id, presence="present")
    check("history_only filter", all(r["still_present"] in (0, None) for r in only_hist), len(only_hist))
    check("present filter", all(r["still_present"] == 1 for r in present), len(present))
    check("filters partition the rows", len(only_hist) + len(present) == len(db.list_history_findings(repo_id)))

    print("9) Severity ordering (critical first) for the UI table")
    sevs = [r["severity"] for r in db.list_history_findings(repo_id)]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    check("rows sorted by severity", sevs == sorted(sevs, key=lambda s: order.get(s, 9)), sevs)

    print("10) Failure handling")
    try:
        pipeline.run_history_scan(repo_id, clone_url="file:///nonexistent/nope.git")
        check("bad clone URL raises", False)
    except history_scan.HistoryScanError:
        check("bad clone URL raises", True)
    check("error recorded on the repo row", bool(db.get_repo(repo_id)["history_error"]))
    check("state is 'error'", db.get_repo(repo_id)["history_state"] == "error",
          db.get_repo(repo_id)["history_state"])
    check("token never leaks into an error message",
          "ghp_" not in (db.get_repo(repo_id)["history_error"] or ""))

    test_history_follows_new_commits(tmp)

    print(f"\n{'ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'}")
    return 1 if FAILURES else 0


def test_history_follows_new_commits(tmp: Path):
    """The poller / webhook path (scan_for_updates) must refresh the git-history
    view when new commits arrive, not only when a repo is first added."""
    import os
    from app import db, history_scan, pipeline
    from tests.git_backed_github import GitBackedGitHub

    print("11) History refreshes when new commits arrive (poller / webhook path)")
    db.DB_PATH = tmp / "follow.db"
    history_scan.MIRROR_DIR = tmp / "follow-mirrors"
    db.init_db()
    gh = GitBackedGitHub(tmp / "remote")
    gh.start()
    saved = os.environ.pop("HISTORY_SCAN_ON_PUSH", None)
    try:
        repo = gh.create_repo("acme", "live")
        gh.commit(repo, {"app.py": "print('hi')\n"}, "init")
        repo_id = pipeline.add_and_scan_repo("https://github.com/acme/live")["repo_id"]
        pipeline.run_history_scan(repo_id)                      # what adding a repo queues
        check("starts with no history findings", db.history_stats(repo_id)["total"] == 0,
              db.history_stats(repo_id))

        # A push adds a secret: code table and history table both pick it up.
        key = "AKIA" + "QYLPMN5HHHFPZAM2"
        gh.commit(repo, {"config.py": f'AWS_KEY = "{key}"\n'}, "add config", author="Eve <eve@example.com>")
        r = pipeline.scan_for_updates(repo_id)
        check("code scan sees the new secret", r["new_findings"] == 1, r)
        check("history refreshed on the new commit", r.get("history", {}).get("state") == "done", r.get("history"))
        rows = db.list_history_findings(repo_id)
        check("history lists the new secret, still in code",
              len(rows) == 1 and rows[0]["still_present"] == 1, rows)
        check("attributed to the pushing author", rows and rows[0]["first_author_name"] == "Eve",
              rows[0]["first_author_name"] if rows else None)

        # The secret is deleted: resolved in code, and history flips to "deleted from code".
        gh.commit(repo, {"config.py": "import os\nAWS_KEY = os.environ['AWS_KEY']\n"}, "use env var")
        r = pipeline.scan_for_updates(repo_id)
        check("code scan resolves it", r["removed_findings"] == 1, r)
        row = db.list_history_findings(repo_id)[0]
        check("history marks it deleted from code", row["still_present"] == 0, row["still_present"])
        check("history records the removing commit", len(row["removed_commit_sha"] or "") == 40,
              row["removed_commit_sha"])
        kinds = [a["kind"] for a in db.list_alerts(repo_id)]
        check("alert log has exposed, history and removed events",
              {"new_secret", "history_secret", "secret_removed"} <= set(kinds), kinds)
        check("resolved list has the secret", len(db.list_findings(repo_id=repo_id, status="removed")) == 1)

        # No new commits: no history re-walk.
        r = pipeline.scan_for_updates(repo_id)
        check("no new commits, no history rescan", "history" not in r, r.get("history"))

        # Opt-out.
        os.environ["HISTORY_SCAN_ON_PUSH"] = "false"
        gh.commit(repo, {"README.md": "docs\n"}, "docs")
        r = pipeline.scan_for_updates(repo_id)
        check("HISTORY_SCAN_ON_PUSH=false skips the refresh", "history" not in r, r.get("history"))
    finally:
        os.environ.pop("HISTORY_SCAN_ON_PUSH", None)
        if saved is not None:
            os.environ["HISTORY_SCAN_ON_PUSH"] = saved
        gh.stop()


if __name__ == "__main__":
    raise SystemExit(main())
