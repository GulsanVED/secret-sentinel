"""
End-to-end test of the real pipeline against a local fake GitHub API.

Run:  python3 -m tests.test_pipeline_e2e     (needs only httpx)

Simulates a repo's history: clean start -> secrets pushed -> one edited out
-> file deleted -> secret re-added -> force-push -> rate limit, and checks
the findings/alerts produced at each step.
"""
import hashlib
import json
import os
import re
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse


class FakeRepo:
    def __init__(self):
        self.commits = []          # list of (sha, {path: content}), oldest first
        self.rate_limited = False

    def commit(self, files):
        sha = hashlib.sha1(json.dumps([len(self.commits), files], sort_keys=True).encode()).hexdigest()
        self.commits.append((sha, dict(files)))
        return sha

    def force_push(self, files):
        """Rewrite history: drop all previous commits."""
        self.commits = []
        return self.commit(files)

    def snapshot(self, sha):
        for s, files in self.commits:
            if s == sha:
                return files
        return None

    @property
    def head(self):
        return self.commits[-1][0]


REPO = FakeRepo()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj, code=200, headers=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if REPO.rate_limited and path.startswith("/raw/"):
            return self._json({"message": "API rate limit exceeded"}, 403, {"x-ratelimit-remaining": "0"})

        if m := re.fullmatch(r"/api/repos/acme/demo", path):
            return self._json({"default_branch": "main"})
        if m := re.fullmatch(r"/api/repos/acme/demo/commits/main", path):
            return self._json({"sha": REPO.head})
        if m := re.fullmatch(r"/api/repos/acme/demo/git/trees/([0-9a-f]+)", path):
            snap = REPO.snapshot(m.group(1))
            if snap is None:
                return self._json({"message": "Not Found"}, 404)
            return self._json({"tree": [{"path": p, "type": "blob", "size": len(c)} for p, c in snap.items()],
                               "truncated": False})
        if m := re.fullmatch(r"/api/repos/acme/demo/compare/([0-9a-f]+)\.\.\.([0-9a-f]+)", path):
            base, head = REPO.snapshot(m.group(1)), REPO.snapshot(m.group(2))
            if base is None or head is None:
                return self._json({"message": "Not Found"}, 404)
            files = []
            for p in set(base) | set(head):
                if p not in head:
                    files.append({"filename": p, "status": "removed"})
                elif p not in base:
                    files.append({"filename": p, "status": "added"})
                elif base[p] != head[p]:
                    files.append({"filename": p, "status": "modified"})
            shas = [s for s, _ in REPO.commits]
            n = shas.index(m.group(2)) - shas.index(m.group(1))
            return self._json({"status": "ahead", "total_commits": n, "files": files})
        if m := re.fullmatch(r"/raw/acme/demo/([0-9a-f]+)/(.+)", path):
            snap = REPO.snapshot(m.group(1)) or {}
            p = unquote(m.group(2))
            if p not in snap:
                self.send_response(404); self.end_headers(); return
            body = snap[p].encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._json({"message": f"Not Found: {path}"}, 404)


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    os.environ["GITHUB_API_URL"] = f"http://127.0.0.1:{port}/api"
    os.environ["GITHUB_RAW_URL"] = f"http://127.0.0.1:{port}/raw"
    os.environ.pop("GITHUB_TOKEN", None)
    for k in ("SLACK_WEBHOOK_URL", "ALERT_WEBHOOK_URL", "SMTP_HOST"):
        os.environ.pop(k, None)
    os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"

    from app import db, pipeline
    from app.github_client import RateLimitError
    db.DB_PATH = Path(tempfile.mkdtemp()) / "test.db"
    db.init_db()

    failures = []

    def check(label, cond, detail=""):
        print(f"  [{'PASS' if cond else 'FAIL'}] {label}" + (f"  ({detail})" if detail and not cond else ""))
        if not cond:
            failures.append(label)

    def active():
        return {(f["file_path"], f["rule_id"]) for f in db.list_findings(status="active")}

    def alert_kinds():
        return [a["kind"] for a in db.list_alerts(limit=1000)]

    # 1. Clean repo
    print("1) Initial scan of a clean repo")
    REPO.commit({"README.md": "# demo\n", "src/app.py": "import os\nDB = os.environ['DATABASE_URL']\n"})
    r = pipeline.add_and_scan_repo("https://github.com/acme/demo")
    check("scans both files", r["files_scanned"] == 2, r)
    check("no findings", r["new_findings"] == 0 and not active(), active())

    # 2. Push a commit that exposes secrets
    print("2) Push a commit exposing a DB URL, a DB password and an API key")
    REPO.commit({
        "README.md": "# demo\n",
        "src/app.py": "import os\nDB = os.environ['DATABASE_URL']\n",
        ".env": "DATABASE_URL=postgres://admin:S3cretPass@db.prod.internal:5432/app\nDB_PASSWORD=S3cretPass\n",
        "config/settings.py": 'STRIPE_KEY = "sk_live_51HxYzAbCdEfGhIjKlMn"\nAPI_KEY = "a8f5f167f44f4964e6c998dee827110c"\n',
    })
    r = pipeline.incremental_scan(r["repo_id"])
    expected = {(".env", "db-url-with-credentials"), (".env", "generic-secret-assignment"),
                ("config/settings.py", "stripe-key"), ("config/settings.py", "generic-secret-assignment")}
    check("incremental scan picked up the new commit", r["mode"] == "incremental" and r["new_commits"] == 1, r)
    check("4 new findings", r["new_findings"] == 4, r)
    check("expected rules fired", active() == expected, active())
    check("4 new_secret alerts", alert_kinds().count("new_secret") == 4, alert_kinds())
    repo_id = r["repo_id"]

    # 3. No change -> nothing happens
    print("3) Poll again with no new commits")
    r = pipeline.incremental_scan(repo_id)
    check("no-op", r["new_commits"] == 0 and r["new_findings"] == 0 and len(active()) == 4, r)

    # 4. Edit one secret out of .env
    print("4) Commit that removes DB_PASSWORD from .env (file still exists)")
    REPO.commit({
        "README.md": "# demo\n", "src/app.py": "import os\nDB = os.environ['DATABASE_URL']\n",
        ".env": "DATABASE_URL=postgres://admin:S3cretPass@db.prod.internal:5432/app\n",
        "config/settings.py": 'STRIPE_KEY = "sk_live_51HxYzAbCdEfGhIjKlMn"\nAPI_KEY = "a8f5f167f44f4964e6c998dee827110c"\n',
    })
    r = pipeline.incremental_scan(repo_id)
    check("1 removed", r["removed_findings"] == 1, r)
    check("DB password no longer active", (".env", "generic-secret-assignment") not in active(), active())
    check("secret_removed alert raised", alert_kinds().count("secret_removed") == 1, alert_kinds())

    # 5. Delete a whole file
    print("5) Commit that deletes config/settings.py")
    REPO.commit({"README.md": "# demo\n", "src/app.py": "import os\nDB = os.environ['DATABASE_URL']\n",
                 ".env": "DATABASE_URL=postgres://admin:S3cretPass@db.prod.internal:5432/app\n"})
    r = pipeline.incremental_scan(repo_id)
    check("2 removed", r["removed_findings"] == 2, r)
    check("only the DB URL remains", active() == {(".env", "db-url-with-credentials")}, active())

    # 6. Secret comes back
    print("6) Commit that re-adds the same DB_PASSWORD")
    REPO.commit({"README.md": "# demo\n", "src/app.py": "import os\nDB = os.environ['DATABASE_URL']\n",
                 ".env": "DATABASE_URL=postgres://admin:S3cretPass@db.prod.internal:5432/app\nDB_PASSWORD=S3cretPass\n"})
    r = pipeline.incremental_scan(repo_id)
    check("flagged as re-introduced", r["reintroduced_findings"] == 1, r)
    check("secret_reintroduced alert", "secret_reintroduced" in alert_kinds(), alert_kinds())

    # 7. Rate limit mid-scan must NOT mark everything removed
    print("7) GitHub rate-limits file downloads during a full rescan")
    REPO.rate_limited = True
    before = active()
    try:
        pipeline.full_scan(repo_id)
        check("raises RateLimitError", False)
    except RateLimitError:
        check("raises RateLimitError", True)
    check("findings untouched (no false 'removed' alerts)", active() == before, active())
    check("error recorded on repo", "rate limit" in (db.get_repo(repo_id)["last_error"] or "").lower())
    REPO.rate_limited = False

    # 8. Force-push that scrubs the secrets from history
    print("8) Force-push rewriting history to remove the .env file")
    REPO.force_push({"README.md": "# demo\n", "src/app.py": "import os\nDB = os.environ['DATABASE_URL']\n"})
    r = pipeline.incremental_scan(repo_id)
    check("fell back to a full scan", r["mode"] == "full", r)
    check("everything resolved", not active() and r["removed_findings"] == 2, (active(), r))
    check("error cleared after success", db.get_repo(repo_id)["last_error"] is None)

    # 9. Fingerprints stable across process restarts (PYTHONHASHSEED)
    print("9) Fingerprints are stable across restarts")
    import subprocess, sys
    code = "from app import scanner; print(scanner.scan_text('.env','DB_PASSWORD=S3cretPass')[0].fingerprint)"
    outs = {subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                           env={**os.environ, "PYTHONHASHSEED": seed}).stdout.strip() for seed in ("1", "2", "3")}
    check("same fingerprint in 3 processes", len(outs) == 1, outs)

    # 10. URL parsing
    print("10) Repo URL formats")
    from app.github_client import parse_repo_url
    cases = {
        "https://github.com/acme/demo": ("acme", "demo", None),
        "https://github.com/acme/demo.git": ("acme", "demo", None),
        "https://github.com/acme/demo/": ("acme", "demo", None),
        "https://github.com/acme/demo/tree/feature-x": ("acme", "demo", "feature-x"),
        "https://github.com/acme/demo/blob/main/src/app.py": ("acme", "demo", "main"),
        "git@github.com:acme/demo.git": ("acme", "demo", None),
        "acme/demo": ("acme", "demo", None),
    }
    for url, exp in cases.items():
        p = parse_repo_url(url)
        got = (p["owner"], p["name"], p["branch"])
        check(url, got == exp, got)

    server.shutdown()
    print(f"\n{'ALL PASSED' if not failures else f'{len(failures)} FAILED: {failures}'}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
