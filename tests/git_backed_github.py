"""
A fake GitHub backed by real local git repositories, so the API-based code
scan and the git-history scan see the same commits.

    server = GitBackedGitHub(root)          # repos live at <root>/<owner>/<name>.git
    server.start()                          # sets GITHUB_API_URL / GITHUB_RAW_URL / GITHUB_CLONE_HOST
    repo = server.create_repo("acme", "demo")
    server.commit(repo, {".env": "KEY=..."}, "message")

Serves the endpoints app/github_client.py uses: repo info, branch head,
recursive tree, raw file contents and compare. History scans clone over
file:// from the same directories. It also fakes the GitHub Actions API
(workflow runs, artifacts, served through a redirect to another origin as
GitHub does) and pull-request comments, for the CI runs tab and
ci/pr_comment.py. Used by tests/test_history.py and handy
for trying the dashboard locally without GitHub (see tests/demo_server.py).
"""
import io
import itertools
import json
import os
import re
import subprocess
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import unquote, urlparse


def _git(repo: Path, *args: str, check: bool = True) -> str:
    proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr}")
    return proc.stdout


class GitBackedGitHub:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.server: Optional[ThreadingHTTPServer] = None
        self.port = 0
        self._ids = itertools.count(1001)
        self.runs: Dict[str, list] = {}         # "owner/name" -> workflow runs, newest first
        self.artifacts: Dict[int, list] = {}    # run id -> artifact dicts
        self.zips: Dict[int, bytes] = {}        # artifact id -> zip bytes
        self.comments: Dict[str, list] = {}     # "owner/name#pr" -> comments
        self.actions_forbidden = False          # simulate a token without Actions: Read
        self.comments_forbidden = False         # simulate a fork PR's read-only token
        self.blob_auth_headers: list = []       # Authorization seen by the artifact storage

    # -- GitHub Actions -------------------------------------------------
    def add_run(self, owner: str, name: str, *, result: Optional[dict] = None, event: str = "push",
                branch: str = "main", status: str = "completed", conclusion: Optional[str] = None,
                sha: str = "0" * 40, pr: Optional[int] = None, workflow: str = "Secret scan",
                created_at: str = "2026-09-30T10:00:00Z", actor: str = "priya",
                title: str = "Add payments") -> int:
        run_id = next(self._ids)
        if conclusion is None and status == "completed":
            conclusion = "success" if not result or result.get("status") == "passed" else "failure"
        run = {"id": run_id, "name": workflow, "run_number": run_id - 1000, "event": event,
               "head_branch": branch, "head_sha": sha, "status": status, "conclusion": conclusion,
               "display_title": title, "actor": {"login": actor}, "created_at": created_at,
               "updated_at": created_at, "html_url": f"https://github.com/{owner}/{name}/actions/runs/{run_id}",
               "pull_requests": [{"number": pr}] if pr else []}
        self.runs.setdefault(f"{owner}/{name}", []).insert(0, run)
        self.artifacts[run_id] = []
        if result is not None:
            self.set_run_result(run_id, result)
        return run_id

    def set_run_result(self, run_id: int, result: dict, status: str = "completed") -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("result.json", json.dumps(result))
            zf.writestr("code.sarif", "{}")
        art_id = next(self._ids)
        self.zips[art_id] = buf.getvalue()
        self.artifacts[run_id] = [{"id": art_id, "name": "secret-scan-results", "expired": False}]
        for runs in self.runs.values():
            for run in runs:
                if run["id"] == run_id:
                    run["status"] = status
                    run["conclusion"] = "success" if result.get("status") == "passed" else "failure"

    # -- repositories ---------------------------------------------------
    def repo_path(self, owner: str, name: str) -> Path:
        return self.root / owner / f"{name}.git"

    def create_repo(self, owner: str, name: str, branch: str = "main") -> Path:
        path = self.repo_path(owner, name)
        path.mkdir(parents=True)
        _git(path, "init", "-q", "-b", branch)
        _git(path, "config", "user.email", "alice@example.com")
        _git(path, "config", "user.name", "Alice Dev")
        _git(path, "config", "core.hooksPath", "/dev/null")
        return path

    def commit(self, repo: Path, files: Dict[str, Optional[str]], message: str,
               author: Optional[str] = None) -> str:
        """Write (or, with None, delete) files and commit. Returns the new SHA."""
        for rel, content in files.items():
            target = repo / rel
            if content is None:
                target.unlink(missing_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content)
        _git(repo, "add", "-A")
        args = ["commit", "-q", "--allow-empty", "-m", message]
        if author:
            args[1:1] = ["--author", author]
        _git(repo, *args)
        return _git(repo, "rev-parse", "HEAD").strip()

    # -- HTTP -----------------------------------------------------------
    def start(self) -> int:
        owner_self = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body: bytes, ctype="application/json"):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _json(self, obj, code=200):
                self._send(code, json.dumps(obj).encode())

            def do_GET(self):
                try:
                    owner_self._route(self, urlparse(self.path).path)
                except Exception as e:  # a bad sha etc. -> 404, like GitHub
                    self._json({"message": f"Not Found ({e})"}, 404)

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(n) or b"{}")

            def do_POST(self):
                owner_self._write(self, "POST", urlparse(self.path).path, self._body())

            def do_PATCH(self):
                owner_self._write(self, "PATCH", urlparse(self.path).path, self._body())

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        port = self.port = self.server.server_address[1]
        os.environ.update(GITHUB_API_URL=f"http://127.0.0.1:{port}/api",
                          GITHUB_RAW_URL=f"http://127.0.0.1:{port}/raw",
                          GITHUB_CLONE_HOST=f"file://{self.root}",
                          NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost")
        os.environ.pop("GITHUB_TOKEN", None)
        return port

    def stop(self):
        if self.server:
            self.server.shutdown()

    def _write(self, h, method: str, path: str, body: dict):
        if self.comments_forbidden:
            return h._json({"message": "Resource not accessible by integration"}, 403)
        if method == "POST" and (m := re.fullmatch(r"/api/repos/([^/]+)/([^/]+)/issues/(\d+)/comments", path)):
            c = {"id": next(self._ids), "body": body.get("body", "")}
            self.comments.setdefault(f"{m.group(1)}/{m.group(2)}#{m.group(3)}", []).append(c)
            return h._json(c, 201)
        if method == "PATCH" and (m := re.fullmatch(r"/api/repos/([^/]+)/([^/]+)/issues/comments/(\d+)", path)):
            for comments in self.comments.values():
                for c in comments:
                    if c["id"] == int(m.group(3)):
                        c["body"] = body.get("body", "")
                        return h._json(c)
        return h._json({"message": "Not Found"}, 404)

    def _route(self, h, path: str):
        if m := re.fullmatch(r"/blob/(\d+)", path):     # artifact storage, another origin
            self.blob_auth_headers.append(h.headers.get("Authorization"))
            data = self.zips.get(int(m.group(1)))
            return h._send(200, data, "application/zip") if data else h._json({"message": "gone"}, 410)
        if m := re.fullmatch(r"/api/repos/([^/]+)/([^/]+)/issues/(\d+)/comments", path):
            if self.comments_forbidden:
                return h._json({"message": "forbidden"}, 403)
            return h._json(self.comments.get(f"{m.group(1)}/{m.group(2)}#{m.group(3)}", []))
        if m := re.fullmatch(r"/api/repos/([^/]+)/([^/]+)/actions/(.*)", path):
            if self.actions_forbidden:
                return h._json({"message": "Resource not accessible by personal access token"}, 403)
            repo_key, rest = f"{m.group(1)}/{m.group(2)}", m.group(3)
            if rest == "runs":
                runs = self.runs.get(repo_key, [])
                return h._json({"total_count": len(runs), "workflow_runs": runs})
            if mm := re.fullmatch(r"runs/(\d+)/artifacts", rest):
                arts = self.artifacts.get(int(mm.group(1)), [])
                return h._json({"total_count": len(arts), "artifacts": arts})
            if mm := re.fullmatch(r"artifacts/(\d+)/zip", rest):
                # GitHub answers with a redirect to short-lived storage on another host.
                h.send_response(302)
                h.send_header("Location", f"http://localhost:{self.port}/blob/{mm.group(1)}")
                h.send_header("Content-Length", "0")
                h.end_headers()
                return
            return h._json({"message": "Not Found"}, 404)
        if m := re.fullmatch(r"/raw/([^/]+)/([^/]+)/([0-9a-f]{40})/(.+)", path):
            repo = self.repo_path(m.group(1), m.group(2))
            proc = subprocess.run(["git", "-C", str(repo), "show", f"{m.group(3)}:{unquote(m.group(4))}"],
                                  capture_output=True)
            if proc.returncode != 0:
                return h._send(404, b"Not Found", "text/plain")
            return h._send(200, proc.stdout, "text/plain")

        m = re.fullmatch(r"/api/repos/([^/]+)/([^/]+)(/.*)?", path)
        if not m or not self.repo_path(m.group(1), m.group(2)).exists():
            return h._json({"message": "Not Found"}, 404)
        repo, rest = self.repo_path(m.group(1), m.group(2)), m.group(3) or ""

        if rest == "":
            return h._json({"default_branch": _git(repo, "symbolic-ref", "--short", "HEAD").strip()})
        if mm := re.fullmatch(r"/commits/(.+)", rest):
            return h._json({"sha": _git(repo, "rev-parse", f"{unquote(mm.group(1))}^{{commit}}").strip()})
        if mm := re.fullmatch(r"/git/trees/([0-9a-f]{40})", rest):
            tree = []
            for line in _git(repo, "ls-tree", "-r", "-l", mm.group(1)).splitlines():
                meta, _, p = line.partition("\t")
                _mode, kind, _sha, size = meta.split()
                if kind == "blob":
                    tree.append({"path": p, "type": "blob", "size": int(size)})
            return h._json({"tree": tree, "truncated": False})
        if mm := re.fullmatch(r"/compare/([0-9a-f]{40})\.\.\.([0-9a-f]{40})", rest):
            base, head = mm.group(1), mm.group(2)
            ahead = subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor", base, head]).returncode == 0
            if not ahead:
                return h._json({"status": "diverged", "total_commits": 0, "files": []})
            files = []
            for line in _git(repo, "diff", "--name-status", "--no-renames", base, head).splitlines():
                status, _, p = line.partition("\t")
                files.append({"filename": p, "status": {"A": "added", "D": "removed"}.get(status[0], "modified")})
            n = int(_git(repo, "rev-list", "--count", f"{base}..{head}").strip())
            return h._json({"status": "ahead", "total_commits": n, "files": files})
        return h._json({"message": "Not Found"}, 404)
