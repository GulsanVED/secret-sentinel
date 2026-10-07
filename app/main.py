"""
FastAPI app: serves the simple UI and the JSON API it talks to.

Run with:  uvicorn app.main:app --port 8000
Then open  http://localhost:8000 (landing page) or /dashboard
"""
import json
import logging
import os
from pathlib import Path
from typing import Optional


def _load_dotenv(path: Path) -> None:
    """Load KEY=VALUE lines from .env into the environment (without overriding
    variables that are already set). Avoids needing python-dotenv."""
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip().removeprefix("export ").strip(), value.strip().strip('"').strip("'")
        if key and value and key not in os.environ:
            os.environ[key] = value


_load_dotenv(Path(__file__).resolve().parent.parent / ".env")  # must run before importing scheduler

import hashlib
import hmac

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from . import alerts, db, pipeline, scanner, tunnel
from .github_client import GitHubError, RateLimitError
from .scheduler import start_scheduler, stop_scheduler, POLL_INTERVAL_SECONDS

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

app = FastAPI(title="Secret Sentinel")
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


@app.middleware("http")
async def tunnel_guard(request: Request, call_next):
    """While a public tunnel is open (python -m app.serve --ngrok), only the
    webhooks may be reached through it: the dashboard has no login, so its
    pages and API stay local unless NGROK_EXPOSE_DASHBOARD=true."""
    if tunnel.blocks(request.url.path, request.headers.get("host", ""),
                     request.headers.get("x-forwarded-for")):
        return JSONResponse({"detail": "The dashboard is only available on the machine running it. "
                                       "This public address serves the webhooks."}, status_code=403)
    return await call_next(request)


@app.on_event("startup")
def on_startup():
    db.init_db()
    rules_file = os.environ.get("SENTINEL_RULES_FILE", "").strip()
    if rules_file:
        # A broken rules file stops startup: silently scanning without the
        # team's own rules would look like "no secrets" when it is not.
        scanner.set_custom_rules(scanner.load_custom_rules(rules_file))
        logging.getLogger("secret-sentinel").info(
            "Loaded %d custom rule(s) from %s", len(scanner.CUSTOM_RULES), rules_file)
    start_scheduler()
    if not os.environ.get("GITHUB_TOKEN"):
        logging.getLogger("secret-sentinel").warning(
            "GITHUB_TOKEN is not set: GitHub allows only 60 API requests/hour unauthenticated. "
            "Set it to avoid rate-limit failures.")


@app.on_event("shutdown")
def on_shutdown():
    stop_scheduler()


def _http_error(e: Exception) -> HTTPException:
    if isinstance(e, RateLimitError):
        return HTTPException(status_code=429, detail=str(e))
    return HTTPException(status_code=400, detail=str(e))


class AddRepoRequest(BaseModel):
    url: str


class TestScanRequest(BaseModel):
    content: str
    filename: str = "sample.env"


@app.get("/")
def home():
    """Landing page: set up CI scanning, or scan a repository now."""
    return FileResponse(STATIC_DIR / "home.html")


@app.get("/dashboard")
def dashboard():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/status")
def status():
    from . import history_scan
    return {
        "github_token_configured": bool(os.environ.get("GITHUB_TOKEN")),
        "git_available": history_scan.git_available(),
        "history_max_commits": history_scan.MAX_COMMITS,
        "poll_interval_seconds": POLL_INTERVAL_SECONDS,
        "alert_channels": alerts.channel_status(),
        "email_mode": alerts.email_mode(),
        "email_to": os.environ.get("ALERT_EMAIL_TO", ""),
        "webhook_secret_configured": bool(os.environ.get("GITHUB_WEBHOOK_SECRET")),
        "ci_workflow": pipeline.ci_workflow_name(),
        "public_url": tunnel.public_url(),
        "rules": len(scanner.active_rules()),
        "custom_rules": len(scanner.CUSTOM_RULES),
    }


@app.post("/api/test-email")
def send_test_email():
    """Check SMTP settings from the UI."""
    if not alerts.email_configured():
        raise HTTPException(status_code=400,
                            detail="SMTP_HOST and ALERT_EMAIL_TO are not set. Add them to .env and restart.")
    if alerts.send_test_email():
        return {"ok": True, "sent_to": os.environ.get("ALERT_EMAIL_TO")}
    raise HTTPException(status_code=502, detail="SMTP send failed — check the server logs for the reason.")


@app.post("/api/repos")
def add_repo(req: AddRepoRequest, background: BackgroundTasks):
    """Register a repo and run the initial full scan (synchronous, so the UI shows
    results immediately). The git-history scan runs in the background afterwards,
    since a mirror clone of a large repo can take a while."""
    try:
        result = pipeline.add_and_scan_repo(req.url)
    except GitHubError as e:
        raise _http_error(e)

    if os.environ.get("HISTORY_SCAN_ON_ADD", "true").strip().lower() != "false":
        db.set_repo_history_state(result["repo_id"], "queued", None, None)
        background.add_task(_history_scan_in_background, result["repo_id"])
        result["history_scan"] = "queued"
    background.add_task(_ci_sync_in_background, result["repo_id"])
    return result


def _ci_sync_in_background(repo_id: int, force: bool = True) -> None:
    try:
        pipeline.sync_ci_runs(repo_id, force=force)
    except Exception:
        logging.getLogger("secret-sentinel").exception("CI sync failed for repo %s", repo_id)


def _history_scan_in_background(repo_id: int) -> None:
    try:
        pipeline.run_history_scan(repo_id)
    except Exception:
        logging.getLogger("secret-sentinel").exception("Background history scan failed for repo %s", repo_id)


@app.post("/api/repos/{repo_id}/history-scan")
def history_scan_repo(repo_id: int, background: BackgroundTasks, wait: bool = False):
    """Walk the whole git history for secrets, including deleted ones.
    wait=true runs it synchronously (handy for scripts and small repos)."""
    if not db.get_repo(repo_id):
        raise HTTPException(status_code=404, detail="repo not found")
    if wait:
        try:
            return pipeline.run_history_scan(repo_id)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
    db.set_repo_history_state(repo_id, "queued", None, None)
    background.add_task(_history_scan_in_background, repo_id)
    return {"ok": True, "state": "queued"}


@app.get("/api/history")
def get_history(repo_id: Optional[int] = None, presence: Optional[str] = None):
    """Every secret ever committed. presence=present|history_only to filter."""
    rows = db.list_history_findings(repo_id=repo_id, presence=presence)
    for r in rows:
        try:
            r["commits"] = json.loads(r.pop("commits_json") or "[]")
        except (json.JSONDecodeError, TypeError):
            r["commits"] = []
    return rows


@app.get("/api/history/stats")
def get_history_stats(repo_id: Optional[int] = None):
    return db.history_stats(repo_id=repo_id)


@app.get("/api/repos")
def get_repos():
    return db.list_repos()


def _ci_row(r: dict) -> dict:
    try:
        r["findings"] = json.loads(r.pop("findings_json") or "[]")
    except (json.JSONDecodeError, TypeError):
        r["findings"] = []
    return r


@app.get("/api/ci-runs")
def get_ci_runs(repo_id: Optional[int] = None, limit: int = 50):
    """Secret scan runs read back from GitHub Actions, newest first."""
    return [_ci_row(r) for r in db.list_ci_runs(repo_id=repo_id, limit=min(max(limit, 1), 200))]


@app.post("/api/ci-sync")
def ci_sync(repo_id: Optional[int] = None):
    """Refresh CI runs from GitHub now (throttled per repo). The dashboard calls
    this while the CI runs tab is open."""
    if repo_id is not None:
        if not db.get_repo(repo_id):
            raise HTTPException(status_code=404, detail="repo not found")
        return [pipeline.sync_ci_runs(repo_id)]
    return pipeline.sync_all_ci_runs()


@app.get("/api/ci-summary")
def ci_summary():
    """Live CI status for the start page."""
    import time as _time
    from datetime import datetime
    repos = db.list_repos()
    runs = db.list_ci_runs(limit=500)
    week_ago = _time.time() - 7 * 86400

    def ts(r):
        try:
            return datetime.fromisoformat((r.get("run_created_at") or "").replace("Z", "+00:00")).timestamp()
        except ValueError:
            return 0.0
    recent = [r for r in runs if ts(r) >= week_ago]
    finished = [r for r in runs if r["gate"] != "running"]
    last = finished[0] if finished else None
    return {
        "repos_total": len(repos),
        "repos_reporting": len({r["repo_id"] for r in runs}),
        "runs_7d": len(recent),
        "blocked_7d": sum(1 for r in recent if r["gate"] == "blocked"),
        "passed_7d": sum(1 for r in recent if r["gate"] == "passed"),
        "running": sum(1 for r in runs if r["gate"] == "running"),
        "last_run": ({k: last.get(k) for k in ("owner", "name", "gate", "event", "branch", "pr_number",
                                                 "head_sha", "run_created_at", "html_url", "gating_count")}
                     if last else None),
        "ci_errors": [{"repo": f"{r['owner']}/{r['name']}", "error": r["ci_error"]}
                      for r in repos if r.get("ci_error")],
    }


@app.post("/api/repos/{repo_id}/rescan")
def rescan_repo(repo_id: int, background: BackgroundTasks, full: bool = True):
    """Rescan the code now; the git-history scan is refreshed in the background
    (HISTORY_SCAN_ON_PUSH=false turns that off)."""
    if not db.get_repo(repo_id):
        raise HTTPException(status_code=404, detail="repo not found")
    try:
        result = pipeline.full_scan(repo_id) if full else pipeline.incremental_scan(repo_id)
    except GitHubError as e:
        raise _http_error(e)
    if pipeline.history_refresh_enabled():
        db.set_repo_history_state(repo_id, "queued", None, None)
        background.add_task(_history_scan_in_background, repo_id)
        result["history_scan"] = "queued"
    background.add_task(_ci_sync_in_background, repo_id)
    return result


@app.delete("/api/repos/{repo_id}")
def remove_repo(repo_id: int):
    repo = db.get_repo(repo_id)
    db.delete_repo(repo_id)
    if repo:
        from . import history_scan
        history_scan.delete_mirror(repo["owner"], repo["name"])
    return {"ok": True}


@app.get("/api/findings")
def get_findings(repo_id: Optional[int] = None, status: Optional[str] = None):
    return db.list_findings(repo_id=repo_id, status=status)


@app.get("/api/alerts")
def get_alerts(repo_id: Optional[int] = None, limit: int = 200):
    return db.list_alerts(repo_id=repo_id, limit=limit)


@app.post("/api/test-scan")
def test_scan(req: TestScanRequest):
    """Paste file content and see exactly what the rules detect — no GitHub involved.
    Handy for checking whether a test secret matches before pushing it."""
    findings = scanner.scan_text(req.filename, req.content)
    return [
        {"rule_id": f.rule_id, "description": f.description, "severity": f.severity,
         "line_number": f.line_number, "matched_text": f.matched_text}
        for f in findings
    ]


# --------------------------------------------------------------------------
# Real-time triggers
# --------------------------------------------------------------------------

def _find_repo_by_full_name(full_name: str, branch: Optional[str] = None) -> Optional[dict]:
    """Match 'owner/name' (optionally a branch) against the registered repos."""
    owner, _, name = full_name.partition("/")
    matches = [r for r in db.list_repos()
               if r["owner"].lower() == owner.lower() and r["name"].lower() == name.lower()]
    if branch:
        exact = [r for r in matches if (r["branch"] or "") == branch]
        if exact:
            return exact[0]
        return None if matches else None
    return matches[0] if matches else None


def _scan_in_background(repo_id: int) -> None:
    try:
        pipeline.scan_for_updates(repo_id)
    except Exception:
        logging.getLogger("secret-sentinel").exception("Webhook-triggered scan failed for repo %s", repo_id)


def _register_and_scan(url: str) -> None:
    try:
        pipeline.add_and_scan_repo(url)
    except Exception:
        logging.getLogger("secret-sentinel").exception("Webhook auto-registration failed for %s", url)


@app.post("/webhook/github")
async def github_webhook(request: Request, background: BackgroundTasks):
    """GitHub push webhook — scans within seconds of a push, no polling.

    Configure in the repo: Settings -> Webhooks -> Add webhook
      Payload URL:  https://<your-host>/webhook/github
      Content type: application/json
      Secret:       same value as GITHUB_WEBHOOK_SECRET in .env
      Events:       Just the push event
    """
    raw = await request.body()
    secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "").strip()
    signature = request.headers.get("x-hub-signature-256", "")
    if secret:
        expected = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise HTTPException(status_code=401, detail="Invalid webhook signature")
    elif signature:
        logging.getLogger("secret-sentinel").warning(
            "Webhook arrived signed but GITHUB_WEBHOOK_SECRET is not set — signature not verified.")

    event = request.headers.get("x-github-event", "")
    if event == "ping":
        return {"ok": True, "message": "Secret Sentinel webhook is reachable."}
    if event != "push":
        return {"ok": True, "ignored_event": event}

    try:
        payload = json.loads(raw or b"{}")
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Body is not valid JSON")

    full_name = (payload.get("repository") or {}).get("full_name") or ""
    ref = payload.get("ref") or ""
    branch = ref.split("refs/heads/", 1)[1] if ref.startswith("refs/heads/") else None
    if not full_name or not branch:
        return {"ok": True, "ignored": f"not a branch push (ref={ref!r})"}

    repo = _find_repo_by_full_name(full_name, branch)
    if repo:
        background.add_task(_scan_in_background, repo["id"])
        return {"ok": True, "scanning": f"{full_name}@{branch}", "repo_id": repo["id"]}

    # The repo is known but this push was to a different branch: ignore it unless
    # WEBHOOK_SCAN_ALL_BRANCHES=true, so feature branches don't each become a row.
    if _find_repo_by_full_name(full_name) and \
            os.environ.get("WEBHOOK_SCAN_ALL_BRANCHES", "false").strip().lower() != "true":
        return {"ok": True, "ignored": f"push to unmonitored branch {branch!r}"}

    # Unknown repo: register it automatically (default on, disable with
    # WEBHOOK_AUTO_REGISTER=false) so a new repo needs no dashboard step.
    if os.environ.get("WEBHOOK_AUTO_REGISTER", "true").strip().lower() != "false":
        default_branch = (payload.get("repository") or {}).get("default_branch")
        url = f"https://github.com/{full_name}" if branch == default_branch \
            else f"https://github.com/{full_name}/tree/{branch}"
        background.add_task(_register_and_scan, url)
        return {"ok": True, "registering": url}
    return {"ok": True, "ignored": f"{full_name}@{branch} is not registered"}


class CiNotifyRequest(BaseModel):
    repo: str
    commit: str = ""
    findings: list = []


@app.post("/webhook/ci")
def ci_webhook(req: CiNotifyRequest, request: Request, background: BackgroundTasks):
    """Called by the CI job (`--notify-url`) so the dashboard refreshes right
    after a pipeline run. Protect it by setting SENTINEL_TOKEN in .env."""
    token = os.environ.get("SENTINEL_TOKEN", "").strip()
    if token and not hmac.compare_digest(token, request.headers.get("x-sentinel-token", "")):
        raise HTTPException(status_code=401, detail="Invalid token")

    repo = _find_repo_by_full_name(req.repo)
    if repo:
        background.add_task(_scan_in_background, repo["id"])
        background.add_task(_ci_sync_in_background, repo["id"])
        return {"ok": True, "rescanning": req.repo, "ci_findings": len(req.findings)}
    if "/" in req.repo and os.environ.get("WEBHOOK_AUTO_REGISTER", "true").strip().lower() != "false":
        background.add_task(_register_and_scan, f"https://github.com/{req.repo}")
        return {"ok": True, "registering": req.repo, "ci_findings": len(req.findings)}
    return {"ok": True, "ignored": req.repo, "ci_findings": len(req.findings)}
