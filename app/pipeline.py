"""
The pipeline: add a repo -> full initial scan -> incremental scans on every
poll. Each scan reconciles which previously flagged secrets are still present
and which have been removed.

Reconciliation rule: a finding is only marked "removed" if its file was
actually (re)read successfully in this scan, or the file no longer exists.
A file that failed to download never counts as "clean" — that would produce
false "secret removed" alerts on a flaky network or a rate limit.
"""
import json
import logging
import os
import threading
import time
from collections import defaultdict
from typing import Optional, Dict, Any, List, Set

from . import db, scanner, alerts
from .github_client import GitHubClient, GitHubError, RateLimitError, parse_repo_url

logger = logging.getLogger("secret-sentinel.pipeline")

# One scan per repo at a time (UI click + background poller could otherwise race).
_repo_locks: Dict[int, threading.Lock] = defaultdict(threading.Lock)
MAX_COMPARE_FILES = 300  # GitHub's compare API caps the file list at 300


def canonical_url(owner: str, name: str, branch: Optional[str]) -> str:
    base = f"https://github.com/{owner}/{name}"
    return f"{base}/tree/{branch}" if branch else base


def add_and_scan_repo(url: str) -> Dict[str, Any]:
    """Registers a repo (if new) and runs a full scan. Called by the UI's "Scan repo" button."""
    parsed = parse_repo_url(url)
    owner, name, branch = parsed["owner"], parsed["name"], parsed["branch"]
    client = GitHubClient()
    try:
        explicit_branch = branch
        if not branch:
            branch = client.get_default_branch(owner, name)
        repo_id = db.upsert_repo(canonical_url(owner, name, explicit_branch), owner, name, branch)
        return full_scan(repo_id, client)
    finally:
        client.close()


# --------------------------------------------------------------------------
# Full scan
# --------------------------------------------------------------------------

def full_scan(repo_id: int, client: Optional[GitHubClient] = None) -> Dict[str, Any]:
    """Scan every file in the branch at its latest commit. Safe to re-run any time."""
    repo = db.get_repo(repo_id)
    if not repo:
        raise ValueError(f"Unknown repo_id {repo_id}")
    owned = client is None
    client = client or GitHubClient()
    lock = _repo_locks[repo_id]
    with lock:
        try:
            return _full_scan_locked(repo, client)
        except GitHubError as e:
            db.set_repo_error(repo_id, str(e))
            raise
        finally:
            if owned:
                client.close()


def _full_scan_locked(repo: Dict[str, Any], client: GitHubClient) -> Dict[str, Any]:
    repo_id, owner, name, branch = repo["id"], repo["owner"], repo["name"], repo["branch"]
    sha = client.get_latest_commit_sha(owner, name, branch)
    tree = client.list_tree(owner, name, sha)
    tree_paths = {e["path"] for e in tree["files"]}

    findings: List[scanner.Finding] = []
    scanned_ok: Set[str] = set()
    failed: List[str] = []
    skipped = 0

    for entry in tree["files"]:
        path = entry["path"]
        if scanner.should_skip_path(path) or (entry.get("size") or 0) > scanner.MAX_FILE_BYTES:
            skipped += 1
            continue
        try:
            content = client.get_file_at(owner, name, sha, path)
        except RateLimitError:
            raise  # abort: a partial scan must not mark things "removed"
        except GitHubError as e:
            logger.warning("Failed to fetch %s: %s", path, e)
            failed.append(path)
            continue
        if content is None:
            failed.append(path)
            continue
        scanned_ok.add(path)
        findings.extend(scanner.scan_text(path, content))

    # Files that vanished from the tree are also "covered": their findings are gone.
    active_paths = {f["file_path"] for f in db.get_active_findings(repo_id)}
    covered = scanned_ok | (active_paths - tree_paths)

    counts = _apply_results(repo, findings, covered, sha)
    summary = (f"Full scan @ {sha[:7]}: {len(scanned_ok)} files scanned, {skipped} skipped, "
               f"{len(failed)} failed; {counts['new']} new, {counts['removed']} removed, "
               f"{counts['active']} active")
    if tree["truncated"]:
        summary += " (WARNING: repo tree truncated by GitHub — very large repo, some files not scanned)"
    db.update_repo_scan_state(repo_id, sha, summary)
    _send_digest(repo, counts["events"], summary)
    if failed:
        db.set_repo_error(repo_id, f"{len(failed)} file(s) could not be downloaded, e.g. {failed[:3]}")
    logger.info("%s/%s %s", owner, name, summary)

    return {
        "repo_id": repo_id, "owner": owner, "name": name, "branch": branch,
        "mode": "full", "latest_commit": sha,
        "files_scanned": len(scanned_ok), "files_skipped": skipped, "files_failed": len(failed),
        "failed_examples": failed[:5], "truncated": tree["truncated"],
        "new_findings": counts["new"], "reintroduced_findings": counts["reactivated"],
        "removed_findings": counts["removed"], "active_findings": counts["active"],
        "summary": summary,
    }


# --------------------------------------------------------------------------
# Incremental scan (what the background poller runs)
# --------------------------------------------------------------------------

def incremental_scan(repo_id: int, client: Optional[GitHubClient] = None) -> Dict[str, Any]:
    """Re-scan only files touched since the last scanned commit. Falls back to a
    full scan on first run, after a force-push, or when too many files changed."""
    repo = db.get_repo(repo_id)
    if not repo:
        raise ValueError(f"Unknown repo_id {repo_id}")
    if not repo["last_commit_sha"]:
        return full_scan(repo_id, client)

    owned = client is None
    client = client or GitHubClient()
    try:
        with _repo_locks[repo_id]:
            try:
                result = _incremental_locked(repo, client)
            except GitHubError as e:
                db.set_repo_error(repo_id, str(e))
                raise
        if result is None:  # needs a full rescan
            return full_scan(repo_id, client)
        return result
    finally:
        if owned:
            client.close()


def history_refresh_enabled() -> bool:
    """Re-walk git history whenever new commits arrive (HISTORY_SCAN_ON_PUSH,
    default on). Without it the history table only changes on a manual scan."""
    return os.environ.get("HISTORY_SCAN_ON_PUSH", "true").strip().lower() != "false"


def scan_for_updates(repo_id: int, client: Optional[GitHubClient] = None) -> Dict[str, Any]:
    """What the poller and the webhooks run: an incremental scan of the code,
    then, if the branch moved, a history scan so the git-history view picks up
    the new commits too (the mirror is updated with a `git fetch`)."""
    repo = db.get_repo(repo_id)
    before = repo["last_commit_sha"] if repo else None
    result = incremental_scan(repo_id, client)
    moved = bool(result.get("latest_commit")) and result.get("latest_commit") != before
    if moved and history_refresh_enabled():
        try:
            result["history"] = run_history_scan(repo_id)
        except Exception as e:  # the code scan above already succeeded; report, don't fail it
            logger.warning("History refresh failed for repo %s: %s", repo_id, e)
            result["history"] = {"state": "error", "error": str(e)}
    # CI runs change on their own schedule (a PR run needs no new commit on the
    # monitored branch), so they are refreshed on every poll, throttled.
    try:
        result["ci"] = sync_ci_runs(repo_id)
    except Exception as e:
        logger.warning("CI sync failed for repo %s: %s", repo_id, e)
    return result


def _incremental_locked(repo: Dict[str, Any], client: GitHubClient) -> Optional[Dict[str, Any]]:
    repo_id, owner, name, branch = repo["id"], repo["owner"], repo["name"], repo["branch"]
    base = repo["last_commit_sha"]
    head = client.get_latest_commit_sha(owner, name, branch)
    if head == base:
        db.update_repo_scan_state(repo_id, head)
        return {"repo_id": repo_id, "mode": "incremental", "new_commits": 0, "latest_commit": head,
                "new_findings": 0, "removed_findings": 0, "files_scanned": 0}

    try:
        cmp = client.compare(owner, name, base, head)
    except RateLimitError:
        raise
    except GitHubError:
        logger.info("Compare %s...%s failed (force-push?) — falling back to full scan", base[:7], head[:7])
        return None
    if cmp.get("status") not in ("ahead",) or len(cmp.get("files", [])) >= MAX_COMPARE_FILES:
        return None  # diverged / behind (history rewritten) or huge change set

    touched: Dict[str, Optional[str]] = {}   # path -> status
    for f in cmp.get("files", []):
        touched[f["filename"]] = f.get("status")
        if f.get("previous_filename"):          # renamed: old path no longer exists
            touched[f["previous_filename"]] = "removed"

    findings: List[scanner.Finding] = []
    covered: Set[str] = set()
    failed: List[str] = []
    for path, status in touched.items():
        if scanner.should_skip_path(path):
            continue
        if status == "removed":
            covered.add(path)                    # file gone -> its secrets are gone
            continue
        try:
            content = client.get_file_at(owner, name, head, path)
        except RateLimitError:
            raise
        except GitHubError as e:
            logger.warning("Failed to fetch %s: %s", path, e)
            failed.append(path)
            continue
        if content is None:
            failed.append(path)
            continue
        covered.add(path)
        findings.extend(scanner.scan_text(path, content))

    counts = _apply_results(repo, findings, covered, head)
    n_commits = cmp.get("total_commits", 0)
    summary = (f"Incremental scan {base[:7]}..{head[:7]} ({n_commits} commit(s), {len(covered)} file(s)): "
               f"{counts['new']} new, {counts['removed']} removed, {counts['active']} active")
    db.update_repo_scan_state(repo_id, head, summary)
    _send_digest(repo, counts["events"], summary)
    if failed:
        db.set_repo_error(repo_id, f"{len(failed)} file(s) could not be downloaded, e.g. {failed[:3]}")
    logger.info("%s/%s %s", owner, name, summary)
    return {
        "repo_id": repo_id, "owner": owner, "name": name, "branch": branch, "mode": "incremental",
        "new_commits": n_commits, "latest_commit": head, "files_scanned": len(covered),
        "files_failed": len(failed), "new_findings": counts["new"],
        "reintroduced_findings": counts["reactivated"], "removed_findings": counts["removed"],
        "active_findings": counts["active"], "summary": summary,
    }


# --------------------------------------------------------------------------
# Shared: persist findings, raise alerts, reconcile removals
# --------------------------------------------------------------------------

def _apply_results(repo: Dict[str, Any], findings: List[scanner.Finding],
                   covered_paths: Set[str], sha: str) -> Dict[str, Any]:
    repo_id = repo["id"]
    label = f"{repo['owner']}/{repo['name']}"
    counts: Dict[str, Any] = {"new": 0, "reactivated": 0, "removed": 0, "active": 0, "events": []}
    seen: Set[str] = set()

    for f in findings:
        seen.add(f.fingerprint)
        finding_id, state = db.upsert_finding(repo_id, f, sha)
        if state in ("new", "reactivated"):
            kind = "new_secret" if state == "new" else "secret_reintroduced"
            counts["new" if state == "new" else "reactivated"] += 1
            msg = _finding_message(f, sha, repo)
            if state == "reactivated":
                msg = "Previously removed secret is BACK. " + msg
            alerts.send_alert(label, kind, msg)
            db.record_alert(repo_id, finding_id, kind, msg)
            counts["events"].append({
                "kind": kind, "severity": f.severity, "description": f.description,
                "file_path": f.file_path, "line_number": f.line_number,
                "matched_text": f.matched_text, "link": _blob_link(repo, sha, f.file_path, f.line_number),
            })

    for row in db.get_active_findings(repo_id):
        if row["file_path"] in covered_paths and row["fingerprint"] not in seen:
            db.mark_removed(row["id"])
            counts["removed"] += 1
            msg = (f"[{row['severity'].upper()}] {row['description']} ({row['matched_text']}) is no longer "
                   f"present in {row['file_path']} as of commit {sha[:7]} — removed or rotated. "
                   f"Note: it still exists in git history; rotate the credential if it was real.")
            alerts.send_alert(label, "secret_removed", msg)
            db.record_alert(repo_id, row["id"], "secret_removed", msg)
            counts["events"].append({
                "kind": "secret_removed", "severity": row["severity"], "description": row["description"],
                "file_path": row["file_path"], "line_number": row["line_number"],
                "matched_text": row["matched_text"], "link": None,
            })

    counts["active"] = len(db.get_active_findings(repo_id))
    return counts


def _blob_link(repo: Dict[str, Any], sha: str, file_path: str, line_number: Optional[int]) -> str:
    link = f"https://github.com/{repo['owner']}/{repo['name']}/blob/{sha}/{file_path}"
    return link + (f"#L{line_number}" if line_number else "")


def _finding_message(f: scanner.Finding, sha: str, repo: Dict[str, Any]) -> str:
    where = f"{f.file_path}:{f.line_number}" if f.line_number else f.file_path
    link = _blob_link(repo, sha, f.file_path, f.line_number)
    return f"[{f.severity.upper()}] {f.description} in {where} (commit {sha[:7]}) — value: {f.matched_text} — {link}"


def _send_digest(repo: Dict[str, Any], events: List[Dict[str, Any]], summary: str) -> None:
    """One email per scan listing everything that changed (default email mode)."""
    if not events or alerts.email_mode() != "digest":
        return
    label = f"{repo['owner']}/{repo['name']}"
    try:
        alerts.send_scan_digest(label, repo["url"], events, summary)
    except Exception:
        logger.exception("Failed to send digest email for %s", label)


# --------------------------------------------------------------------------
# Git-history scan (finds secrets that were deleted from the code but remain
# in commit history, where they are still exploitable)
# --------------------------------------------------------------------------

def run_history_scan(repo_id: int, clone_url: Optional[str] = None) -> Dict[str, Any]:
    """Mirror-clone the repo, walk every commit, and store one row per unique
    secret ever committed. Safe to re-run: rows are updated in place."""
    from . import history_scan

    repo = db.get_repo(repo_id)
    if not repo:
        raise ValueError(f"Unknown repo_id {repo_id}")
    owner, name, label = repo["owner"], repo["name"], f"{repo['owner']}/{repo['name']}"

    if not history_scan.git_available():
        msg = "git is not installed on the server, so history scanning is unavailable."
        db.set_repo_history_state(repo_id, "unavailable", msg, msg)
        return {"repo_id": repo_id, "state": "unavailable", "error": msg}

    db.set_repo_history_state(repo_id, "running", None, None)
    with _repo_locks[repo_id]:
        try:
            result = history_scan.scan_history(owner, name, clone_url)
        except history_scan.HistoryScanError as e:
            logger.error("History scan failed for %s: %s", label, e)
            db.set_repo_history_state(repo_id, "error", None, str(e))
            raise
        except Exception as e:
            logger.exception("History scan crashed for %s", label)
            db.set_repo_history_state(repo_id, "error", None, f"unexpected error: {e}")
            raise

    new_records = []
    for rec in result["findings"]:
        if db.upsert_history_finding(repo_id, rec, json.dumps(rec.get("commits", []))):
            new_records.append(rec)

    summary = (f"History scan: {result['secrets_total']} secret(s) across "
               f"{result['total_commits']} commit(s) — {result['secrets_still_present']} still in the code, "
               f"{result['secrets_only_in_history']} only in history "
               f"({result['duration_seconds']}s)")
    if result["truncated"]:
        summary += f" — only the most recent {history_scan.MAX_COMMITS} commits were walked"
    if not result["head_tree_readable"]:
        summary += " — current tree unreadable, 'still present' is unknown"
    db.set_repo_history_state(repo_id, "done", summary, None)
    logger.info("%s %s", label, summary)

    if new_records:
        alert_msg = (f"{len(new_records)} secret(s) found in git history"
                     f" ({sum(1 for r in new_records if r['still_present'] is False)} already deleted from the "
                     f"code but still recoverable from history). {summary}")
        alerts.send_alert(label, "history_secret", alert_msg)
        db.record_alert(repo_id, None, "history_secret", alert_msg)
        _send_history_digest(repo, new_records, summary)

    result["repo_id"] = repo_id
    result["state"] = "done"
    result["summary"] = summary
    result["new_records"] = len(new_records)
    result.pop("findings", None)          # the rows are in the DB; keep the response small
    return result


def _send_history_digest(repo: Dict[str, Any], records: List[Dict[str, Any]], summary: str) -> None:
    if alerts.email_mode() != "digest":
        return
    label = f"{repo['owner']}/{repo['name']}"
    events = []
    for rec in records[:50]:
        sha = rec.get("first_commit_sha") or ""
        where = rec["file_path"] + (f":{rec['line_number']}" if rec.get("line_number") else "")
        status = "still in the code" if rec.get("still_present") else "deleted from code, still in history"
        events.append({
            "kind": "new_secret",
            "severity": rec["severity"],
            "description": (f"{rec['description']} — in git history ({status}), introduced by "
                            f"{rec.get('first_author_name') or 'unknown'} in {sha[:7]}"),
            "file_path": where,
            "line_number": None,
            "matched_text": rec["matched_text"],
            "link": (f"https://github.com/{repo['owner']}/{repo['name']}/commit/{sha}" if sha else None),
        })
    extra = f" (showing the first 50 of {len(records)})" if len(records) > 50 else ""
    try:
        alerts.send_scan_digest(label, repo["url"], events, summary + extra)
    except Exception:
        logger.exception("Failed to send history digest email for %s", label)


# --------------------------------------------------------------------------
# CI runs: read the Secret scan workflow's results back from GitHub Actions,
# so the dashboard shows what the CI gate decided. Pulled, not pushed, so it
# needs no public URL; the workflow uploads result.json (ci/ci_result.py) in
# its "secret-scan-results" artifact.
# --------------------------------------------------------------------------

CI_ARTIFACT = "secret-scan-results"
CI_SYNC_MIN_SECONDS = int(os.environ.get("CI_SYNC_MIN_SECONDS", "20"))
_ci_locks: Dict[int, threading.Lock] = defaultdict(threading.Lock)


def ci_workflow_name() -> str:
    return os.environ.get("SENTINEL_CI_WORKFLOW", "Secret scan").strip() or "Secret scan"


def _gate_from_conclusion(run: Dict[str, Any]) -> str:
    if run.get("status") != "completed":
        return "running"
    return {"success": "passed", "failure": "failed", "cancelled": "cancelled",
            "timed_out": "error", "startup_failure": "error"}.get(run.get("conclusion") or "", "error")


def _ci_alert(repo: Dict[str, Any], rec: Dict[str, Any]) -> None:
    label = f"{repo['owner']}/{repo['name']}"
    where = f"pull request #{rec['pr_number']}" if rec.get("pr_number") else f"{rec.get('event')} to {rec.get('branch')}"
    findings = [f for f in json.loads(rec.get("findings_json") or "[]") if f.get("gating")]
    listed = "; ".join(f"[{f.get('severity', '').upper()}] {f.get('description')} in "
                       f"{f.get('file_path')}:{f.get('line_number')} ({f.get('value_masked')})" for f in findings[:5])
    who = rec.get("commit_author") or rec.get("actor") or "unknown"
    msg = (f"CI blocked {where} at commit {(rec.get('head_sha') or '')[:7]} by {who}: "
           f"{rec.get('gating_count') or len(findings)} secret(s). {listed} — {rec.get('html_url') or ''}")
    db.record_alert(repo["id"], None, "ci_blocked", msg.strip())


def sync_ci_runs(repo_id: int, force: bool = False, client: Optional[GitHubClient] = None) -> Dict[str, Any]:
    """Fetch the repo's latest Secret scan runs and store them. Throttled to one
    GitHub call per CI_SYNC_MIN_SECONDS unless force=True. Never raises for
    GitHub errors: they are stored on the repo row and shown in the tab."""
    repo = db.get_repo(repo_id)
    if not repo:
        raise ValueError(f"Unknown repo_id {repo_id}")
    if not force and repo.get("ci_synced_at") and time.time() - repo["ci_synced_at"] < CI_SYNC_MIN_SECONDS:
        return {"repo_id": repo_id, "skipped": "recently synced"}
    lock = _ci_locks[repo_id]
    if not lock.acquire(blocking=False):
        return {"repo_id": repo_id, "skipped": "sync already running"}
    owned = client is None
    client = client or GitHubClient()
    first_sync = not repo.get("ci_synced_at")
    counts = {"runs": 0, "new": 0, "results": 0, "blocked_alerts": 0}
    try:
        wanted = ci_workflow_name()
        runs = [r for r in client.list_workflow_runs(repo["owner"], repo["name"]) if r.get("name") == wanted][:20]
        for run in runs:
            counts["runs"] += 1
            old = db.get_ci_run(repo_id, run["id"])
            if old and old["has_result"]:
                continue                        # final: nothing more to learn about this run
            prs = run.get("pull_requests") or []
            rec: Dict[str, Any] = {
                "run_number": run.get("run_number"), "event": run.get("event"),
                "branch": run.get("head_branch"), "pr_number": prs[0].get("number") if prs else None,
                "head_sha": run.get("head_sha"), "title": run.get("display_title"),
                "actor": (run.get("actor") or {}).get("login"), "run_status": run.get("status"),
                "conclusion": run.get("conclusion"), "gate": _gate_from_conclusion(run),
                "html_url": run.get("html_url"), "run_created_at": run.get("created_at"),
            }
            if run.get("status") == "completed":
                result = _read_ci_result(client, repo, run["id"])
                if result:
                    counts["results"] += 1
                    findings = result.get("findings") or []
                    rec.update({
                        "gate": result.get("status") or rec["gate"], "has_result": 1,
                        "pr_number": result.get("pr_number") or rec["pr_number"],
                        "head_sha": result.get("sha") or rec["head_sha"],
                        "branch": result.get("branch") or rec["branch"],
                        "commit_author": result.get("commit_author"), "scope": result.get("scope"),
                        "fail_on": result.get("fail_on"),
                        "findings_json": json.dumps(findings),
                        "gating_count": (result.get("counts") or {}).get("gating", 0),
                        "total_count": (result.get("counts") or {}).get("total", len(findings)),
                    })
                elif run.get("updated_at") and _age_hours(run["updated_at"]) > 1:
                    rec["has_result"] = 1           # no artifact after an hour: stop asking
            db.upsert_ci_run(repo_id, run["id"], rec)
            if old is None:
                counts["new"] += 1
            newly_blocked = rec["gate"] == "blocked" and (old is None or old["gate"] != "blocked")
            if newly_blocked and not first_sync:     # don't replay old history on the first sync
                _ci_alert(repo, rec)
                counts["blocked_alerts"] += 1
        db.set_repo_ci_state(repo_id, None)
    except GitHubError as e:
        db.set_repo_ci_state(repo_id, str(e))
        counts["error"] = str(e)
    finally:
        lock.release()
        if owned:
            client.close()
    return {"repo_id": repo_id, **counts}


def _read_ci_result(client: GitHubClient, repo: Dict[str, Any], run_id: int) -> Optional[Dict[str, Any]]:
    arts = [a for a in client.list_run_artifacts(repo["owner"], repo["name"], run_id)
            if a.get("name") == CI_ARTIFACT and not a.get("expired")]
    if not arts:
        return None
    raw = client.read_artifact_file(repo["owner"], repo["name"], arts[0]["id"], "result.json")
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    return data if isinstance(data, dict) and data.get("tool") == "secret-sentinel" else None


def _age_hours(iso: str) -> float:
    from datetime import datetime, timezone
    try:
        when = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return 0.0
    return (datetime.now(timezone.utc) - when).total_seconds() / 3600


def sync_all_ci_runs(force: bool = False) -> List[Dict[str, Any]]:
    out = []
    for repo in db.list_repos():
        try:
            out.append(sync_ci_runs(repo["id"], force=force))
        except Exception as e:  # one repo's failure must not stop the others
            logger.exception("CI sync failed for repo %s", repo["id"])
            out.append({"repo_id": repo["id"], "error": str(e)})
    return out
