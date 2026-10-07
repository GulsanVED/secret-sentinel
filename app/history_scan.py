"""
Git history scanning — finds secrets that were committed at ANY point, including
ones later deleted from the code.

This matters because deleting a secret from a file does not remove it: it stays
in every clone, fork and the GitHub UI forever, and remains exploitable until
the credential is rotated. The API-based scan in pipeline.py only sees the
current files; this module sees everything.

How it works
------------
1. Maintain a bare mirror clone of the repo under data/mirrors/.
2. Walk the full history with `git log --all -p` and scan every ADDED line
   (the moment a secret entered the repo) and every REMOVED line (the moment
   it was taken out).
3. Scan the current HEAD tree (streamed via `git archive`) to know which of
   those secrets are still in the code and which only exist in history.
4. Aggregate per unique secret: who introduced it, when, in which commit, how
   many commits contain it, and which commit removed it.

Requires the `git` binary. No other dependencies.
"""
import io
import logging
import os
import re
import shutil
import subprocess
import tarfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import scanner

logger = logging.getLogger("secret-sentinel.history")

MIRROR_DIR = Path(__file__).resolve().parent.parent / "data" / "mirrors"
COMMIT_SENTINEL = "\x01"
FIELD_SEP = "\x1f"

MAX_COMMITS = int(os.environ.get("HISTORY_MAX_COMMITS", "5000"))
GIT_TIMEOUT = int(os.environ.get("HISTORY_TIMEOUT_SECONDS", "900"))


class HistoryScanError(Exception):
    pass


def git_available() -> bool:
    return shutil.which("git") is not None


def _run_git(args: List[str], cwd: Optional[Path] = None, timeout: int = GIT_TIMEOUT) -> subprocess.CompletedProcess:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "", "GCM_INTERACTIVE": "never"}
    try:
        return subprocess.run(["git", *args], cwd=str(cwd) if cwd else None, capture_output=True,
                              text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired as e:
        raise HistoryScanError(f"git timed out after {timeout}s: git {' '.join(args[:3])}…") from e
    except OSError as e:
        raise HistoryScanError(f"could not run git: {e}") from e


def _redact(text: str) -> str:
    """Never let a token from a clone URL reach a log or the UI."""
    return re.sub(r"x-access-token:[^@]+@", "x-access-token:***@", text or "")


def _clone_url(owner: str, name: str) -> str:
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    host = os.environ.get("GITHUB_CLONE_HOST", "github.com").rstrip("/")
    scheme, sep, host = host.rpartition("://")   # a full base URL is allowed too
    scheme = scheme if sep else "https"
    if token and scheme == "https":
        return f"https://x-access-token:{token}@{host}/{owner}/{name}.git"
    return f"{scheme}://{host}/{owner}/{name}.git"


def mirror_path(owner: str, name: str) -> Path:
    return MIRROR_DIR / f"{owner}__{name}.git"


def ensure_mirror(owner: str, name: str, clone_url: Optional[str] = None) -> Path:
    """Clone the repo as a bare mirror, or fetch new commits into an existing one."""
    if not git_available():
        raise HistoryScanError("git is not installed on this machine — history scanning needs it.")
    MIRROR_DIR.mkdir(parents=True, exist_ok=True)
    path = mirror_path(owner, name)
    url = clone_url or _clone_url(owner, name)

    if path.exists():
        # A valid mirror is updated in place. If the directory is not a usable
        # git dir, throw it away and clone again.
        if _run_git(["rev-parse", "--git-dir"], cwd=path).returncode != 0:
            logger.warning("%s is not a usable git dir — re-cloning", path)
            shutil.rmtree(path, ignore_errors=True)
        else:
            # Point at the current URL: the token may have been added since the
            # first clone, or the repo may have moved.
            _run_git(["remote", "set-url", "origin", url], cwd=path)
            proc = _run_git(["fetch", "--prune", "--quiet", "origin",
                             "+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"], cwd=path)
            if proc.returncode == 0:
                return path
            # Keep the existing mirror (it is still usable for a scan) and report why.
            raise HistoryScanError(f"fetch failed: {_redact(proc.stderr).strip()[:400]}")

    proc = _run_git(["clone", "--bare", "--quiet", url, str(path)])
    if proc.returncode != 0:
        shutil.rmtree(path, ignore_errors=True)
        err = _redact(proc.stderr).strip()[:400]
        if "Authentication failed" in err or "could not read Username" in err:
            raise HistoryScanError("clone failed: authentication required. Set GITHUB_TOKEN for private repos.")
        if "not found" in err.lower():
            raise HistoryScanError(f"clone failed: repository {owner}/{name} not found (or no access).")
        raise HistoryScanError(f"clone failed: {err}")
    return path


# --------------------------------------------------------------------------
# History walk
# --------------------------------------------------------------------------

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def iter_history_occurrences(mirror: Path, max_commits: int = MAX_COMMITS,
                             revisions: Optional[List[str]] = None):
    """Yield (finding, commit_meta, action) for every secret added or removed
    in the given revisions (default: all refs). action is 'added' or 'removed'.
    `revisions` takes anything `git log` does, e.g. ["origin/main..HEAD"]."""
    args = ["log", *(revisions or ["--all"]), "--full-history", "--no-merges", "--no-renames",
            "--no-color", "--no-textconv", f"--max-count={max_commits}", "--unified=0", "-p",
            f"--format={COMMIT_SENTINEL}%H{FIELD_SEP}%an{FIELD_SEP}%ae{FIELD_SEP}%aI{FIELD_SEP}%s"]
    proc = subprocess.Popen(["git", *args], cwd=str(mirror), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, errors="replace", bufsize=1)
    commit: Dict[str, str] = {}
    new_path = old_path = None
    new_line = 0
    deadline = time.time() + GIT_TIMEOUT
    try:
        for raw in proc.stdout:
            if time.time() > deadline:
                raise HistoryScanError(f"history walk exceeded {GIT_TIMEOUT}s — raise HISTORY_TIMEOUT_SECONDS")
            line = raw.rstrip("\n")
            if line.startswith(COMMIT_SENTINEL):
                parts = line[1:].split(FIELD_SEP)
                if len(parts) >= 5:
                    commit = {"sha": parts[0], "author_name": parts[1], "author_email": parts[2],
                              "date": parts[3], "subject": parts[4]}
                new_path = old_path = None
                continue
            if line.startswith("diff --git "):
                new_path = old_path = None
                continue
            if line.startswith("--- "):
                old_path = None if line[4:] == "/dev/null" else re.sub(r"^a/", "", line[4:])
                continue
            if line.startswith("+++ "):
                new_path = None if line[4:] == "/dev/null" else re.sub(r"^b/", "", line[4:])
                continue
            if line.startswith("@@"):
                m = _HUNK_RE.match(line)
                new_line = int(m.group(1)) if m else 0
                continue
            if not commit or line[:1] not in ("+", "-"):
                continue

            content = line[1:]
            if line.startswith("+"):
                path = new_path
                if path and not scanner.should_skip_path(path):
                    for f in scanner.scan_line(path, content, new_line):
                        yield f, commit, "added"
                new_line += 1
            else:  # removal
                path = old_path
                if path and not scanner.should_skip_path(path):
                    for f in scanner.scan_line(path, content, 0):
                        yield f, commit, "removed"
    finally:
        if proc.stdout:
            proc.stdout.close()
        stderr = proc.stderr.read() if proc.stderr else ""
        proc.wait()
        if proc.returncode not in (0, None) and stderr.strip():
            logger.warning("git log exited %s: %s", proc.returncode, _redact(stderr)[:300])


def head_fingerprints(mirror: Path) -> Optional[set]:
    """Fingerprints of secrets present in the CURRENT default-branch tree,
    read by streaming `git archive` (one subprocess, no checkout).
    None means HEAD could not be read (e.g. empty repo)."""
    proc = subprocess.run(["git", "archive", "--format=tar", "HEAD"], cwd=str(mirror),
                          capture_output=True, timeout=GIT_TIMEOUT)
    if proc.returncode != 0:
        return None
    out = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(proc.stdout), mode="r|") as tar:
            for member in tar:
                if not member.isfile() or scanner.should_skip_path(member.name):
                    continue
                if member.size > scanner.MAX_FILE_BYTES:
                    continue
                fh = tar.extractfile(member)
                if fh is None:
                    continue
                data = fh.read()
                if b"\x00" in data[:8000]:
                    continue
                for f in scanner.scan_text(member.name, data.decode("utf-8", errors="replace")):
                    out.add(f.fingerprint)
    except (tarfile.TarError, OSError) as e:
        logger.warning("Could not read HEAD tree: %s", e)
        return None
    return out


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------

MAX_COMMITS_PER_FINDING = 25


def scan_history(owner: str, name: str, clone_url: Optional[str] = None,
                 max_commits: int = MAX_COMMITS) -> Dict[str, Any]:
    """Full history scan of a GitHub repo (via a local bare mirror)."""
    mirror = ensure_mirror(owner, name, clone_url)
    return scan_git_dir(mirror, max_commits=max_commits)


def scan_git_dir(repo: Path, revisions: Optional[List[str]] = None,
                 max_commits: int = MAX_COMMITS) -> Dict[str, Any]:
    """Scan the history of any local git directory — a bare mirror or a CI
    checkout. `revisions` limits the walk (e.g. ["<base>..<head>"] for the
    commits a pull request adds); the default is every ref. Returns
    aggregated findings plus stats."""
    if not git_available():
        raise HistoryScanError("git is not installed on this machine — history scanning needs it.")
    started = time.time()
    repo = Path(repo)
    if _run_git(["rev-parse", "--git-dir"], cwd=repo).returncode != 0:
        raise HistoryScanError(f"{repo} is not a git repository")
    revisions = revisions or ["--all"]

    total_commits = 0
    rl = _run_git(["rev-list", "--count", "--no-merges", *revisions], cwd=repo)
    if rl.returncode == 0 and rl.stdout.strip().isdigit():
        total_commits = int(rl.stdout.strip())
    elif rl.returncode != 0:
        raise HistoryScanError(f"bad revision range {' '.join(revisions)}: {_redact(rl.stderr).strip()[:300]}")

    mirror = repo
    agg: Dict[str, Dict[str, Any]] = {}
    for finding, commit, action in iter_history_occurrences(mirror, max_commits, revisions):
        rec = agg.get(finding.fingerprint)
        if rec is None:
            rec = agg[finding.fingerprint] = {
                "fingerprint": finding.fingerprint, "rule_id": finding.rule_id,
                "description": finding.description, "severity": finding.severity,
                "file_path": finding.file_path, "line_number": finding.line_number,
                "matched_text": finding.matched_text, "commits": [], "occurrences": 0,
                "removed_commit": None,
            }
        rec["occurrences"] += 1
        if len(rec["commits"]) < MAX_COMMITS_PER_FINDING:
            rec["commits"].append({"sha": commit["sha"], "date": commit["date"], "action": action,
                                   "author_name": commit["author_name"], "subject": commit["subject"]})
        if action == "added" and finding.line_number:
            rec["line_number"] = finding.line_number

    present = head_fingerprints(mirror)

    findings: List[Dict[str, Any]] = []
    for rec in agg.values():
        # `git log` output is newest-first, so the oldest "added" entry is the introduction.
        added = [c for c in rec["commits"] if c["action"] == "added"]
        removed = [c for c in rec["commits"] if c["action"] == "removed"]
        added.sort(key=lambda c: c["date"])
        removed.sort(key=lambda c: c["date"])
        first = added[0] if added else (rec["commits"][-1] if rec["commits"] else {})
        last = (added[-1] if added else first)
        still_present = (rec["fingerprint"] in present) if present is not None else None
        rec.update({
            "first_commit_sha": first.get("sha", ""), "first_commit_date": first.get("date", ""),
            "first_author_name": first.get("author_name", ""), "first_commit_subject": first.get("subject", ""),
            "last_commit_sha": last.get("sha", ""), "last_commit_date": last.get("date", ""),
            "still_present": still_present,
            "removed_commit_sha": (removed[-1]["sha"] if removed and not still_present else None),
            "removed_commit_date": (removed[-1]["date"] if removed and not still_present else None),
            "commits": sorted(rec["commits"], key=lambda c: c["date"], reverse=True),
            # False when the walked commits only REMOVE this secret: it was
            # introduced before the scanned range (see cmd_scan_history).
            "added_in_range": bool(added),
        })
        findings.append(rec)

    findings.sort(key=lambda r: ({"critical": 0, "high": 1, "medium": 2, "low": 3}.get(r["severity"], 9),
                                 r["first_commit_date"]))
    only_history = sum(1 for f in findings if f["still_present"] is False)
    return {
        "findings": findings,
        "revisions": revisions,
        "commits_walked": min(total_commits, max_commits) if total_commits else 0,
        "total_commits": total_commits,
        "truncated": bool(total_commits and total_commits > max_commits),
        "secrets_total": len(findings),
        "secrets_only_in_history": only_history,
        "secrets_still_present": sum(1 for f in findings if f["still_present"]),
        "duration_seconds": round(time.time() - started, 1),
        "head_tree_readable": present is not None,
    }


def delete_mirror(owner: str, name: str) -> None:
    shutil.rmtree(mirror_path(owner, name), ignore_errors=True)
