"""
Scan files on local disk (a CI checkout), rather than through the GitHub API.

Used by the CI entrypoint (`ci_scan.py` / `python -m app.cli scan-path`), which
runs inside GitHub Actions (or a git hook) where the repo is already checked out.
No network, no API rate limits, no token needed.

Stdlib only.
"""
import os
import subprocess
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from . import scanner

ALWAYS_SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".venv", "venv",
                    "dist", "build", ".next", ".tox", ".mypy_cache", ".pytest_cache", "sentinel-results"}


def _read_text(path: Path) -> Optional[str]:
    try:
        if path.stat().st_size > scanner.MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
    except (OSError, ValueError):
        return None
    if b"\x00" in data[:8000]:
        return None
    return data.decode("utf-8", errors="replace")


def iter_repo_files(root: Path) -> List[str]:
    """Every scannable file under root, as repo-relative paths."""
    out: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ALWAYS_SKIP_DIRS]
        for fn in filenames:
            rel = os.path.relpath(os.path.join(dirpath, fn), root).replace(os.sep, "/")
            if not scanner.should_skip_path(rel):
                out.append(rel)
    return sorted(out)


def changed_files(root: Path, base_ref: str, head_ref: str = "HEAD") -> Optional[List[str]]:
    """Files changed between two git refs, or None if git can't answer (shallow
    clone, unknown/first-push base). Caller should fall back to a full scan."""
    if not base_ref or set(base_ref) <= {"0"}:   # all-zero sha = branch created by this push
        return None
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "diff", "--name-only", "--diff-filter=ACMR", f"{base_ref}..{head_ref}"],
            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return [p.strip().replace(os.sep, "/") for p in proc.stdout.splitlines()
            if p.strip() and not scanner.should_skip_path(p.strip())]


def scan_paths(root: Path, rel_paths: Sequence[str]) -> Tuple[List[scanner.Finding], int]:
    """Scan the given repo-relative paths. Returns (findings, files_scanned)."""
    findings: List[scanner.Finding] = []
    scanned = 0
    for rel in rel_paths:
        content = _read_text(root / rel)
        if content is None:
            continue
        scanned += 1
        findings.extend(scanner.scan_text(rel, content))
    return findings, scanned


def scan_directory(root: Path, base_ref: Optional[str] = None) -> dict:
    """Scan a checkout. With base_ref, only files changed since that ref are
    scanned (much faster and quieter on an existing repo with known findings);
    falls back to the whole tree if git can't resolve it."""
    root = Path(root).resolve()
    mode = "full"
    paths = None
    if base_ref:
        paths = changed_files(root, base_ref)
        mode = "changed-files" if paths is not None else "full (base ref unavailable)"
    if paths is None:
        paths = iter_repo_files(root)
    findings, scanned = scan_paths(root, paths)
    return {"root": str(root), "mode": mode, "files_scanned": scanned,
            "files_considered": len(paths), "findings": findings}


def scan_staged(root: Path) -> dict:
    """Scan only the lines added in the git staging area (what the next commit
    would contain), for a pre-commit hook. Deleted lines are ignored: removing
    a secret should never block a commit."""
    root = Path(root).resolve()
    proc = subprocess.run(
        ["git", "-C", str(root), "diff", "--cached", "--unified=0", "--no-color", "--no-ext-diff",
         "--no-renames", "--diff-filter=ACM"],
        capture_output=True, text=True, errors="replace", timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "git diff --cached failed")

    findings: List[scanner.Finding] = []
    seen, files = set(), set()
    path, line_no = None, 0
    for raw in proc.stdout.splitlines():
        if raw.startswith("+++ "):
            target = raw[4:]
            path = None if target == "/dev/null" else target[2:] if target.startswith("b/") else target
            if path and scanner.should_skip_path(path):
                path = None
            continue
        if raw.startswith("@@"):
            # "@@ -a,b +c,d @@": new-file lines start at c
            try:
                line_no = int(raw.split("+", 1)[1].split(",", 1)[0].split(" ", 1)[0])
            except (IndexError, ValueError):
                line_no = 0
            continue
        if raw.startswith("+") and path:
            files.add(path)
            for f in scanner.scan_line(path, raw[1:5001], line_no):
                if f.fingerprint not in seen:
                    seen.add(f.fingerprint)
                    findings.append(f)
            line_no += 1
    return {"root": str(root), "mode": "staged", "files_scanned": len(files), "findings": findings}
