"""
Minimal GitHub REST API client — just what the scanner needs.

Important details (these were the causes of "it finds nothing"):
* File contents are fetched by COMMIT SHA, never by branch name. Raw URLs
  keyed by branch are CDN-cached for ~5 minutes, so a file you just pushed
  could come back as the old version (or 404) and silently scan clean.
* Rate-limit / auth failures raise loudly instead of being treated as
  "file had no secrets".
* Paths are URL-encoded (spaces, #, unicode in filenames).
* If raw download fails (e.g. private repo), it falls back to the contents API.

Set GITHUB_TOKEN to raise the rate limit (60/hr -> 5000/hr) and to scan
private repos. GITHUB_API_URL / GITHUB_RAW_URL can point at GitHub Enterprise.
"""
import base64
import os
import re
from typing import Optional, List, Dict, Any
from urllib.parse import quote

import httpx


def _api_base() -> str:
    return os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")


def _raw_base() -> str:
    return os.environ.get("GITHUB_RAW_URL", "https://raw.githubusercontent.com").rstrip("/")


class GitHubError(Exception):
    pass


class RateLimitError(GitHubError):
    pass


def _headers() -> Dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "secret-sentinel",
               "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def parse_repo_url(url: str) -> Dict[str, Optional[str]]:
    """Accepts:
      https://github.com/owner/repo            (default branch)
      https://github.com/owner/repo.git
      https://github.com/owner/repo/tree/dev   (scan the 'dev' branch)
      https://github.com/owner/repo/blob/main/some/file.py
      git@github.com:owner/repo.git
      owner/repo
    Returns {"owner", "name", "branch"} (branch may be None = default branch)."""
    url = url.strip().rstrip("/")
    m = re.search(r"github\.com[:/]+([^/\s]+)/([^/\s#?]+?)(?:\.git)?(?:/(?:tree|blob|commits?)/([^?#\s]+))?(?:[/?#].*)?$", url)
    if m:
        branch = m.group(3)
        if branch and m.group(0).find("/blob/") != -1:
            branch = branch.split("/")[0]  # /blob/<branch>/<path> -> keep only the branch
        return {"owner": m.group(1), "name": m.group(2), "branch": branch}
    m = re.match(r"^([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+?)(?:\.git)?$", url)
    if m:
        return {"owner": m.group(1), "name": m.group(2), "branch": None}
    raise GitHubError(f"Could not parse a GitHub owner/repo out of: {url!r}. "
                      f"Use a URL like https://github.com/owner/repo")


class GitHubClient:
    def __init__(self, timeout: float = 30.0):
        self.client = httpx.Client(headers=_headers(), timeout=timeout, follow_redirects=True)

    def close(self):
        self.client.close()

    # ---- helpers ----------------------------------------------------------
    def _get(self, url: str, **kwargs) -> httpx.Response:
        try:
            r = self.client.get(url, **kwargs)
        except httpx.HTTPError as e:
            raise GitHubError(f"Network error talking to GitHub ({url}): {e}") from e
        if r.status_code in (403, 429) and (
            r.headers.get("x-ratelimit-remaining") == "0" or "rate limit" in r.text.lower()
        ):
            reset = r.headers.get("x-ratelimit-reset")
            raise RateLimitError(
                "GitHub API rate limit exceeded"
                + (f" (resets at unix time {reset})" if reset else "")
                + ". Set GITHUB_TOKEN in your environment to get 5000 requests/hour."
            )
        if r.status_code == 401:
            raise GitHubError("GitHub rejected the token (401). Check GITHUB_TOKEN.")
        return r

    def _api(self, path: str, **kwargs) -> Any:
        r = self._get(f"{_api_base()}{path}", **kwargs)
        if r.status_code == 404:
            raise GitHubError(
                f"Not found: {path}. Check the repo URL/branch — and for a private repo, set GITHUB_TOKEN.")
        if r.status_code >= 400:
            raise GitHubError(f"GitHub API error {r.status_code} on {path}: {r.text[:300]}")
        return r.json()

    # ---- repo metadata ----------------------------------------------------
    def get_default_branch(self, owner: str, name: str) -> str:
        return self._api(f"/repos/{owner}/{name}")["default_branch"]

    def get_latest_commit_sha(self, owner: str, name: str, branch: str) -> str:
        return self._api(f"/repos/{owner}/{name}/commits/{quote(branch, safe='')}")["sha"]

    # ---- full-tree scan ---------------------------------------------------
    def list_tree(self, owner: str, name: str, sha: str) -> Dict[str, Any]:
        """Recursive tree at a commit. Returns {"files": [...blob entries], "truncated": bool}."""
        data = self._api(f"/repos/{owner}/{name}/git/trees/{sha}", params={"recursive": "1"})
        files = [e for e in data.get("tree", []) if e.get("type") == "blob"]
        return {"files": files, "truncated": bool(data.get("truncated"))}

    def get_file_at(self, owner: str, name: str, sha: str, path: str) -> Optional[str]:
        """File text at a specific commit, or None if it doesn't exist there."""
        r = self._get(f"{_raw_base()}/{owner}/{name}/{sha}/{quote(path)}")
        if r.status_code == 200:
            return r.content.decode("utf-8", errors="replace")
        if r.status_code == 404 and not os.environ.get("GITHUB_TOKEN"):
            return None
        # Fallback: contents API (works for private repos with a token).
        r = self._get(f"{_api_base()}/repos/{owner}/{name}/contents/{quote(path)}", params={"ref": sha})
        if r.status_code == 404:
            return None
        if r.status_code >= 400:
            raise GitHubError(f"Could not fetch {path}@{sha[:7]}: HTTP {r.status_code}")
        data = r.json()
        if isinstance(data, dict) and data.get("encoding") == "base64":
            return base64.b64decode(data.get("content", "")).decode("utf-8", errors="replace")
        if isinstance(data, dict) and data.get("download_url"):
            r2 = self._get(data["download_url"])
            if r2.status_code == 200:
                return r2.content.decode("utf-8", errors="replace")
        return None

    # ---- GitHub Actions (the dashboard's "CI runs" tab) -------------------
    def _actions(self, path: str, **kwargs) -> Any:
        r = self._get(f"{_api_base()}{path}", **kwargs)
        if r.status_code in (403, 404):
            raise GitHubError(
                "Can't read GitHub Actions for this repository"
                + (" (not found)" if r.status_code == 404 else " (access denied)")
                + ". A private repo needs GITHUB_TOKEN with 'Actions: Read' (fine-grained token).")
        if r.status_code >= 400:
            raise GitHubError(f"GitHub API error {r.status_code} on {path}: {r.text[:300]}")
        return r.json()

    def list_workflow_runs(self, owner: str, name: str, per_page: int = 30) -> List[Dict[str, Any]]:
        """Most recent workflow runs of any workflow, newest first."""
        data = self._actions(f"/repos/{owner}/{name}/actions/runs", params={"per_page": per_page})
        return data.get("workflow_runs", [])

    def list_run_artifacts(self, owner: str, name: str, run_id: int) -> List[Dict[str, Any]]:
        data = self._actions(f"/repos/{owner}/{name}/actions/runs/{run_id}/artifacts")
        return data.get("artifacts", [])

    def read_artifact_file(self, owner: str, name: str, artifact_id: int, filename: str,
                           max_bytes: int = 5_000_000) -> Optional[bytes]:
        """One file out of a run artifact (GitHub serves artifacts as a zip,
        through a redirect to short-lived storage; httpx drops the token on
        that cross-origin hop). None if the file isn't in the artifact."""
        import io
        import zipfile
        r = self._get(f"{_api_base()}/repos/{owner}/{name}/actions/artifacts/{artifact_id}/zip")
        if r.status_code in (403, 404, 410):
            return None
        if r.status_code >= 400:
            raise GitHubError(f"Artifact download failed: HTTP {r.status_code}")
        if len(r.content) > max_bytes:
            return None
        try:
            with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
                for info in zf.infolist():
                    if info.filename.rsplit("/", 1)[-1] == filename and info.file_size <= max_bytes:
                        return zf.read(info)
        except zipfile.BadZipFile:
            return None
        return None

    # ---- incremental scan -------------------------------------------------
    def compare(self, owner: str, name: str, base_sha: str, head_sha: str) -> Dict[str, Any]:
        """Files changed between two commits. Raises GitHubError if base is no longer
        reachable (force-push / history rewrite) so the caller can fall back to a full scan."""
        return self._api(f"/repos/{owner}/{name}/compare/{base_sha}...{head_sha}")
