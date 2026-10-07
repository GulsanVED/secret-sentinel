#!/usr/bin/env python3
"""
Post the secret-scan result as ONE comment on the pull request, and keep that
comment up to date on every push.

    python3 ci/pr_comment.py <result.json>

Needs, from the workflow: GITHUB_TOKEN (with `pull-requests: write`),
GITHUB_REPOSITORY and PR_NUMBER; GITHUB_API_URL is set by Actions.

- Blocked or failed scan: create the comment, or update the existing one.
- Clean scan: update an existing comment to say the findings are resolved;
  if there never was one, stay quiet (no noise on clean pull requests).
- It never fails the job: on a fork's pull request the token is read-only, so
  it prints a warning and exits 0. The check itself is the gate.

Values in the comment are masked, exactly as in the scan output. Stdlib only.
"""
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Optional, Tuple

MARKER = "<!-- secret-sentinel -->"
MAX_ROWS = 20
ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}


def _api(method: str, path: str, token: str, body: Optional[dict] = None) -> Tuple[int, object]:
    base = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    url = base + path
    if not url.startswith(("https://", "http://")):
        raise ValueError(f"refusing non-http(s) URL: {url}")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json",
        "User-Agent": "secret-sentinel"})
    try:
        # URL scheme checked above; only the GitHub API is called.
        with urllib.request.urlopen(req, timeout=20) as resp:  # nosec B310
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, None


def render(result: dict) -> str:
    repo = result.get("repository", "")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    sha = result.get("sha") or ""
    status = result.get("status")
    gating = [f for f in result.get("findings", []) if f.get("gating")]

    if status == "blocked":
        head = f"### 🛑 Secret Sentinel blocked this pull request\n\n{len(gating)} new secret(s) at or above `{result.get('fail_on')}`. Values are masked."
    elif status == "error":
        head = "### ⚠️ Secret Sentinel could not finish the scan\n\nThe check failed without a verdict; see the run log."
    else:
        head = "### ✅ Secret Sentinel: no new secrets\n\nThe earlier findings on this pull request are resolved."
    lines = [MARKER, head, ""]

    if gating:
        lines += ["| | Secret | Where | Value | Found in |", "|---|---|---|---|---|"]
        for f in gating[:MAX_ROWS]:
            path, line = f.get("file_path", ""), f.get("line_number") or 0
            where = f"`{path}:{line}`" if line else f"`{path}`"
            if repo and sha and line:
                where = f"[{where}]({server}/{repo}/blob/{sha}/{path}#L{line})"
            if f.get("source") == "history":
                found = f"history, commit `{(f.get('commit') or '')[:7]}`"
                if f.get("author"):
                    found += f" by {f['author']}"
            else:
                found = "current code"
            sev = f.get("severity", "")
            lines.append(f"| {ICON.get(sev, '')} {sev} | {f.get('description', '')} | {where} "
                         f"| `{f.get('value_masked', '')}` | {found} |")
        if len(gating) > MAX_ROWS:
            lines.append(f"\n…and {len(gating) - MAX_ROWS} more in the run's summary.")
        lines += ["", "**What to do:** rotate each key at its provider (it was pushed, so assume it is exposed), "
                      "then read it from the environment instead. A test value or false positive: add "
                      "`# sentinel:ignore` to the line, or an entry to `.sentinelignore`. A secret that is "
                      "rotated but still in history: add it to `.sentinel-baseline.json`."]
    footer = []
    if result.get("run_url"):
        footer.append(f"[run log]({result['run_url']})")
    if sha:
        footer.append(f"commit `{sha[:7]}`")
    if result.get("scanned_at"):
        footer.append(f"scanned {result['scanned_at']}")
    if footer:
        lines += ["", "<sub>" + " · ".join(footer) + "</sub>"]
    return "\n".join(lines)


def find_existing(repo: str, pr: str, token: str) -> Optional[int]:
    for page in range(1, 6):
        code, comments = _api("GET", f"/repos/{repo}/issues/{pr}/comments?per_page=100&page={page}", token)
        if code != 200 or not comments:
            return None
        for c in comments:
            if MARKER in (c.get("body") or ""):
                return c["id"]
        if len(comments) < 100:
            return None
    return None


def main(argv) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 0
    repo, pr, token = (os.environ.get(k, "") for k in ("GITHUB_REPOSITORY", "PR_NUMBER", "GITHUB_TOKEN"))
    if not (repo and pr.isdigit() and token):
        print("not a pull request run (or no token): no comment")
        return 0
    try:
        with open(argv[1], encoding="utf-8") as fh:
            result = json.load(fh)
    except (OSError, ValueError) as e:
        print(f"::warning::no scan result to comment on: {e}")
        return 0

    existing = find_existing(repo, pr, token)
    if result.get("status") == "passed" and existing is None:
        print("clean scan and no earlier comment: nothing to post")
        return 0
    body = {"body": render(result)}
    if existing is None:
        code, _ = _api("POST", f"/repos/{repo}/issues/{pr}/comments", token, body)
        action = "posted"
    else:
        code, _ = _api("PATCH", f"/repos/{repo}/issues/comments/{existing}", token, body)
        action = "updated"
    if code in (200, 201):
        print(f"pull request comment {action}")
    elif code in (403, 404):
        print("::warning::Could not comment on the pull request (a fork's read-only token, or the "
              "workflow lacks `pull-requests: write`). The check result still applies.")
    else:
        print(f"::warning::Commenting on the pull request failed with HTTP {code}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
