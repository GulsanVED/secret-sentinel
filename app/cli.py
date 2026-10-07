"""
Command-line entrypoint — this is what GitHub Actions and the git hooks run.

  # scan a checkout, email anything found, fail the build on critical/high
  python -m app.cli scan-path . --email --fail-on high

  # only scan what this push changed
  python -m app.cli scan-path . --diff-base $GITHUB_EVENT_BEFORE --email

  # scan a repo through the GitHub API and record it in the dashboard DB
  python -m app.cli scan-repo https://github.com/owner/repo

  # scan git history: every commit on every branch, or just a PR's commits
  python -m app.cli scan-history .
  python -m app.cli scan-history . --range origin/main..HEAD

  # git hooks (.githooks/): what the next commit adds / what a push would upload
  python -m app.cli scan-staged .
  python -m app.cli scan-history . --unpushed

  # verify SMTP settings
  python -m app.cli test-email

Build gating: only NEW findings at/above --fail-on fail the build. Findings
matched by .sentinelignore are dropped; ones listed in the baseline
(.sentinel-baseline.json, written with --write-baseline) are reported as
"baselined" but do not fail it. Inside GitHub Actions, findings are also
printed as annotations and written to the job summary.

Exit codes: 0 = nothing new at/above the threshold, 1 = new findings at/above
it, 2 = error. `scan-path` and `scan-history` need only the standard library
(and git).
"""
import argparse
import json
import os
import sys
from pathlib import Path
from typing import List

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().removeprefix("export ").strip()
        value = value.strip().strip('"').strip("'")
        if key and value and key not in os.environ:
            os.environ[key] = value


def _fmt_findings(findings: List, label: str, mode: str, files_scanned: int, commit: str = "") -> str:
    lines = [f"Secret Sentinel scan of {label}" + (f" @ {commit[:7]}" if commit else ""),
             f"mode: {mode}, files scanned: {files_scanned}, findings: {len(findings)}", ""]
    for f in sorted(findings, key=lambda f: -SEVERITY_ORDER.get(f["severity"], 0)):
        tag = " (baselined)" if f.get("status") == "baselined" else ""
        lines.append(f"[{f['severity'].upper():8s}] {f['description']}{tag}")
        lines.append(f"             {f['file_path']}:{f['line_number']}   value: {f['value_masked']}")
        lines.append(f"             fingerprint: {f['fingerprint']}")
    return "\n".join(lines)


def _tree_finding(f) -> dict:
    return {"rule_id": f.rule_id, "description": f.description, "severity": f.severity,
            "file_path": f.file_path, "line_number": f.line_number, "value_masked": f.matched_text,
            "fingerprint": f.fingerprint, "source": "tree"}


def _history_finding(rec: dict) -> dict:
    return {"rule_id": rec["rule_id"], "description": rec["description"], "severity": rec["severity"],
            "file_path": rec["file_path"], "line_number": rec["line_number"],
            "value_masked": rec["matched_text"], "fingerprint": rec["fingerprint"], "source": "history",
            "commit": rec["first_commit_sha"], "author": rec["first_author_name"],
            "date": rec["first_commit_date"], "subject": rec["first_commit_subject"],
            "still_present": rec["still_present"], "removed_commit": rec["removed_commit_sha"],
            "occurrences": rec["occurrences"]}


def _in_github_actions() -> bool:
    return os.environ.get("GITHUB_ACTIONS") == "true"


def _load_rules(args, root: Path):
    """Load the team's custom rules (default <path>/.sentinel-rules.json, if it
    exists). Returns an exit code on error, else None."""
    from . import scanner
    path = Path(args.rules_file) if args.rules_file else root / ".sentinel-rules.json"
    if not args.rules_file and not path.is_file():
        scanner.set_custom_rules([])
        return None
    try:
        rules = scanner.load_custom_rules(path)
    except scanner.RulesFileError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    scanner.set_custom_rules(rules)
    print(f"loaded {len(rules)} custom rule(s) from {path}", file=sys.stderr)
    return None


def _format_time(when, tz_name: str) -> str:
    from datetime import timezone
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(tz_name)
    except Exception:  # unknown zone name or no tz database: fall back to UTC
        print(f"warning: unknown timezone {tz_name!r}, using UTC", file=sys.stderr)
        tz = timezone.utc
    return when.astimezone(tz).strftime("%d %b %Y, %I:%M %p %Z")


def _commit_context(root: Path, commit: str, tz_name: str) -> dict:
    """Who wrote the commit under test, when, and when it was scanned, for
    alerts. On a pull request's merge commit, the PR head (last parent) is the
    author's own commit. Empty values are dropped (e.g. not a git checkout)."""
    import subprocess
    from datetime import datetime, timezone

    out = {"scanned_at": _format_time(datetime.now(timezone.utc), tz_name)}
    try:
        def git(*a):
            return subprocess.run(["git", "-C", str(root), *a], capture_output=True, text=True,
                                  timeout=30).stdout.strip()
        sha = git("rev-parse", "--verify", "-q", f"{commit or 'HEAD'}^{{commit}}")
        parents = git("log", "-1", "--format=%P", sha).split() if sha else []
        if len(parents) > 1:
            sha = parents[-1]
        info = git("log", "-1", "--format=%an%x1f%cI", sha) if sha else ""
    except (OSError, subprocess.SubprocessError):
        info = ""
    if "\x1f" in info:
        author, iso = info.split("\x1f", 1)
        out["commit_author"] = author
        try:
            out["commit_time"] = _format_time(datetime.fromisoformat(iso), tz_name)
        except ValueError:
            pass
    return out


def _finish(args, root: Path, kind: str, raw_findings: List[dict], label: str, commit: str,
            meta: dict, text_report) -> int:
    """Shared tail of every local scan: policy -> outputs -> alerts -> gate."""
    from . import alerts, policy, reporting

    ignore_path = Path(args.ignore_file) if args.ignore_file else root / policy.DEFAULT_IGNORE_FILE
    baseline_path = Path(args.baseline) if args.baseline else root / policy.DEFAULT_BASELINE_FILE
    try:
        baseline = policy.load_baseline(baseline_path)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    findings = policy.apply(raw_findings, policy.load_ignore(ignore_path), baseline)
    context = _commit_context(root, commit, args.timezone)
    meta = {**meta, **context}

    if args.write_baseline:
        total = policy.write_baseline(Path(args.write_baseline), findings)
        print(f"baseline written to {args.write_baseline}: {total} fingerprint(s)", file=sys.stderr)

    threshold = SEVERITY_ORDER.get(args.fail_on) if args.fail_on != "none" else None
    new = [f for f in findings if f["status"] == "new"]
    gating = [f for f in new if threshold is not None and SEVERITY_ORDER.get(f["severity"], 0) >= threshold]

    report = {"label": label, "commit": commit, "scan": kind, **meta, "findings": findings}
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(text_report(findings))
    if args.json_out:
        gating_ids = {id(f) for f in gating}
        report = {**report, "fail_on": args.fail_on, "blocked": bool(gating),
                  "findings": [{**f, "gating": id(f) in gating_ids} for f in findings]}
        Path(args.json_out).write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    if args.sarif:
        Path(args.sarif).write_text(json.dumps(reporting.to_sarif(findings), indent=2), encoding="utf-8")
        print(f"SARIF written to {args.sarif}", file=sys.stderr)

    if args.annotations == "on" or (args.annotations == "auto" and _in_github_actions()):
        # stderr, so --json on stdout stays parseable; the runner reads both.
        for line in reporting.github_annotations(findings, threshold if threshold is not None else 99):
            print(line, file=sys.stderr)

    summary_path = args.summary or (os.environ.get("GITHUB_STEP_SUMMARY") if _in_github_actions() else None)
    if summary_path:
        title = "Secret scan — git history" if kind == "history" else "Secret scan — code"
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(reporting.markdown_summary(title, findings, meta, bool(gating), args.fail_on) + "\n")

    # Alerts: only NEW findings, so a baselined secret doesn't email on every push.
    repo_url = args.repo_url or (f"https://github.com/{label}" if "/" in label else "")
    if new and (args.email or args.slack):
        events = []
        for f in new:
            ref = f.get("commit") or commit
            desc = f["description"]
            if kind == "history":
                desc += (f" — committed {f['commit'][:7]} by {f.get('author') or '?'}"
                         + ("" if f.get("still_present") else ", deleted from code but still in history"))
            events.append({"kind": "new_secret", "severity": f["severity"], "description": desc,
                           "file_path": f["file_path"], "line_number": f["line_number"],
                           "matched_text": f["value_masked"],
                           "link": (f"{repo_url}/blob/{ref}/{f['file_path']}#L{f['line_number']}"
                                    if repo_url and ref else None)})
        who = ""
        if context.get("commit_author"):
            who = f" Commit by {context['commit_author']}" + (
                f" on {context['commit_time']}" if context.get("commit_time") else "") + "."
        summary = (f"CI {'history' if kind == 'history' else 'code'} scan of {label}"
                   + (f" at commit {commit[:7]}" if commit else "")
                   + ": " + ", ".join(f"{k}: {v}" for k, v in meta.items() if k not in context)
                   + f"; {len(new)} new finding(s)." + who
                   + f" Scanned {context['scanned_at']}.")
        if args.email:
            if not alerts.email_configured():
                print("warning: --email given but SMTP_HOST / ALERT_EMAIL_TO are not set", file=sys.stderr)
            else:
                ok = alerts.send_scan_digest(label, repo_url or label, events, summary)
                print(("email sent" if ok else "email FAILED — see log above"), file=sys.stderr)
        if args.slack:
            if not os.environ.get("SLACK_WEBHOOK_URL"):
                print("warning: --slack given but SLACK_WEBHOOK_URL is not set", file=sys.stderr)
            else:
                ok = alerts.send_slack_digest(label, events, summary)
                print(("slack message sent" if ok else "slack FAILED — see log above"), file=sys.stderr)

    if getattr(args, "notify_url", None):
        _notify(args.notify_url, args.notify_token, label, commit, new)

    if gating:
        print(f"\nFAILED: {len(gating)} new finding(s) at or above severity '{args.fail_on}'.", file=sys.stderr)
        return 1
    return 0


def _label_and_commit(args, root: Path):
    label = args.label or os.environ.get("GITHUB_REPOSITORY") or root.name
    commit = args.commit or os.environ.get("GITHUB_SHA") or ""
    return label, commit


def cmd_scan_path(args) -> int:
    from . import local_scan

    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2
    label, commit = _label_and_commit(args, root)
    if (code := _load_rules(args, root)) is not None:
        return code
    result = local_scan.scan_directory(root, base_ref=args.diff_base)
    raw = [_tree_finding(f) for f in result["findings"]]
    meta = {"mode": result["mode"], "files_scanned": result["files_scanned"]}

    def text(findings):
        return _fmt_findings(findings, label, result["mode"], result["files_scanned"], commit)
    return _finish(args, root, "tree", raw, label, commit, meta, text)


def cmd_scan_staged(args) -> int:
    """Scan what the next commit would add (for a pre-commit hook)."""
    from . import local_scan

    root = Path(args.path).resolve()
    label, commit = _label_and_commit(args, root)
    if (code := _load_rules(args, root)) is not None:
        return code
    try:
        result = local_scan.scan_staged(root)
    except (RuntimeError, OSError) as e:
        print(f"error: cannot read staged changes: {e}", file=sys.stderr)
        return 2
    raw = [_tree_finding(f) for f in result["findings"]]
    meta = {"mode": "staged", "files_scanned": result["files_scanned"]}

    def text(findings):
        return _fmt_findings(findings, label, "staged changes", result["files_scanned"], commit)
    return _finish(args, root, "tree", raw, label, commit, meta, text)


def cmd_scan_history(args) -> int:
    from . import history_scan

    root = Path(args.path).resolve()
    label, commit = _label_and_commit(args, root)
    if (code := _load_rules(args, root)) is not None:
        return code
    revisions = None
    if args.unpushed:
        # Commits reachable from the tips being pushed but from no remote-tracking
        # ref: exactly what a push would upload, even for a brand-new branch.
        revisions = [*(args.tip or ["HEAD"]), "--not", "--remotes"]
    elif args.range:
        base = args.range.split("..", 1)[0]
        if base and set(base) <= {"0"}:          # new branch: no "before" commit
            revisions = None
        else:
            revisions = [args.range]
    try:
        result = history_scan.scan_git_dir(root, revisions=revisions, max_commits=args.max_commits)
    except history_scan.HistoryScanError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    records = result["findings"]
    if revisions is not None:
        # A scoped scan (push, PR, pre-push) answers "do these commits leak a
        # secret?". A commit that only deletes one leaks nothing new: the secret
        # came from an earlier commit, outside this range. Counting it would fail
        # the very commit that cleans it up and blame its author.
        records = [r for r in records if r.get("added_in_range", True)]
    raw = [_history_finding(r) for r in records]
    meta = {"range": " ".join(result["revisions"]), "commits_scanned": result["commits_walked"],
            "only_in_history": result["secrets_only_in_history"]}
    if result["truncated"]:
        meta["truncated_at"] = args.max_commits

    def text(findings):
        lines = [f"Secret Sentinel history scan of {label} ({' '.join(result['revisions'])})",
                 f"commits scanned: {result['commits_walked']}"
                 + (f" (truncated, {result['total_commits']} total)" if result["truncated"] else "")
                 + f", findings: {len(findings)}", ""]
        for f in sorted(findings, key=lambda f: -SEVERITY_ORDER.get(f["severity"], 0)):
            state = "in code" if f["still_present"] else "HISTORY ONLY"
            tag = " (baselined)" if f["status"] == "baselined" else ""
            lines.append(f"[{f['severity'].upper():8s}] {f['description']}{tag}")
            lines.append(f"             {f['file_path']}:{f['line_number']}   value: {f['value_masked']}   [{state}]")
            lines.append(f"             introduced {f['commit'][:10]} {f['date'][:10]} by {f['author']}:"
                         f" {f['subject'][:60]}")
            lines.append(f"             fingerprint: {f['fingerprint']}")
        return "\n".join(lines)
    return _finish(args, root, "history", raw, label, commit, meta, text)


def _notify(url: str, token: str, label: str, commit: str, findings: List) -> None:
    """Tell a running Secret Sentinel server about this CI scan (optional)."""
    import urllib.error
    from .alerts import post_json
    payload = {
        "repo": label, "commit": commit,
        "findings": [{k: f[k] for k in ("rule_id", "severity", "file_path", "line_number", "description")}
                     for f in findings],
    }
    try:
        status = post_json(url, payload, {"X-Sentinel-Token": token} if token else None, timeout=20)
        print(f"notified {url}: HTTP {status}", file=sys.stderr)
    except (urllib.error.URLError, OSError, ValueError) as e:
        print(f"warning: could not notify {url}: {e}", file=sys.stderr)


def cmd_scan_repo(args) -> int:
    from . import db, pipeline
    from .github_client import GitHubError
    db.init_db()
    try:
        result = pipeline.add_and_scan_repo(args.url)
    except GitHubError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(result["summary"])
    if args.fail_on != "none":
        threshold = SEVERITY_ORDER.get(args.fail_on, 3)
        active = [f for f in db.list_findings(repo_id=result["repo_id"], status="active")
                  if SEVERITY_ORDER.get(f["severity"], 0) >= threshold]
        if active:
            print(f"FAILED: {len(active)} active finding(s) at or above '{args.fail_on}'.", file=sys.stderr)
            return 1
    return 0


def cmd_test_email(args) -> int:
    from . import alerts
    if not alerts.email_configured():
        print("error: SMTP_HOST and ALERT_EMAIL_TO must be set (check your .env)", file=sys.stderr)
        return 2
    print(f"sending test email to {os.environ.get('ALERT_EMAIL_TO')} via "
          f"{os.environ.get('SMTP_HOST')}:{os.environ.get('SMTP_PORT', '587')} …")
    ok = alerts.send_test_email()
    print("sent" if ok else "FAILED — see the error above", file=sys.stderr)
    return 0 if ok else 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secret-sentinel", description="Scan for exposed secrets.")
    sub = p.add_subparsers(dest="command", required=True)

    fail_choices = ["none", "low", "medium", "high", "critical"]

    def add_common(sp):
        sp.add_argument("path", nargs="?", default=".")
        sp.add_argument("--label", default=None, help="name for reports (default: $GITHUB_REPOSITORY)")
        sp.add_argument("--commit", default=None, help="commit sha for report links (default: $GITHUB_SHA)")
        sp.add_argument("--repo-url", default=None, help="repo URL used to build links in alerts")
        sp.add_argument("--json", action="store_true", help="machine-readable output on stdout")
        sp.add_argument("--json-out", default=None, metavar="FILE",
                        help="also write the JSON report, with the gate decision, to FILE")
        sp.add_argument("--sarif", default=None, metavar="FILE", help="also write a SARIF 2.1.0 report")
        sp.add_argument("--summary", default=None, metavar="FILE",
                        help="append a Markdown summary (default in GitHub Actions: $GITHUB_STEP_SUMMARY)")
        sp.add_argument("--annotations", default="auto", choices=["auto", "on", "off"],
                        help="print GitHub Actions ::error annotations (auto = when running in Actions)")
        sp.add_argument("--ignore-file", default=None, help="default: <path>/.sentinelignore")
        sp.add_argument("--baseline", default=None, help="default: <path>/.sentinel-baseline.json")
        sp.add_argument("--write-baseline", default=None, metavar="FILE",
                        help="record the current findings as accepted (merges into FILE)")
        sp.add_argument("--email", action="store_true", help="email new findings (needs SMTP_* env vars)")
        sp.add_argument("--slack", action="store_true", help="post new findings to $SLACK_WEBHOOK_URL")
        sp.add_argument("--rules-file", default=None,
                        help="custom rules JSON (default: <path>/.sentinel-rules.json if present)")
        sp.add_argument("--timezone", default=os.environ.get("SENTINEL_TIMEZONE") or "UTC",
                        help="IANA zone for times in alerts, e.g. Asia/Kolkata (default: $SENTINEL_TIMEZONE or UTC)")
        sp.add_argument("--fail-on", default="high", choices=fail_choices,
                        help="exit 1 when a NEW finding is at/above this severity (default: high)")

    sp = sub.add_parser("scan-path", help="scan a local checkout (for CI)")
    add_common(sp)
    sp.add_argument("--diff-base", default=None,
                    help="only scan files changed since this git ref (e.g. the push's 'before' sha)")
    sp.add_argument("--notify-url", default=None, help="POST results to a Secret Sentinel server")
    sp.add_argument("--notify-token", default=os.environ.get("SENTINEL_TOKEN", ""))
    sp.set_defaults(func=cmd_scan_path)

    sh = sub.add_parser("scan-history", help="scan the git history of a local checkout (for CI)")
    add_common(sh)
    sh.add_argument("--range", default=None,
                    help="git revision range, e.g. origin/main..HEAD (default: every commit on every ref)")
    sh.add_argument("--unpushed", action="store_true",
                    help="only commits not on any remote yet (for a pre-push hook)")
    sh.add_argument("--tip", action="append", default=None,
                    help="with --unpushed: a commit being pushed (repeatable; default HEAD)")
    sh.add_argument("--max-commits", type=int, default=int(os.environ.get("HISTORY_MAX_COMMITS", "5000")))
    sh.set_defaults(func=cmd_scan_history)

    ss = sub.add_parser("scan-staged", help="scan the lines staged for the next commit (pre-commit hook)")
    add_common(ss)
    ss.set_defaults(func=cmd_scan_staged)

    sr = sub.add_parser("scan-repo", help="scan a GitHub repo via the API and store results")
    sr.add_argument("url")
    sr.add_argument("--fail-on", default="none", choices=["none", "low", "medium", "high", "critical"])
    sr.set_defaults(func=cmd_scan_repo)

    te = sub.add_parser("test-email", help="send a test email to check SMTP settings")
    te.set_defaults(func=cmd_test_email)
    return p


def main(argv=None) -> int:
    _load_dotenv(Path(__file__).resolve().parent.parent / ".env")
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
