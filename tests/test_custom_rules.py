"""
Tests for custom rules (.sentinel-rules.json) and the commit author / local
time added to CI alerts.

Run:  python3 -m tests.test_custom_rules      (needs git; no other dependencies)
"""
import contextlib
import io
import json
import os
import subprocess
import tempfile
from pathlib import Path

from app import scanner
from app.cli import main

FAILURES = []


def check(label, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}" + (f"  ({detail})" if detail and not cond else ""))
    if not cond:
        FAILURES.append(label)


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


def git(root, *a, env=None):
    return subprocess.run(["git", "-C", str(root), *a], capture_output=True, text=True, check=True,
                          env={**os.environ, **(env or {})}).stdout.strip()


ACME_KEY = "acme_Q7wErTyUiOpAsDfGhJkLzXcVbNm12345"   # fake, 32 chars after the prefix
RULES = {"rules": [
    {"id": "acme-api-key", "description": "Acme API key",
     "pattern": r"\b(?P<secret>acme_[A-Za-z0-9]{32})\b", "severity": "critical"},
    {"id": "acme-session", "pattern": r"\bsess_(?P<secret>[A-Za-z0-9]{20,})", "severity": "medium",
     "min_entropy": 3.5},
]}


def write_rules(path: Path, data) -> Path:
    path.write_text(json.dumps(data) if not isinstance(data, str) else data, encoding="utf-8")
    return path


def test_rules():
    print("1) Loading and using custom rules")
    tmp = Path(tempfile.mkdtemp())
    rules = scanner.load_custom_rules(write_rules(tmp / "r.json", RULES))
    check("two rules loaded", [r.id for r in rules] == ["acme-api-key", "acme-session"], [r.id for r in rules])
    check("description defaults to the id", rules[1].description == "acme-session")

    scanner.set_custom_rules(rules)
    try:
        found = scanner.scan_text("config.py", f'ACME_TOKEN = "{ACME_KEY}"')
        check("custom format beats the generic rule (one finding)",
              [(f.rule_id, f.severity) for f in found] == [("acme-api-key", "critical")],
              [(f.rule_id, f.severity) for f in found])
        check("value is masked", ACME_KEY not in found[0].matched_text if found else False)
        check("min_entropy rejects a low-randomness match",
              scanner.scan_text("x.py", "sess_aaaaaaaaaaaaaaaaaaaaaaaa") == [])
        check("min_entropy accepts a random match",
              [f.rule_id for f in scanner.scan_text("x.py", "sess_Zq8Rk2Lw9Tv4Xn7Bm1Hc6")] == ["acme-session"])
        order = [r.id for r in scanner.active_rules()]
        check("custom rules sit after built-in formats, before generic rules",
              order.index("private-key-block") < order.index("acme-api-key")
              < order.index("generic-secret-assignment"))
    finally:
        scanner.set_custom_rules([])
    check("clearing restores the built-in list",
          [r.id for r in scanner.active_rules()] == [r.id for r in scanner.RULES])

    print("2) Bad rules files are refused with a clear message")
    bad = {
        "invalid JSON": "{not json",
        "missing rules list": {"rule": []},
        "bad regex": {"rules": [{"id": "x-rule", "pattern": "(unclosed"}]},
        "clash with a built-in id": {"rules": [{"id": "stripe-key", "pattern": "abc"}]},
        "duplicate id": {"rules": [{"id": "dup-rule", "pattern": "a"}, {"id": "dup-rule", "pattern": "b"}]},
        "bad severity": {"rules": [{"id": "x-rule", "pattern": "a", "severity": "urgent"}]},
        "bad id": {"rules": [{"id": "Has Spaces", "pattern": "a"}]},
        "empty pattern": {"rules": [{"id": "x-rule", "pattern": ""}]},
    }
    for label, data in bad.items():
        try:
            scanner.load_custom_rules(write_rules(tmp / "bad.json", data))
            check(f"refuses {label}", False)
        except scanner.RulesFileError as e:
            check(f"refuses {label}", "bad.json" in str(e), str(e))


def build_repo() -> Path:
    root = Path(tempfile.mkdtemp()) / "svc"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.email", "alice@example.com")
    git(root, "config", "user.name", "Alice Dev")
    (root / "app.py").write_text("print('hi')\n")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "init", env={"GIT_COMMITTER_DATE": "2026-09-27T08:36:31+00:00"})
    return root


def test_cli():
    # CI runners set these; they would point the scan at the runner's commit
    # instead of the temporary repos built here.
    for k in ("GITHUB_ACTIONS", "GITHUB_STEP_SUMMARY", "GITHUB_SHA", "GITHUB_REPOSITORY", "GIT_COMMIT",
              "JOB_NAME", "SMTP_HOST", "SLACK_WEBHOOK_URL", "SENTINEL_TIMEZONE"):
        os.environ.pop(k, None)
    root = build_repo()

    print("3) The CLI picks up .sentinel-rules.json automatically")
    write_rules(root / ".sentinel-rules.json", RULES)
    (root / "settings.py").write_text(f'ACME = "{ACME_KEY}"\n')
    git(root, "add", "-A")
    git(root, "commit", "-qm", "add acme key")
    code, out, err = run_cli("scan-path", str(root), "--json")
    data = json.loads(out)
    check("custom rule fires from the default rules file",
          [f["rule_id"] for f in data["findings"]] == ["acme-api-key"], data["findings"])
    check("critical custom finding fails the build", code == 1, code)
    check("load is reported", "loaded 2 custom rule(s)" in err, err)
    check("the rules file itself is never scanned",
          not any(f["file_path"] == ".sentinel-rules.json" for f in data["findings"]))

    code, out, _ = run_cli("scan-history", str(root), "--json")
    check("history scan uses custom rules too",
          [f["rule_id"] for f in json.loads(out)["findings"]] == ["acme-api-key"], out[-300:])

    sarif = root / "out.sarif"
    run_cli("scan-path", str(root), "--sarif", str(sarif), "--fail-on", "none")
    ids = {r["id"] for r in json.loads(sarif.read_text())["runs"][0]["tool"]["driver"]["rules"]}
    check("SARIF declares the custom rule", "acme-api-key" in ids)

    write_rules(root / "broken.json", "{oops")
    code, _, err = run_cli("scan-path", str(root), "--rules-file", str(root / "broken.json"))
    check("a broken --rules-file exits 2", code == 2 and "not valid JSON" in err, (code, err))
    code, _, err = run_cli("scan-path", str(root), "--rules-file", str(root / "missing.json"))
    check("a missing --rules-file exits 2", code == 2, (code, err))
    (root / ".sentinel-rules.json").unlink()
    code, out, _ = run_cli("scan-path", str(root), "--json", "--fail-on", "none")
    check("without the file, custom rules are gone again",
          not any(f["rule_id"] == "acme-api-key" for f in json.loads(out)["findings"]))

    print("4) Commit author and local time in reports and alerts")
    code, out, _ = run_cli("scan-path", str(root), "--json", "--fail-on", "none", "--timezone", "Asia/Kolkata")
    data = json.loads(out)
    check("commit author reported", data.get("commit_author") == "Alice Dev", data.get("commit_author"))
    check("scan time in the chosen zone", data.get("scanned_at", "").endswith(" IST"), data.get("scanned_at"))

    # A PR build checks out GitHub's merge commit; the author shown should be
    # the PR head's, not whoever made the merge commit.
    git(root, "checkout", "-qb", "feature")
    git(root, "config", "user.name", "Bob Contributor")
    (root / "b.py").write_text("x = 1\n")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "feature", env={"GIT_COMMITTER_DATE": "2026-09-27T08:36:31+00:00"})
    git(root, "checkout", "-q", "main")
    git(root, "config", "user.name", "Merge Bot")
    git(root, "merge", "-q", "--no-ff", "feature", "-m", "merge")
    code, out, _ = run_cli("scan-path", str(root), "--json", "--fail-on", "none", "--timezone", "Asia/Kolkata")
    data = json.loads(out)
    check("merge commit -> PR head author", data.get("commit_author") == "Bob Contributor",
          data.get("commit_author"))
    check("commit time converted to the zone", data.get("commit_time") == "27 Sep 2026, 02:06 PM IST",
          data.get("commit_time"))

    summary = root / "summary.md"
    run_cli("scan-path", str(root), "--fail-on", "none", "--summary", str(summary))
    check("job summary shows the author", "Bob Contributor" in summary.read_text())

    code, out, err = run_cli("scan-path", str(root), "--json", "--fail-on", "none", "--timezone", "Mars/Olympus")
    check("unknown zone falls back to UTC with a warning",
          "UTC" in json.loads(out)["scanned_at"] and "unknown timezone" in err, err)

    plain = Path(tempfile.mkdtemp())
    (plain / "a.txt").write_text("hello\n")
    code, out, _ = run_cli("scan-path", str(plain), "--json")
    data = json.loads(out)
    check("outside git: no author, still a scan time", "commit_author" not in data and "scanned_at" in data,
          data)


def main_all():
    test_rules()
    test_cli()
    print(f"\n{'ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main_all())
