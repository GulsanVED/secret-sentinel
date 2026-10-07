"""
Tests for the CI pipeline pieces: `scan-history` on a local checkout (full
history and a pull request's commit range), .sentinelignore, the baseline,
SARIF output, GitHub annotations / job summary, and build gating.

Run:  python3 -m tests.test_gating      (needs git; no other dependencies)
"""
import contextlib
import io
import json
import os
import subprocess
import tempfile
from pathlib import Path

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


def git(root, *a):
    return subprocess.run(["git", "-C", str(root), *a], capture_output=True, text=True, check=True).stdout.strip()


def build_repo() -> Path:
    root = Path(tempfile.mkdtemp()) / "svc"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.email", "dev@example.com")
    git(root, "config", "user.name", "Dev")
    (root / "app.py").write_text("import os\nKEY = os.environ['KEY']\n")
    git(root, "add", "-A"); git(root, "commit", "-qm", "clean start")

    # A secret committed and then deleted on main (history only).
    (root / "deploy.sh").write_text("export AWS_ACCESS_KEY_ID=AKIAQWERTYUIOPASDFGH\n")
    git(root, "add", "-A"); git(root, "commit", "-qm", "add deploy")
    (root / "deploy.sh").write_text("export AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID\n")
    git(root, "add", "-A"); git(root, "commit", "-qm", "read key from env")

    # Test fixtures that should be ignored via .sentinelignore.
    (root / "tests").mkdir()
    (root / "tests" / "fixtures.py").write_text('FAKE = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"\n')
    (root / ".sentinelignore").write_text("# fixtures\ntests/\n")
    git(root, "add", "-A"); git(root, "commit", "-qm", "tests")
    return root


def main_all():
    for k in ("GITHUB_ACTIONS", "GITHUB_STEP_SUMMARY", "SMTP_HOST", "SLACK_WEBHOOK_URL"):
        os.environ.pop(k, None)
    root = build_repo()
    base = git(root, "rev-parse", "HEAD")

    print("1) Full history scan finds a secret that was deleted from the code")
    code, out, _ = run_cli("scan-history", str(root), "--json", "--fail-on", "critical")
    data = json.loads(out)
    aws = [f for f in data["findings"] if f["rule_id"] == "aws-access-key-id"]
    check("deleted AWS key found in history", len(aws) == 1, data["findings"])
    check("marked as not in the current code", aws and aws[0]["still_present"] is False, aws)
    check("attributed to the introducing commit", aws and aws[0]["subject"] == "add deploy", aws)
    check("history finding fails the build (exit 1)", code == 1, code)
    check(".sentinelignore drops test fixtures",
          not any(f["file_path"].startswith("tests/") for f in data["findings"]), data["findings"])

    print("2) Current code is clean")
    code, out, _ = run_cli("scan-path", str(root), "--json")
    check("tree scan passes (exit 0)", code == 0, out)

    print("3) A pull request's commits only")
    git(root, "checkout", "-qb", "feature")
    (root / "db.py").write_text('URL = "postgres://app:Pr0dPassw0rd@db.internal:5432/app"\n')
    git(root, "add", "-A"); git(root, "commit", "-qm", "wire db")
    code, out, _ = run_cli("scan-history", str(root), "--range", f"{base}..HEAD", "--json")
    data = json.loads(out)
    rules = {f["rule_id"] for f in data["findings"]}
    check("range scan finds only the PR's secret", rules == {"db-url-with-credentials"}, rules)
    check("range scan walked 1 commit", data["commits_scanned"] == 1, data["commits_scanned"])
    check("PR secret fails the build", code == 1, code)
    code, out, _ = run_cli("scan-path", str(root), "--diff-base", base, "--json")
    check("tree diff scan also catches it", code == 1 and "db-url-with-credentials" in out, out[-300:])

    print("4) An all-zero range base (new branch) scans everything")
    code, out, _ = run_cli("scan-history", str(root), "--range", "0" * 40 + "..HEAD", "--json", "--fail-on", "none")
    check("zero base -> full history", json.loads(out)["range"] == "--all", json.loads(out)["range"])

    print("5) Baseline: accepted findings are reported but don't gate")
    bl = root / ".sentinel-baseline.json"
    code, _, err = run_cli("scan-history", str(root), "--fail-on", "none", "--write-baseline", str(bl))
    check("baseline written", bl.exists() and "fingerprint" in err, err)
    code, out, _ = run_cli("scan-history", str(root), "--json")
    data = json.loads(out)
    check("baselined findings pass the gate", code == 0, code)
    check("baselined findings still reported",
          data["findings"] and all(f["status"] == "baselined" for f in data["findings"]), data["findings"])
    (root / "more.env").write_text("STRIPE_KEY=sk_live_51QwErTyUiOpAsDfGhJk\n")
    git(root, "add", "-A"); git(root, "commit", "-qm", "oops")
    code, out, _ = run_cli("scan-history", str(root), "--json")
    new = [f for f in json.loads(out)["findings"] if f["status"] == "new"]
    check("a NEW secret still fails despite the baseline", code == 1 and [f["rule_id"] for f in new] == ["stripe-key"],
          new)

    print("6) Ignore by fingerprint and by rule")
    fp = new[0]["fingerprint"] if new else "x"
    (root / ".sentinelignore").write_text(f"tests/\nfingerprint:{fp}\n")
    code, out, _ = run_cli("scan-history", str(root), "--json")
    check("fingerprint entry suppresses one finding", code == 0, out[-300:])
    (root / ".sentinelignore").write_text("tests/\nrule:stripe-key\n")
    code, _, _ = run_cli("scan-path", str(root), "--baseline", str(bl))
    check("rule entry suppresses a rule", code == 0, code)
    (root / ".sentinelignore").write_text("tests/\n")

    print("7) SARIF output")
    sarif = root / "out.sarif"
    run_cli("scan-path", str(root), "--sarif", str(sarif), "--baseline", "/nonexistent", "--fail-on", "none")
    doc = json.loads(sarif.read_text())
    run = doc["runs"][0]
    check("SARIF 2.1.0", doc["version"] == "2.1.0")
    check("rules listed with security-severity",
          all("security-severity" in r["properties"] for r in run["tool"]["driver"]["rules"]))
    res = [r for r in run["results"] if r["ruleId"] == "stripe-key"]
    check("result has location + fingerprint",
          res and res[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "more.env"
          and "secretSentinel/v1" in res[0]["partialFingerprints"], res)
    check("SARIF never contains the raw secret", "sk_live_51QwErTyUiOpAsDfGhJk" not in sarif.read_text())
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    check("every result references a declared rule", all(r["ruleId"] in rule_ids for r in run["results"]))

    print("8) GitHub Actions annotations + job summary")
    summary = root / "summary.md"
    os.environ["GITHUB_ACTIONS"] = "true"
    os.environ["GITHUB_STEP_SUMMARY"] = str(summary)
    try:
        code, out, err = run_cli("scan-path", str(root), "--baseline", "/nonexistent")
    finally:
        os.environ.pop("GITHUB_ACTIONS"); os.environ.pop("GITHUB_STEP_SUMMARY")
    check("error annotation for a gating finding", "::error file=more.env,line=1," in err, err[:300])
    check("annotation is escaped (no raw newlines)", all("\n" not in l for l in err.splitlines()))
    md = summary.read_text() if summary.exists() else ""
    check("job summary written", "Secret scan" in md and "stripe-key" in md, md[:300])
    check("summary says the build failed", "failed" in md.lower(), md[:300])
    check("exit 1", code == 1, code)

    print("9) Inline suppression")
    (root / "more.env").write_text("STRIPE_KEY=sk_live_51QwErTyUiOpAsDfGhJk  # sentinel:ignore\n")
    _, out, _ = run_cli("scan-path", str(root), "--baseline", "/nonexistent", "--json")
    files = {f["file_path"] for f in json.loads(out)["findings"]}
    check("# sentinel:ignore suppresses the line", "more.env" not in files and "db.py" in files, files)

    print("10) Errors")
    code, _, err = run_cli("scan-history", tempfile.mkdtemp())
    check("non-git directory exits 2", code == 2, err)
    code, _, err = run_cli("scan-history", str(root), "--range", "nope..HEAD")
    check("bad range exits 2", code == 2, err)

    test_removal_only_ranges()

    print(f"\n{'ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'}")
    return 1 if FAILURES else 0


def test_removal_only_ranges():
    print("11) A push that only deletes a secret is not a new leak")
    root = Path(tempfile.mkdtemp()) / "cleanup"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.email", "dev@example.com")
    git(root, "config", "user.name", "Dev")
    (root / ".env").write_text("AWS_ACCESS_KEY_ID=AKIAQYLPMN5HHHFPZAM2\n")
    git(root, "add", "-A"); git(root, "commit", "-qm", "add env")
    leak = git(root, "rev-parse", "HEAD")
    git(root, "rm", "-q", ".env"); git(root, "commit", "-qm", "remove env")

    code, out, _ = run_cli("scan-history", str(root), "--range", f"{leak}..HEAD", "--json")
    data = json.loads(out)
    check("removal-only range passes (exit 0)", code == 0, data["findings"])
    check("removal-only range reports nothing", data["findings"] == [], data["findings"])

    code, out, _ = run_cli("scan-history", str(root), "--json", "--fail-on", "none")
    aws = [f for f in json.loads(out)["findings"] if f["rule_id"] == "aws-access-key-id"]
    check("full history still reports the deleted key", len(aws) == 1, aws)
    check("...attributed to the commit that added it, not the one that removed it",
          aws and aws[0]["subject"] == "add env", aws)

    # Added and removed inside the same range: still a leak (the push uploads both commits).
    (root / "k.py").write_text('TOKEN = "ghp_aB3xK9mQ7pL2wR5tY8uI3oP6aS1dF4gH7jK0"\n')
    git(root, "add", "-A"); git(root, "commit", "-qm", "add token")
    git(root, "rm", "-q", "k.py"); git(root, "commit", "-qm", "remove token")
    code, out, _ = run_cli("scan-history", str(root), "--range", "HEAD~2..HEAD", "--json")
    rules = {f["rule_id"] for f in json.loads(out)["findings"]}
    check("added-then-deleted within the range still fails", code == 1 and rules == {"github-token"}, rules)


if __name__ == "__main__":
    raise SystemExit(main_all())
