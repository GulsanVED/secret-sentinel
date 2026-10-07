#!/usr/bin/env python3
"""
Turn a Bandit JSON report into a Markdown job summary for GitHub Actions.

    bandit -r . -f json -o bandit-report.json --exit-zero
    python3 ci/bandit_summary.py bandit-report.json >> "$GITHUB_STEP_SUMMARY"

Lists every issue at medium-or-higher severity (the ones that fail the build)
and counts the rest. Stdlib only.
"""
import json
import sys

ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def main(path: str) -> int:
    try:
        with open(path, encoding="utf-8") as fh:
            results = json.load(fh).get("results", [])
    except (OSError, ValueError) as e:
        print(f"### ⚠️ Code vulnerabilities (Bandit)\n\nCould not read the report: {e}\n")
        return 0

    counts = {s: sum(1 for r in results if r["issue_severity"] == s) for s in ORDER}
    serious = sorted((r for r in results
                      if r["issue_severity"] in ("HIGH", "MEDIUM") and r["issue_confidence"] in ("HIGH", "MEDIUM")),
                     key=lambda r: (ORDER[r["issue_severity"]], r["filename"], r["line_number"]))
    icon = "❌" if serious else "✅"
    lines = [f"### {icon} Code vulnerabilities (Bandit)", "",
             f"high: **{counts['HIGH']}** · medium: **{counts['MEDIUM']}** · low: **{counts['LOW']}**", ""]
    if serious:
        lines += ["Build **failed**: issues at medium-or-higher severity and confidence.", "",
                  "| Severity | Confidence | Test | Location | Issue |", "|---|---|---|---|---|"]
        for r in serious[:50]:
            text = r["issue_text"].replace("|", "\\|")
            lines.append(f"| {r['issue_severity'].lower()} | {r['issue_confidence'].lower()} | "
                         f"`{r['test_id']}` | `{r['filename'].removeprefix('./')}:{r['line_number']}` | {text} |")
        if len(serious) > 50:
            lines.append(f"\n…and {len(serious) - 50} more in the `bandit-report.json` artifact.")
    else:
        lines.append("No issues at medium-or-higher severity and confidence. "
                     "Low-severity notes are in the `bandit-report.json` artifact.")
    print("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "bandit-report.json"))
