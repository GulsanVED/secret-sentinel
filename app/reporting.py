"""
Report formats for CI: SARIF (GitHub code scanning / any SARIF viewer),
GitHub Actions annotations, and a Markdown job summary.

Every function takes the normalised finding dicts built by `app.cli`:
    rule_id, description, severity, file_path, line_number, value_masked,
    fingerprint, status ('new' | 'baselined'), source ('tree' | 'history')
and, for history findings, commit / author / date / still_present.

Secret values are always the masked form. Stdlib only.
"""
from typing import Dict, List

from . import scanner

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
# GitHub code scanning maps security-severity to its critical/high/medium/low.
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def _message(f: Dict) -> str:
    msg = f"{f['description']} (value: {f['value_masked']})."
    if f.get("source") == "history":
        where = "still in the code" if f.get("still_present") else "deleted from the code but still in git history"
        msg += (f" Committed in {f.get('commit', '')[:10]} by {f.get('author') or 'unknown'}"
                f" on {(f.get('date') or '')[:10]}; {where}.")
    msg += " Rotate the credential, then remove it."
    return msg


def to_sarif(findings: List[Dict], tool_version: str = "2.0") -> Dict:
    rules = [{
        "id": r.id,
        "name": r.id.replace("-", " ").title().replace(" ", ""),
        "shortDescription": {"text": r.description},
        "fullDescription": {"text": f"{r.description}. Hard-coded credentials in source or history can be "
                                    f"extracted by anyone with read access to the repository."},
        "defaultConfiguration": {"level": _SARIF_LEVEL.get(r.severity, "warning")},
        "properties": {"tags": ["security", "secrets", "external/cwe/cwe-798"],
                       "security-severity": _SECURITY_SEVERITY.get(r.severity, "5.5"),
                       "precision": "high" if not r.generic else "medium"},
    } for r in scanner.active_rules()]

    results = []
    for f in findings:
        if f.get("status") == "baselined":
            continue
        results.append({
            "ruleId": f["rule_id"],
            "level": _SARIF_LEVEL.get(f["severity"], "warning"),
            "message": {"text": _message(f)},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f["file_path"], "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": max(int(f.get("line_number") or 1), 1)},
            }}],
            "partialFingerprints": {"secretSentinel/v1": f["fingerprint"]},
            "properties": {"severity": f["severity"], "source": f.get("source", "tree"),
                           **({"commit": f.get("commit")} if f.get("commit") else {})},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Secret Sentinel", "version": tool_version,
                                "rules": rules}},
            "results": results,
        }],
    }


def _esc_data(s: str) -> str:
    return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _esc_prop(s: str) -> str:
    return _esc_data(s).replace(":", "%3A").replace(",", "%2C")


def github_annotations(findings: List[Dict], fail_threshold: int) -> List[str]:
    """`::error file=..,line=..::msg` workflow commands. Findings that gate the
    build are errors; the rest are warnings (or notices when baselined)."""
    out = []
    for f in findings:
        if f.get("status") == "baselined":
            level = "notice"
        elif SEVERITY_ORDER.get(f["severity"], 0) >= fail_threshold:
            level = "error"
        else:
            level = "warning"
        title = f"Secret Sentinel [{f['severity'].upper()}]: {f['description']}"
        out.append(f"::{level} file={_esc_prop(f['file_path'])},line={max(int(f.get('line_number') or 1), 1)},"
                   f"title={_esc_prop(title)}::{_esc_data(_message(f))}")
    return out


def markdown_summary(title: str, findings: List[Dict], meta: Dict, gate_failed: bool, fail_on: str) -> str:
    new = [f for f in findings if f.get("status") != "baselined"]
    icon = "❌" if gate_failed else ("⚠️" if new else "✅")
    lines = [f"### {icon} {title}", ""]
    lines.append(" · ".join(f"{k}: **{v}**" for k, v in meta.items()))
    lines.append("")
    if not findings:
        lines.append("No secrets found.")
        return "\n".join(lines) + "\n"
    verdict = (f"Build **failed**: new findings at or above `{fail_on}`." if gate_failed
               else f"Gate passed (threshold `{fail_on}`).")
    lines += [verdict, ""]
    history = any(f.get("source") == "history" for f in findings)
    head = "| Severity | Rule | Location | Value | Status |" + (" Commit | In code now |" if history else "")
    lines += [head, "|" + "---|" * (7 if history else 5)]
    for f in sorted(findings, key=lambda f: -SEVERITY_ORDER.get(f["severity"], 0)):
        row = (f"| {f['severity']} | `{f['rule_id']}` | `{f['file_path']}:{f.get('line_number') or '-'}` "
               f"| `{f['value_masked']}` | {f.get('status', 'new')} |")
        if history:
            present = {True: "yes", False: "**no — history only**", None: "?"}[f.get("still_present")]
            row += f" `{(f.get('commit') or '')[:7]}` {f.get('author') or ''} | {present} |"
        lines.append(row)
    lines += ["", "Deleting a secret does not make it safe: it stays in git history, clones and forks. "
                  "**Rotate it.** To accept a known finding, add its fingerprint to `.sentinelignore` "
                  "or regenerate the baseline."]
    return "\n".join(lines) + "\n"
