"""
What counts against the build: ignore rules and the baseline.

Two ways to stop a known finding from failing CI, both committed to the repo
so they are reviewed like any other change:

* `.sentinelignore` — one entry per line:
      tests/fixtures/          a directory (prefix match)
      *.md                     a glob on the repo-relative path (or file name)
      rule:high-entropy-string a rule, everywhere
      fingerprint:<fp>         one specific finding (the id every report prints)
  Lines starting with # are comments.

* A baseline (`.sentinel-baseline.json`, written with `--write-baseline`) —
  the fingerprints of findings that were already there when the gate was
  switched on. They are still reported, marked "baselined", but only NEW
  findings fail the build. Use it for secrets that were rotated but cannot be
  purged from history.

Inline `# sentinel:ignore` on the line itself is handled by the scanner.

Stdlib only.
"""
import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

DEFAULT_IGNORE_FILE = ".sentinelignore"
DEFAULT_BASELINE_FILE = ".sentinel-baseline.json"


@dataclass
class IgnoreRules:
    paths: List[str] = field(default_factory=list)
    rules: Set[str] = field(default_factory=set)
    fingerprints: Set[str] = field(default_factory=set)

    def matches(self, finding: Dict) -> bool:
        if finding.get("fingerprint") in self.fingerprints or finding.get("rule_id") in self.rules:
            return True
        path = finding.get("file_path") or ""
        name = path.rsplit("/", 1)[-1]
        for pat in self.paths:
            if pat.endswith("/"):
                if path.startswith(pat) or f"/{pat}" in f"/{path}":
                    return True
            elif fnmatch.fnmatchcase(path, pat) or ("/" not in pat and fnmatch.fnmatchcase(name, pat)):
                return True
        return False


def load_ignore(path: Optional[Path]) -> IgnoreRules:
    rules = IgnoreRules()
    if not path or not Path(path).is_file():
        return rules
    for raw in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("rule:"):
            rules.rules.add(line[5:].strip())
        elif line.startswith("fingerprint:"):
            rules.fingerprints.add(line[12:].strip())
        else:
            rules.paths.append(line.lstrip("/"))
    return rules


def load_baseline(path: Optional[Path]) -> Set[str]:
    if not path or not Path(path).is_file():
        return set()
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ValueError(f"baseline {path} is not valid JSON: {e}") from e
    return set((data.get("fingerprints") or {}).keys())


def write_baseline(path: Path, findings: Iterable[Dict]) -> int:
    """Record the given findings as accepted. Merges with an existing file so
    a tree scan and a history scan can share one baseline."""
    path = Path(path)
    existing: Dict[str, Dict] = {}
    if path.is_file():
        try:
            existing = json.loads(path.read_text(encoding="utf-8")).get("fingerprints") or {}
        except (OSError, ValueError):
            existing = {}
    for f in findings:
        existing[f["fingerprint"]] = {"rule_id": f["rule_id"], "file_path": f["file_path"],
                                      "severity": f["severity"]}
    path.write_text(json.dumps({"version": 1, "fingerprints": dict(sorted(existing.items()))},
                               indent=2) + "\n", encoding="utf-8")
    return len(existing)


def apply(findings: List[Dict], ignore: IgnoreRules, baseline: Set[str]) -> List[Dict]:
    """Drop ignored findings; tag the rest with status 'new' or 'baselined'."""
    out = []
    for f in findings:
        if ignore.matches(f):
            continue
        f["status"] = "baselined" if f.get("fingerprint") in baseline else "new"
        out.append(f)
    return out
