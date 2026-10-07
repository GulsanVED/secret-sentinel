#!/usr/bin/env python3
"""
Standalone CI entrypoint. Works from any directory and needs only Python 3.9+
(no pip install), so a CI job can do:

    git clone --depth 1 https://github.com/<you>/secret-sentinel /tmp/sentinel
    python3 /tmp/sentinel/ci_scan.py "$PWD" --email --fail-on high

All `python -m app.cli scan-path` options are accepted. See README section
"Real-time alerts".
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.cli import main  # noqa: E402

if __name__ == "__main__":
    argv = sys.argv[1:]
    if not argv or argv[0].startswith("-"):
        argv = ["scan-path", *argv] if argv and argv[0].startswith("-") else ["scan-path", "."]
    elif argv[0] not in ("scan-path", "scan-history", "scan-staged", "scan-repo", "test-email"):
        argv = ["scan-path", *argv]
    sys.exit(main(argv))
