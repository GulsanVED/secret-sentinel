"""
Tiny SQLite persistence layer. No ORM — this project is meant to be readable
top to bottom and easy to swap for Postgres later if needed.
"""
import sqlite3
import time
from pathlib import Path
from typing import Optional, List, Dict, Any

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "sentinel.db"
DB_PATH.parent.mkdir(exist_ok=True)


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db() -> None:
    conn = get_conn()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS repos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE NOT NULL,
            owner TEXT NOT NULL,
            name TEXT NOT NULL,
            branch TEXT,
            last_commit_sha TEXT,
            last_scanned_at REAL,
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_id INTEGER NOT NULL,
            fingerprint TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            file_path TEXT NOT NULL,
            line_number INTEGER,
            matched_text TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',   -- active | removed
            first_seen_at REAL NOT NULL,
            last_seen_at REAL NOT NULL,
            removed_at REAL,
            commit_sha TEXT,
            UNIQUE(repo_id, fingerprint),
            FOREIGN KEY(repo_id) REFERENCES repos(id)
        );

        CREATE TABLE IF NOT EXISTS history_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_id INTEGER NOT NULL,
            fingerprint TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            file_path TEXT NOT NULL,
            line_number INTEGER,
            matched_text TEXT NOT NULL,
            still_present INTEGER,              -- 1 in current code, 0 history only, NULL unknown
            occurrences INTEGER NOT NULL DEFAULT 1,
            first_commit_sha TEXT,
            first_commit_date TEXT,
            first_author_name TEXT,
            first_commit_subject TEXT,
            last_commit_sha TEXT,
            last_commit_date TEXT,
            removed_commit_sha TEXT,
            removed_commit_date TEXT,
            commits_json TEXT,
            first_seen_at REAL NOT NULL,
            updated_at REAL NOT NULL,
            UNIQUE(repo_id, fingerprint),
            FOREIGN KEY(repo_id) REFERENCES repos(id)
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_id INTEGER NOT NULL,
            finding_id INTEGER,
            kind TEXT NOT NULL,       -- new_secret | secret_removed
            message TEXT NOT NULL,
            created_at REAL NOT NULL,
            delivered INTEGER NOT NULL DEFAULT 0
        );

        -- Secret scan runs read back from GitHub Actions ("CI runs" tab).
        CREATE TABLE IF NOT EXISTS ci_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_id INTEGER NOT NULL,
            run_id INTEGER NOT NULL,
            run_number INTEGER,
            event TEXT,
            branch TEXT,
            pr_number INTEGER,
            head_sha TEXT,
            title TEXT,
            actor TEXT,
            commit_author TEXT,
            run_status TEXT,          -- queued | in_progress | completed
            conclusion TEXT,          -- GitHub's: success | failure | cancelled ...
            gate TEXT NOT NULL,       -- passed | blocked | error | running | failed | cancelled
            scope TEXT,
            fail_on TEXT,
            findings_json TEXT,
            gating_count INTEGER,
            total_count INTEGER,
            has_result INTEGER NOT NULL DEFAULT 0,
            html_url TEXT,
            run_created_at TEXT,
            updated_at REAL NOT NULL,
            UNIQUE(repo_id, run_id),
            FOREIGN KEY(repo_id) REFERENCES repos(id)
        );
        """
    )
    # Lightweight migrations for databases created by earlier versions.
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(repos)").fetchall()}
    if "last_error" not in cols:
        conn.execute("ALTER TABLE repos ADD COLUMN last_error TEXT")
    if "last_scan_summary" not in cols:
        conn.execute("ALTER TABLE repos ADD COLUMN last_scan_summary TEXT")
    for col, decl in (("history_state", "TEXT"), ("history_summary", "TEXT"),
                      ("history_scanned_at", "REAL"), ("history_error", "TEXT"),
                      ("ci_synced_at", "REAL"), ("ci_error", "TEXT")):
        if col not in cols:
            conn.execute(f"ALTER TABLE repos ADD COLUMN {col} {decl}")
    conn.commit()
    conn.close()


def upsert_repo(url: str, owner: str, name: str, branch: Optional[str]) -> int:
    conn = get_conn()
    cur = conn.execute("SELECT id FROM repos WHERE url = ?", (url,))
    row = cur.fetchone()
    if row:
        repo_id = row["id"]
        if branch:
            conn.execute("UPDATE repos SET branch = ? WHERE id = ?", (branch, repo_id))
    else:
        cur = conn.execute(
            "INSERT INTO repos (url, owner, name, branch, created_at) VALUES (?, ?, ?, ?, ?)",
            (url, owner, name, branch, time.time()),
        )
        repo_id = cur.lastrowid
    conn.commit()
    conn.close()
    return repo_id


def list_repos() -> List[Dict[str, Any]]:
    conn = get_conn()
    rows = conn.execute("SELECT * FROM repos ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_repo(repo_id: int) -> Optional[Dict[str, Any]]:
    conn = get_conn()
    row = conn.execute("SELECT * FROM repos WHERE id = ?", (repo_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_repo_scan_state(repo_id: int, last_commit_sha: Optional[str], summary: Optional[str] = None) -> None:
    conn = get_conn()
    conn.execute(
        "UPDATE repos SET last_commit_sha = ?, last_scanned_at = ?, last_error = NULL, "
        "last_scan_summary = COALESCE(?, last_scan_summary) WHERE id = ?",
        (last_commit_sha, time.time(), summary, repo_id),
    )
    conn.commit()
    conn.close()


def set_repo_error(repo_id: int, error: Optional[str]) -> None:
    conn = get_conn()
    conn.execute("UPDATE repos SET last_error = ? WHERE id = ?", (error, repo_id))
    conn.commit()
    conn.close()


def delete_repo(repo_id: int) -> None:
    conn = get_conn()
    conn.execute("DELETE FROM alerts WHERE repo_id = ?", (repo_id,))
    conn.execute("DELETE FROM ci_runs WHERE repo_id = ?", (repo_id,))
    conn.execute("DELETE FROM history_findings WHERE repo_id = ?", (repo_id,))
    conn.execute("DELETE FROM findings WHERE repo_id = ?", (repo_id,))
    conn.execute("DELETE FROM repos WHERE id = ?", (repo_id,))
    conn.commit()
    conn.close()


def get_finding(finding_id: int) -> Optional[Dict[str, Any]]:
    conn = get_conn()
    row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_active_findings(repo_id: int) -> List[Dict[str, Any]]:
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM findings WHERE repo_id = ? AND status = 'active'", (repo_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_active_fingerprints(repo_id: int) -> Dict[str, int]:
    """fingerprint -> finding id, for findings currently marked active."""
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, fingerprint FROM findings WHERE repo_id = ? AND status = 'active'",
        (repo_id,),
    ).fetchall()
    conn.close()
    return {r["fingerprint"]: r["id"] for r in rows}


def upsert_finding(repo_id: int, f, commit_sha: Optional[str]) -> tuple:
    """Insert a new finding or refresh an existing one.
    Returns (finding_id, state) where state is 'new', 'reactivated' (was removed,
    came back) or 'existing'."""
    conn = get_conn()
    now = time.time()
    row = conn.execute(
        "SELECT id, status FROM findings WHERE repo_id = ? AND fingerprint = ?",
        (repo_id, f.fingerprint),
    ).fetchone()
    if row:
        state = "reactivated" if row["status"] == "removed" else "existing"
        conn.execute(
            "UPDATE findings SET last_seen_at = ?, status = 'active', removed_at = NULL, "
            "line_number = ?, commit_sha = COALESCE(?, commit_sha) WHERE id = ?",
            (now, f.line_number, commit_sha, row["id"]),
        )
        conn.commit()
        conn.close()
        return row["id"], state
    cur = conn.execute(
        """INSERT INTO findings
           (repo_id, fingerprint, rule_id, description, severity, file_path,
            line_number, matched_text, status, first_seen_at, last_seen_at, commit_sha)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)""",
        (repo_id, f.fingerprint, f.rule_id, f.description, f.severity, f.file_path,
         f.line_number, f.matched_text, now, now, commit_sha),
    )
    conn.commit()
    finding_id = cur.lastrowid
    conn.close()
    return finding_id, "new"


def mark_removed(finding_id: int) -> None:
    conn = get_conn()
    conn.execute(
        "UPDATE findings SET status = 'removed', removed_at = ? WHERE id = ?",
        (time.time(), finding_id),
    )
    conn.commit()
    conn.close()


def list_findings(repo_id: Optional[int] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_conn()
    query = "SELECT findings.*, repos.url as repo_url FROM findings JOIN repos ON repos.id = findings.repo_id WHERE 1=1"
    params: List[Any] = []
    if repo_id is not None:
        query += " AND findings.repo_id = ?"
        params.append(repo_id)
    if status is not None:
        query += " AND findings.status = ?"
        params.append(status)
    query += " ORDER BY findings.last_seen_at DESC"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def record_alert(repo_id: int, finding_id: Optional[int], kind: str, message: str) -> int:
    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO alerts (repo_id, finding_id, kind, message, created_at, delivered) VALUES (?, ?, ?, ?, ?, 1)",
        (repo_id, finding_id, kind, message, time.time()),
    )
    conn.commit()
    alert_id = cur.lastrowid
    conn.close()
    return alert_id


def list_alerts(repo_id: Optional[int] = None, limit: int = 100) -> List[Dict[str, Any]]:
    conn = get_conn()
    query = "SELECT * FROM alerts WHERE 1=1"
    params: List[Any] = []
    if repo_id is not None:
        query += " AND repo_id = ?"
        params.append(repo_id)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# --------------------------------------------------------------------------
# Git-history findings
# --------------------------------------------------------------------------

def set_repo_history_state(repo_id: int, state: str, summary: Optional[str] = None,
                           error: Optional[str] = None) -> None:
    conn = get_conn()
    conn.execute(
        "UPDATE repos SET history_state = ?, history_summary = COALESCE(?, history_summary), "
        "history_error = ?, history_scanned_at = CASE WHEN ? = 'done' THEN ? ELSE history_scanned_at END "
        "WHERE id = ?",
        (state, summary, error, state, time.time(), repo_id),
    )
    conn.commit()
    conn.close()


def upsert_history_finding(repo_id: int, rec: Dict[str, Any], commits_json: str) -> bool:
    """Insert or refresh one aggregated history finding. Returns True if it is new."""
    conn = get_conn()
    now = time.time()
    row = conn.execute("SELECT id FROM history_findings WHERE repo_id = ? AND fingerprint = ?",
                       (repo_id, rec["fingerprint"])).fetchone()
    values = (
        rec["rule_id"], rec["description"], rec["severity"], rec["file_path"], rec.get("line_number"),
        rec["matched_text"],
        None if rec.get("still_present") is None else int(bool(rec["still_present"])),
        rec.get("occurrences", 1), rec.get("first_commit_sha"), rec.get("first_commit_date"),
        rec.get("first_author_name"), rec.get("first_commit_subject"), rec.get("last_commit_sha"),
        rec.get("last_commit_date"), rec.get("removed_commit_sha"), rec.get("removed_commit_date"),
        commits_json, now,
    )
    if row:
        conn.execute(
            """UPDATE history_findings SET rule_id=?, description=?, severity=?, file_path=?,
               line_number=?, matched_text=?, still_present=?, occurrences=?, first_commit_sha=?,
               first_commit_date=?, first_author_name=?, first_commit_subject=?, last_commit_sha=?,
               last_commit_date=?, removed_commit_sha=?, removed_commit_date=?, commits_json=?,
               updated_at=? WHERE id=?""", (*values, row["id"]))
        is_new = False
    else:
        conn.execute(
            """INSERT INTO history_findings
               (repo_id, fingerprint, rule_id, description, severity, file_path, line_number,
                matched_text, still_present, occurrences, first_commit_sha, first_commit_date,
                first_author_name, first_commit_subject, last_commit_sha, last_commit_date,
                removed_commit_sha, removed_commit_date, commits_json, updated_at, first_seen_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (repo_id, rec["fingerprint"], *values, now))
        is_new = True
    conn.commit()
    conn.close()
    return is_new


def list_history_findings(repo_id: Optional[int] = None, presence: Optional[str] = None) -> List[Dict[str, Any]]:
    """presence: 'present' (still in code), 'history_only' (deleted), or None for all."""
    conn = get_conn()
    q = ("SELECT history_findings.*, repos.url AS repo_url, repos.owner, repos.name "
         "FROM history_findings JOIN repos ON repos.id = history_findings.repo_id WHERE 1=1")
    params: List[Any] = []
    if repo_id is not None:
        q += " AND history_findings.repo_id = ?"
        params.append(repo_id)
    if presence == "present":
        q += " AND history_findings.still_present = 1"
    elif presence == "history_only":
        q += " AND (history_findings.still_present = 0 OR history_findings.still_present IS NULL)"
    q += (" ORDER BY CASE history_findings.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
          "WHEN 'medium' THEN 2 ELSE 3 END, history_findings.first_commit_date DESC")
    rows = conn.execute(q, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def history_stats(repo_id: Optional[int] = None) -> Dict[str, int]:
    conn = get_conn()
    row = conn.execute(
        """SELECT COUNT(*) AS total,
                  SUM(CASE WHEN still_present = 1 THEN 1 ELSE 0 END) AS present,
                  SUM(CASE WHEN still_present = 0 THEN 1 ELSE 0 END) AS history_only,
                  SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical
           FROM history_findings WHERE (? IS NULL OR repo_id = ?)""", (repo_id, repo_id)).fetchone()
    conn.close()
    return {k: (row[k] or 0) for k in ("total", "present", "history_only", "critical")}


# ---------------------------------------------------------------------------
# CI runs (GitHub Actions results, read back by pipeline.sync_ci_runs)
# ---------------------------------------------------------------------------

_CI_COLS = ("run_number", "event", "branch", "pr_number", "head_sha", "title", "actor", "commit_author",
            "run_status", "conclusion", "gate", "scope", "fail_on", "findings_json", "gating_count",
            "total_count", "has_result", "html_url", "run_created_at")
# Spelled out (not built from _CI_COLS at run time) so the queries are constant.
_CI_UPDATE = (
    "UPDATE ci_runs SET run_number = ?, event = ?, branch = ?, pr_number = ?, head_sha = ?, "
    "title = ?, actor = ?, commit_author = ?, run_status = ?, conclusion = ?, gate = ?, scope "
    "= ?, fail_on = ?, findings_json = ?, gating_count = ?, total_count = ?, has_result = ?, "
    "html_url = ?, run_created_at = ?, updated_at = ? WHERE id = ?"
)
_CI_INSERT = (
    "INSERT INTO ci_runs (repo_id, run_id, run_number, event, branch, pr_number, head_sha, "
    "title, actor, commit_author, run_status, conclusion, gate, scope, fail_on, "
    "findings_json, gating_count, total_count, has_result, html_url, run_created_at, "
    "updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


def get_ci_run(repo_id: int, run_id: int) -> Optional[Dict[str, Any]]:
    conn = get_conn()
    row = conn.execute("SELECT * FROM ci_runs WHERE repo_id = ? AND run_id = ?", (repo_id, run_id)).fetchone()
    conn.close()
    return dict(row) if row else None


def upsert_ci_run(repo_id: int, run_id: int, rec: Dict[str, Any]) -> None:
    conn = get_conn()
    values = [int(bool(rec.get(c))) if c == "has_result" else rec.get(c) for c in _CI_COLS]
    exists = conn.execute("SELECT id FROM ci_runs WHERE repo_id = ? AND run_id = ?",
                          (repo_id, run_id)).fetchone()
    if exists:
        conn.execute(_CI_UPDATE, (*values, time.time(), exists["id"]))
    else:
        conn.execute(_CI_INSERT, (repo_id, run_id, *values, time.time()))
    conn.commit()
    conn.close()


def list_ci_runs(repo_id: Optional[int] = None, limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_conn()
    rows = conn.execute(
        "SELECT ci_runs.*, repos.owner, repos.name FROM ci_runs JOIN repos ON repos.id = ci_runs.repo_id "
        "WHERE (? IS NULL OR ci_runs.repo_id = ?) ORDER BY ci_runs.run_created_at DESC, ci_runs.run_id DESC "
        "LIMIT ?", (repo_id, repo_id, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def set_repo_ci_state(repo_id: int, error: Optional[str]) -> None:
    conn = get_conn()
    conn.execute("UPDATE repos SET ci_synced_at = ?, ci_error = ? WHERE id = ?", (time.time(), error, repo_id))
    conn.commit()
    conn.close()
