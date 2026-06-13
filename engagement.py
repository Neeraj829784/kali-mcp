"""
Engagement model — named engagements that group scope, jobs, findings, and creds.
All tools check the active engagement and tag their results automatically.
"""
import json
import os
import sqlite3
from datetime import datetime, timezone

ENGAGEMENT_DB = os.path.join(os.path.dirname(__file__), "engagements.db")

# Module-level active engagement (in-memory, reset on restart)
_active: dict | None = None


def _conn():
    db = sqlite3.connect(ENGAGEMENT_DB, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=30000")
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS engagements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            client TEXT,
            status TEXT DEFAULT 'active',
            scope TEXT DEFAULT '[]',
            notes TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            ended_at TEXT
        );
        CREATE TABLE IF NOT EXISTS eng_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL,
            host TEXT,
            port INTEGER,
            service TEXT,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            evidence TEXT,
            tool TEXT,
            job_id TEXT,
            added_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'unconfirmed',
            FOREIGN KEY(engagement_id) REFERENCES engagements(id)
        );
    """)
    # Migrate: add status column for existing DBs
    try:
        db.execute("ALTER TABLE eng_findings ADD COLUMN status TEXT NOT NULL DEFAULT 'unconfirmed'")
    except Exception:
        pass  # column already exists
    db.commit()
    return db


def get_active() -> dict | None:
    return _active


def tag_finding(finding: dict, job_id: str = "") -> None:
    """Auto-tag a finding to the active engagement if one is set."""
    if not _active:
        return
    now = datetime.now(timezone.utc).isoformat()
    with _conn() as db:
        db.execute(
            "INSERT INTO eng_findings (engagement_id,host,port,service,title,severity,evidence,tool,job_id,added_at,status) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (_active["id"], finding.get("host",""), finding.get("port"),
             finding.get("service",""), finding.get("title",""),
             finding.get("severity","info"), finding.get("evidence","")[:500],
             finding.get("tool",""), job_id, now, "unconfirmed")
        )


def _register(mcp, job_mgr):

    @mcp.tool()
    async def engagement_start(
        name: str,
        scope: list[str],
        client: str = "",
        notes: str = "",
    ) -> dict:
        """
        Start a new engagement. Sets scope for all tools automatically.
        All subsequent findings, jobs, and credentials are tagged to this engagement.
        name: engagement name e.g. 'ClientName-WebApp-2026'
        scope: list of authorized targets e.g. ['192.168.1.0/24', 'example.com']
        client: optional client name for reporting
        notes: engagement notes / rules of engagement
        """
        global _active
        from scope import set_scope
        set_scope(scope)

        now = datetime.now(timezone.utc).isoformat()
        with _conn() as db:
            # INSERT OR IGNORE preserves existing id (and its findings); UPDATE refreshes fields
            db.execute(
                "INSERT OR IGNORE INTO engagements (name,client,status,scope,notes,created_at) VALUES (?,?,?,?,?,?)",
                (name, client, "active", json.dumps(scope), notes, now)
            )
            db.execute(
                "UPDATE engagements SET client=?,status='active',scope=?,notes=?,ended_at=NULL WHERE name=?",
                (client, json.dumps(scope), notes, name)
            )
            eng_id = db.execute("SELECT id FROM engagements WHERE name=?", (name,)).fetchone()[0]

        _active = {"id": eng_id, "name": name, "scope": scope, "client": client}
        return {
            "engagement": name,
            "status": "started",
            "scope": scope,
            "id": eng_id,
            "note": "Scope set automatically. All tools will check against this scope."
        }

    @mcp.tool()
    async def engagement_status() -> dict:
        """Show the current active engagement and its findings summary."""
        if not _active:
            return {"active": False, "hint": "Start one with engagement_start()"}
        with _conn() as db:
            eng = dict(db.execute("SELECT * FROM engagements WHERE id=?", (_active["id"],)).fetchone())
            findings = db.execute(
                "SELECT severity, COUNT(*) as cnt FROM eng_findings WHERE engagement_id=? GROUP BY severity",
                (_active["id"],)
            ).fetchall()
            jobs_count = db.execute(
                "SELECT COUNT(*) FROM eng_findings WHERE engagement_id=?", (_active["id"],)
            ).fetchone()[0]
        by_severity = {row["severity"]: row["cnt"] for row in findings}
        return {
            "active": True,
            "name": eng["name"],
            "client": eng["client"],
            "scope": json.loads(eng["scope"]),
            "status": eng["status"],
            "created_at": eng["created_at"],
            "findings_total": jobs_count,
            "findings_by_severity": by_severity,
        }

    @mcp.tool()
    async def engagement_findings(
        min_severity: str = "info",
        host: str = "",
        limit: int = 100,
    ) -> dict:
        """
        Get all findings for the current engagement.
        min_severity: info, low, medium, high, critical
        host: filter by specific host
        limit: max results
        """
        if not _active:
            return {"error": "No active engagement. Run engagement_start() first."}
        sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        min_rank = sev_rank.get(min_severity.lower(), 0)
        query = "SELECT * FROM eng_findings WHERE engagement_id=?"
        params: list = [_active["id"]]
        if host:
            query += " AND host=?"
            params.append(host)
        query += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, added_at DESC LIMIT ?"
        params.append(limit)
        with _conn() as db:
            rows = db.execute(query, params).fetchall()
        all_findings = [dict(r) for r in rows]
        filtered = [f for f in all_findings if sev_rank.get(f["severity"], 0) >= min_rank]
        return {"engagement": _active["name"], "total": len(filtered), "findings": filtered}

    @mcp.tool()
    async def engagement_end() -> dict:
        """Close the current engagement and clear scope restrictions."""
        global _active
        if not _active:
            return {"error": "No active engagement"}
        from scope import clear_scope
        now = datetime.now(timezone.utc).isoformat()
        with _conn() as db:
            db.execute("UPDATE engagements SET status='ended', ended_at=? WHERE id=?",
                       (now, _active["id"]))
        name = _active["name"]
        _active = None
        clear_scope()
        return {"engagement": name, "status": "ended", "scope": "cleared (lab mode)"}

    @mcp.tool()
    async def engagement_list() -> list:
        """List all engagements (past and active)."""
        with _conn() as db:
            rows = db.execute(
                "SELECT e.*, COUNT(f.id) as finding_count FROM engagements e "
                "LEFT JOIN eng_findings f ON f.engagement_id=e.id "
                "GROUP BY e.id ORDER BY e.created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    @mcp.tool()
    async def list_unconfirmed_findings(host: str = "", min_severity: str = "low") -> dict:
        """List findings pending validation for the current engagement.

        Returns unconfirmed findings ordered by severity so a validation agent
        can work through them one by one and call update_finding_status on each.
        host: filter by specific host (empty = all)
        min_severity: info, low, medium, high, critical
        """
        if not _active:
            return {"error": "No active engagement. Run engagement_start() first."}
        sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        min_rank = sev_rank.get(min_severity.lower(), 0)
        query = ("SELECT * FROM eng_findings WHERE engagement_id=? AND status='unconfirmed'")
        params: list = [_active["id"]]
        if host:
            query += " AND host=?"
            params.append(host)
        query += (" ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
                  "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, added_at DESC")
        with _conn() as db:
            rows = db.execute(query, params).fetchall()
        findings = [dict(r) for r in rows
                    if sev_rank.get(dict(r).get("severity", "info"), 0) >= min_rank]
        return {
            "engagement": _active["name"],
            "unconfirmed_count": len(findings),
            "findings": findings,
            "hint": "Call update_finding_status(finding_id, 'confirmed'|'false_positive') for each.",
        }

    @mcp.tool()
    async def update_finding_status(finding_id: int, status: str) -> dict:
        """Update the validation status of a finding.

        Called by a validation agent after manually verifying a finding.
        finding_id: the finding's id (from list_unconfirmed_findings)
        status: 'confirmed' — finding is real and exploitable
                'false_positive' — finding is not real, exclude from report
                'unconfirmed' — reset back to pending (if re-verification needed)
        """
        valid = {"confirmed", "false_positive", "unconfirmed"}
        if status not in valid:
            return {"error": f"Invalid status '{status}'. Must be one of: {valid}"}
        if not _active:
            return {"error": "No active engagement. Run engagement_start() first."}
        with _conn() as db:
            cur = db.execute(
                "UPDATE eng_findings SET status=? WHERE id=? AND engagement_id=?",
                (status, finding_id, _active["id"])
            )
        if cur.rowcount == 0:
            return {"error": f"Finding {finding_id} not found in active engagement.", "updated": False}
        return {"finding_id": finding_id, "status": status, "updated": True}
