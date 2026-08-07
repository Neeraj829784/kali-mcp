"""
Persistent asset inventory — tracks hosts, services, and findings across scans.

The asset inventory is a living database of discovered targets, open ports,
service versions, and high-level vulnerability status. It's auto-populated
from findings as scans complete.

Key features:
  - Hosts: discovered IPs/domains, first/last seen, scan count, status
  - Services: host:port → service name/version, open/closed/filtered
  - Vulnerabilities: CVE IDs, severity, confidence, remediation status
  - Status: 'new', 'scanned', 'confirmed', 'remediated', 'false_positive'

Unlike the engagement model (which is per-test-session), this is persistent
and project-wide — you can query "what do we know about 10.10.10.5?" even
across different engagements.
"""
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import aiosqlite

from config import PROGRAMS_DB_PATH

_SCHEMA = """
    CREATE TABLE IF NOT EXISTS hosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        hostname TEXT,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        scan_count INTEGER DEFAULT 0,
        status TEXT DEFAULT 'new',
        metadata TEXT DEFAULT '{}',
        UNIQUE(ip, hostname)
    );
    CREATE TABLE IF NOT EXISTS services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER NOT NULL,
        port INTEGER NOT NULL,
        protocol TEXT DEFAULT 'tcp',
        service TEXT,
        version TEXT,
        state TEXT DEFAULT 'open',
        banner TEXT,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        UNIQUE(host_id, port, protocol)
    );
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER NOT NULL,
        service_id INTEGER,
        cve_id TEXT,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence TEXT NOT NULL,
        remediation TEXT,
        status TEXT DEFAULT 'unconfirmed',
        first_found TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        findings_data TEXT,
        FOREIGN KEY(host_id) REFERENCES hosts(id),
        FOREIGN KEY(service_id) REFERENCES services(id)
    );
    CREATE TABLE IF NOT EXISTS app_state (
        key TEXT PRIMARY KEY,
        value TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);
    CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);
    CREATE INDEX IF NOT EXISTS idx_vulns_host ON vulnerabilities(host_id);
    CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulnerabilities(cve_id);
"""


@asynccontextmanager
async def _get_db():
    async with aiosqlite.connect(PROGRAMS_DB_PATH, timeout=30) as db:
        db.row_factory = aiosqlite.Row
        try:
            yield db
        finally:
            await db.close()


async def init_db() -> None:
    """Create tables. Called once at server startup."""
    async with _get_db() as db:
        await db.executescript(_SCHEMA)
        await db.commit()


async def _ensure_host_exists(db, ip: str | None, hostname: str | None) -> int:
    """Insert or find a host, return its id."""
    if not ip and not hostname:
        raise ValueError("At least one of ip or hostname must be provided")
    # Store empty string (not NULL) for the missing field so the UNIQUE(ip,
    # hostname) constraint actually dedupes — SQLite treats NULLs as distinct.
    ip = ip or ""
    hostname = hostname or ""
    sql = """
        INSERT INTO hosts (ip, hostname, first_seen, last_seen, scan_count, status)
        VALUES (?, ?, ?, ?, 1, 'new')
        ON CONFLICT(ip, hostname) DO UPDATE SET
            last_seen=excluded.last_seen,
            scan_count=hosts.scan_count + 1
        RETURNING id
    """
    now = datetime.now(timezone.utc).isoformat()
    cur = await db.execute(sql, (ip, hostname, now, now))
    row = await cur.fetchone()
    return row[0]


async def _ensure_service_exists(db, host_id: int, port: int, protocol: str = "tcp",
                                 service: str | None = None, version: str | None = None,
                                 banner: str | None = None) -> int | None:
    """Insert or update a service, return its id."""
    sql = """
        INSERT INTO services (host_id, port, protocol, service, version, state, banner,
                              first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?)
        ON CONFLICT(host_id, port, protocol) DO UPDATE SET
            service=COALESCE(excluded.service, services.service),
            version=COALESCE(excluded.version, services.version),
            banner=COALESCE(excluded.banner, services.banner),
            last_seen=excluded.last_seen,
            state='open'
        RETURNING id
    """
    now = datetime.now(timezone.utc).isoformat()
    cur = await db.execute(sql, (host_id, port, protocol, service, version, banner, now, now))
    row = await cur.fetchone()
    return row[0] if row else None


async def _upsert_vulnerability(db, host_id: int, service_id: int | None,
                                 cve_id: str | None, title: str, severity: str,
                                 confidence: str, remediation: str | None,
                                 findings_data: dict) -> int:
    """Insert or update a vulnerability.

    Dedupe key is (host_id, title, cve_id-or-empty). Done with an explicit
    SELECT-then-INSERT/UPDATE rather than ON CONFLICT because cve_id is often
    NULL (most findings have no CVE) and SQLite treats NULLs as distinct in a
    UNIQUE constraint, which would defeat deduplication.
    """
    now = datetime.now(timezone.utc).isoformat()
    cur = await db.execute(
        "SELECT id FROM vulnerabilities "
        "WHERE host_id=? AND title=? AND IFNULL(cve_id,'')=IFNULL(?,'')",
        (host_id, title, cve_id),
    )
    row = await cur.fetchone()
    if row:
        vuln_id = row[0]
        await db.execute(
            "UPDATE vulnerabilities SET severity=?, confidence=?, "
            "remediation=COALESCE(?, remediation), "
            "service_id=COALESCE(?, service_id), "
            "last_seen=?, findings_data=? WHERE id=?",
            (severity, confidence, remediation, service_id, now,
             json.dumps(findings_data), vuln_id),
        )
        return vuln_id
    cur = await db.execute(
        "INSERT INTO vulnerabilities (host_id, service_id, cve_id, title, severity, "
        "confidence, remediation, status, first_found, last_seen, findings_data) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 'unconfirmed', ?, ?, ?) RETURNING id",
        (host_id, service_id, cve_id, title, severity, confidence, remediation,
         now, now, json.dumps(findings_data)),
    )
    row = await cur.fetchone()
    return row[0]


async def ingest_finding(f: dict) -> dict:
    """
    Ingest a finding into the asset inventory.
    Creates/updates host, service, and vulnerability records as needed.
    Returns a summary dict with created/updated ids.
    """
    host_ip = f.get("host", "")
    port = f.get("port", 0)
    service = f.get("service", "")
    title = f.get("title", "Unknown finding")
    severity = f.get("severity", "info")
    confidence = f.get("confidence", "medium")
    cve_id = None
    evidence = f.get("evidence", "")
    if "cve" in evidence.lower() or "cve" in title.lower():
        import re
        m = re.search(r"CVE-\d{4}-\d{4,}", evidence + " " + title, re.IGNORECASE)
        if m:
            cve_id = m.group(0).upper()

    if not host_ip:
        return {"error": "Finding missing host", "finding": f}

    async with _get_db() as db:
        host_id = await _ensure_host_exists(db, host_ip, None)
        service_id = None
        if port:
            service_id = await _ensure_service_exists(db, host_id, port, "tcp", service, None)
        vuln_id = None
        if title:
            remediation = _get_remediation_from_title(title)
            vuln_id = await _upsert_vulnerability(db, host_id, service_id, cve_id, title, severity,
                                                  confidence, remediation, f)
        await db.commit()

    return {"host_id": host_id, "service_id": service_id, "vuln_id": vuln_id,
            "host_ip": host_ip, "port": port, "severity": severity}


def _get_remediation_from_title(title: str) -> str | None:
    """Fallback remediation based on title keywords."""
    t = title.lower()
    if "sql injection" in t or "sqli" in t:
        return "Use parameterized queries / ORM"
    if "credential" in t or "password" in t:
        return "Rotate credentials immediately"
    if "xss" in t:
        return "Encode output + CSP header"
    if "eternalblue" in t or "ms17-010" in t:
        return "Apply MS17-010 patch"
    if "smb" in t:
        return "Disable SMBv1 + require signing"
    if "suid" in t or "privilege escalation" in t:
        return "Audit SUID binaries + sudo rules"
    return None


def _extract_host_port(f: dict) -> tuple[str | None, int | None, str | None]:
    """Extract (ip, port, hostname) from a finding."""
    host = f.get("host", "")
    port = f.get("port", 0)
    service = f.get("service", "")
    return host, port, service


def _extract_title_severity(f: dict) -> tuple[str, str, str, str | None]:
    """Extract title, severity, confidence, and optional CVE from a finding."""
    title = f.get("title", "Unknown finding")
    severity = f.get("severity", "info")
    confidence = f.get("confidence", "medium")
    cve_id = None
    evidence = f.get("evidence", "")
    if "cve" in evidence.lower() or "cve" in title.lower():
        import re
        m = re.search(r"CVE-\d{4}-\d{4,}", evidence + " " + title, re.IGNORECASE)
        if m:
            cve_id = m.group(0).upper()
    return title, severity, confidence, cve_id


def _register(mcp, job_mgr):

    @mcp.tool()
    async def asset_list_hosts(
        status: str = "",
        min_scan_count: int = 0,
        limit: int = 100,
    ) -> dict:
        """
        List all known hosts.
        status: filter by status (new, scanned, confirmed, remediated, false_positive)
        min_scan_count: minimum number of scans
        limit: max results
        """
        query = "SELECT * FROM hosts WHERE scan_count >= ?"
        params: list = [min_scan_count]
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)
        async with _get_db() as db:
            async with db.execute(query, params) as cur:
                rows = await cur.fetchall()
        hosts = [dict(r) for r in rows]
        return {"total": len(hosts), "hosts": hosts}

    @mcp.tool()
    async def asset_get_host(host_ip: str) -> dict:
        """Get full details for a specific host."""
        async with _get_db() as db:
            async with db.execute("SELECT * FROM hosts WHERE ip = ?", (host_ip,)) as cur:
                row = await cur.fetchone()
            if not row:
                return {"error": f"Host {host_ip} not found"}
            host = dict(row)
            async with db.execute("SELECT * FROM services WHERE host_id = ?", (host["id"],)) as cur:
                services = [dict(r) for r in await cur.fetchall()]
            async with db.execute(
                "SELECT * FROM vulnerabilities WHERE host_id = ?", (host["id"],)
            ) as cur:
                vulns = [dict(r) for r in await cur.fetchall()]
        return {"host": host, "services": services, "vulnerabilities": vulns}

    @mcp.tool()
    async def asset_list_services(
        host_ip: str = "",
        service_name: str = "",
        min_port: int = 1,
        max_port: int = 65535,
    ) -> list:
        """List services, optionally filtered by host or service name."""
        query = """
            SELECT s.*, h.ip, h.hostname FROM services s
            JOIN hosts h ON s.host_id = h.id
            WHERE s.port >= ? AND s.port <= ?
        """
        params: list = [min_port, max_port]
        if host_ip:
            query += " AND h.ip = ?"
            params.append(host_ip)
        if service_name:
            query += " AND s.service LIKE ?"
            params.append(f"%{service_name}%")
        query += " ORDER BY s.port"
        async with _get_db() as db:
            async with db.execute(query, params) as cur:
                rows = await cur.fetchall()
        return [dict(r) for r in rows]

    @mcp.tool()
    async def asset_list_vulnerabilities(
        host_ip: str = "",
        min_severity: str = "info",
        status: str = "",
        limit: int = 100,
    ) -> dict:
        """
        List vulnerabilities, optionally filtered by host or severity.
        min_severity: info, low, medium, high, critical
        status: unconfirmed, confirmed, false_positive, remediated
        """
        sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        min_rank = sev_rank.get(min_severity.lower(), 0)
        # Rank severity via a CASE expression (there is no stored severity_rank column).
        rank_case = (
            "CASE v.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END"
        )
        query = (
            "SELECT v.*, h.ip, h.hostname FROM vulnerabilities v "
            "JOIN hosts h ON v.host_id = h.id "
            f"WHERE {rank_case} >= ?"
        )
        params: list = [min_rank]
        if host_ip:
            query += " AND h.ip = ?"
            params.append(host_ip)
        if status:
            query += " AND v.status = ?"
            params.append(status)
        query += f" ORDER BY {rank_case} DESC, v.last_seen DESC LIMIT ?"
        params.append(limit)
        async with _get_db() as db:
            async with db.execute(query, params) as cur:
                rows = await cur.fetchall()
        vulns = [dict(r) for r in rows]
        by_sev = {}
        for v in vulns:
            sev = v.get("severity", "unknown")
            by_sev[sev] = by_sev.get(sev, 0) + 1
        return {"total": len(vulns), "by_severity": by_sev, "vulnerabilities": vulns}

    @mcp.tool()
    async def asset_search(query: str) -> dict:
        """Search assets by IP, hostname, service, or CVE."""
        results = {"hosts": [], "services": [], "vulnerabilities": []}
        async with _get_db() as db:
            for col in ("ip", "hostname"):
                async with db.execute(
                    f"SELECT * FROM hosts WHERE {col} LIKE ? LIMIT 20", (f"%{query}%",)
                ) as cur:
                    results["hosts"].extend([dict(r) for r in await cur.fetchall()])
            async with db.execute(
                "SELECT s.*, h.ip FROM services s JOIN hosts h ON s.host_id=h.id "
                "WHERE s.service LIKE ? LIMIT 20", (f"%{query}%",)
            ) as cur:
                results["services"].extend([dict(r) for r in await cur.fetchall()])
            async with db.execute(
                "SELECT v.*, h.ip FROM vulnerabilities v JOIN hosts h ON v.host_id=h.id "
                "WHERE v.cve_id LIKE ? LIMIT 20", (f"%{query}%",)
            ) as cur:
                results["vulnerabilities"].extend([dict(r) for r in await cur.fetchall()])
        seen = set()
        results["hosts"] = [h for h in results["hosts"] if not (h["ip"] in seen or seen.add(h["ip"]))]
        return results

    @mcp.tool()
    async def asset_mark_host(host_ip: str, status: str) -> dict:
        """Mark a host with a status (new, scanned, confirmed, remediated, false_positive)."""
        valid = {"new", "scanned", "confirmed", "remediated", "false_positive"}
        if status not in valid:
            return {"error": f"Invalid status '{status}'. Must be one of: {valid}"}
        async with _get_db() as db:
            cur = await db.execute("UPDATE hosts SET status=? WHERE ip=?", (status, host_ip))
            await db.commit()
        if cur.rowcount == 0:
            return {"error": f"Host {host_ip} not found"}
        return {"host_ip": host_ip, "status": status, "updated": True}

    @mcp.tool()
    async def asset_mark_vuln(vuln_id: int, status: str) -> dict:
        """Mark a vulnerability with a status."""
        valid = {"unconfirmed", "confirmed", "false_positive", "remediated"}
        if status not in valid:
            return {"error": f"Invalid status '{status}'. Must be one of: {valid}"}
        async with _get_db() as db:
            cur = await db.execute("UPDATE vulnerabilities SET status=? WHERE id=?", (status, vuln_id))
            await db.commit()
        if cur.rowcount == 0:
            return {"error": f"Vulnerability {vuln_id} not found"}
        return {"vuln_id": vuln_id, "status": status, "updated": True}


async def auto_ingest_findings(findings: list[dict], host: str = "") -> list[dict]:
    """Ingest a batch of findings and return summaries."""
    results = []
    for f in findings:
        if not f.get("host") and host:
            f["host"] = host
        result = await ingest_finding(f)
        results.append(result)
    return results
