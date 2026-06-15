"""
LLM-assisted triage — analyze_findings reads all engagement findings
and returns a structured prioritized summary the LLM can act on directly.
No LLM API call needed — the MCP tool itself does the structured analysis.
The result is designed to be the perfect context for the LLM to decide next actions.

FIX: Replaced O(n) job re-scan with engagement DB read.
     When an engagement is active, findings are already tagged to eng_findings
     by run_and_wait() at job completion — so triage reads the DB directly
     instead of looping over all jobs and re-extracting from raw output.
     Falls back to the old job-scan path when no engagement is active (lab mode).
"""
from datetime import datetime, timezone


# ── Helpers ───────────────────────────────────────────────────────────────────

def _suggest_action(finding: dict) -> str:
    title = finding.get("title", "").lower()
    host = finding.get("host", "target")
    if "sql injection" in title:
        return f"sqlmap_scan(url='http://{host}/', enumerate_dbs=True)"
    if "valid credential" in title or "login" in title:
        return "creds_use(host) then ssh_exec() or http_request()"
    if "open port" in title:
        service = finding.get("service", "")
        return f"cve_to_exploit(service='{service}', version='...')"
    if "nikto" in finding.get("tool", "").lower():
        return "Review finding — may need manual verification"
    return "investigate and exploit if confirmed"


def _build_recommendations(findings: list, creds: list, host_services: dict) -> list:
    recs = []
    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f.get("severity", "info")] = sev_counts.get(f.get("severity", "info"), 0) + 1

    if sev_counts.get("critical", 0) > 0:
        recs.append("IMMEDIATE: Critical findings present — run analyze_findings(min_severity='critical')")
    if creds:
        hosts_with_creds = list({c["host"] for c in creds})
        recs.append(f"Credentials found for {hosts_with_creds} — run ssh_enum_privesc or try web admin login")
    if not creds and findings:
        recs.append("No credentials found yet — run hydra_bruteforce on SSH/FTP/HTTP services")
    for host, services in host_services.items():
        if "http" in services:
            recs.append(f"Web app on {host} — run scan_web(url='http://{host}') for full parallel scan")
        if "smb" in services or "microsoft-ds" in services:
            recs.append(f"SMB on {host} — run enum4linux_scan and check for EternalBlue")
    return recs[:5]


async def _load_findings_fast(job_mgr, host: str) -> tuple[list[dict], dict[str, list]]:
    """
    Fast path: read pre-tagged findings straight from the engagement DB.
    Returns (all_findings, host_services).

    Falls back to scanning raw job output only when no engagement is active
    (lab/dev mode). This avoids re-extracting from stdout on every triage call.
    """
    import engagement as eng_mod
    active = eng_mod.get_active()

    if active:
        # ── Fast path: engagement DB already has everything ──────────────────
        import aiosqlite
        host_services: dict[str, list] = {}
        findings: list[dict] = []

        async with aiosqlite.connect(eng_mod.ENGAGEMENT_DB, timeout=30) as db:
            db.row_factory = aiosqlite.Row
            query = "SELECT * FROM eng_findings WHERE engagement_id=?"
            params: list = [active["id"]]
            if host:
                query += " AND host=?"
                params.append(host)
            query += " ORDER BY added_at DESC LIMIT 2000"
            async with db.execute(query, params) as cur:
                rows = await cur.fetchall()

        for row in rows:
            f = dict(row)
            # Normalise field names to match the findings.py schema
            f.setdefault("confidence", "medium")
            findings.append(f)
            h = f.get("host", "unknown")
            svc = f.get("service", "")
            if svc and svc not in host_services.get(h, []):
                host_services.setdefault(h, []).append(svc)

        return findings, host_services

    # ── Slow fallback: no active engagement → scan job history ───────────────
    from findings import extract_findings, dedup_findings
    jobs = await job_mgr.list_jobs(100)
    all_findings: list[dict] = []
    host_services_fb: dict[str, list] = {}

    for j in jobs:
        if j.get("status") != "completed":
            continue
        full = await job_mgr.get_job(j["id"])
        output = full.get("output", "")
        if not output:
            continue
        extracted = extract_findings(j["tool"], output, host or "unknown")
        for f in extracted:
            f["job_id"] = j["id"]
            f["tool_name"] = j["tool"]
            all_findings.append(f)
            h = f.get("host", "unknown")
            svc = f.get("service", "")
            if svc and svc not in host_services_fb.get(h, []):
                host_services_fb.setdefault(h, []).append(svc)

    return dedup_findings(all_findings), host_services_fb


# ── Tool registration ─────────────────────────────────────────────────────────

def _register(mcp, job_mgr):

    @mcp.tool()
    async def analyze_findings(
        host: str = "",
        min_severity: str = "low",
        min_confidence: str = "low",
        max_items: int = 20,
    ) -> dict:
        """
        Analyze and prioritize all findings from recent scans.
        Returns a structured triage report designed for LLM decision-making.
        Identifies: attack paths, quick wins, critical issues, credential reuse opportunities.

        host: focus on specific host (empty = all hosts)
        min_severity: minimum severity to include — low, medium, high, critical
        min_confidence: minimum confidence to include — low, medium, high
        max_items: max findings to analyze (default 20)

        Returns: prioritized attack paths, quick wins, and recommended next actions.
        """
        from findings import dedup_findings
        from chains import build_attack_chains

        all_findings, host_services = await _load_findings_fast(job_mgr, host)

        # Deduplicate (no-op if already deduped via fast path, harmless either way)
        all_findings = dedup_findings(all_findings)

        # Filter
        sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        conf_rank = {"low": 0, "medium": 1, "high": 2}
        min_sev_rank = sev_rank.get(min_severity.lower(), 1)
        min_conf_rank = conf_rank.get(min_confidence.lower(), 0)

        filtered = [
            f for f in all_findings
            if sev_rank.get(f.get("severity", "info"), 0) >= min_sev_rank
            and conf_rank.get(f.get("confidence", "low"), 0) >= min_conf_rank
        ]
        filtered = filtered[:max_items]

        # Group by severity
        by_severity: dict[str, list] = {}
        for f in filtered:
            by_severity.setdefault(f["severity"], []).append(f)

        # Attack chains from full (unfiltered) finding set for maximum correlation
        attack_paths = build_attack_chains(all_findings)

        # Quick wins — critical/high with ready-to-use action
        quick_wins = [
            {
                "title": f["title"],
                "host": f.get("host"),
                "evidence": f.get("evidence", "")[:100],
                "action": _suggest_action(f),
            }
            for f in filtered
            if f.get("severity") in ("critical", "high")
        ]

        # Credential vault
        try:
            from cred_vault import get_all_credentials
            stored_creds = get_all_credentials(limit=10)
        except Exception:
            stored_creds = []

        return {
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(all_findings),
            "filtered_findings": len(filtered),
            "severity_summary": {k: len(v) for k, v in by_severity.items()},
            "hosts_discovered": list(host_services.keys()),
            "services_per_host": host_services,
            "attack_paths": attack_paths,
            "quick_wins": quick_wins[:5],
            "stored_credentials": stored_creds,
            "critical_findings": by_severity.get("critical", []),
            "high_findings": by_severity.get("high", [])[:5],
            "recommended_next": _build_recommendations(all_findings, stored_creds, host_services),
        }

    _register_chains(mcp, job_mgr)


def _register_chains(mcp, job_mgr):
    """Register the analyze_attack_chains tool."""

    @mcp.tool()
    async def analyze_attack_chains(
        host: str = "",
        min_severity: str = "low",
        min_confidence: str = "low",
    ) -> dict:
        """Correlate current findings into multi-stage attack chains.

        Shows how individual low/medium findings combine into high-impact compound
        attack paths (e.g. SQL injection + exposed SSH = credential theft + system access).
        Call this at any point during an engagement to understand compound risk.

        host: focus on a specific host (empty = all hosts)
        min_severity: minimum finding severity to consider — info, low, medium, high, critical
        min_confidence: minimum finding confidence to consider — low, medium, high
        Returns: list of chains with name, escalated severity, narrative, steps, affected hosts.
        """
        from findings import dedup_findings
        from chains import build_attack_chains

        all_findings, _ = await _load_findings_fast(job_mgr, host)
        all_findings = dedup_findings(all_findings)

        sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        conf_rank = {"low": 0, "medium": 1, "high": 2}
        min_sev = min_severity.lower() if min_severity else "low"
        min_conf = min_confidence.lower() if min_confidence else "low"

        filtered = [
            f for f in all_findings
            if sev_rank.get(f.get("severity", "info"), 0) >= sev_rank.get(min_sev, 0)
            and conf_rank.get(f.get("confidence", "low"), 0) >= conf_rank.get(min_conf, 0)
        ]

        chains = build_attack_chains(filtered)
        return {
            "total_findings_analyzed": len(filtered),
            "chains_found": len(chains),
            "chains": chains,
        }
