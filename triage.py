"""
LLM-assisted triage — analyze_findings reads all engagement findings
and returns a structured prioritized summary the LLM can act on directly.
No LLM API call needed — the MCP tool itself does the structured analysis.
The result is designed to be the perfect context for the LLM to decide next actions.
"""
from datetime import datetime, timezone


def _register(mcp, job_mgr):

    @mcp.tool()
    async def analyze_findings(
        host: str = "",
        min_severity: str = "low",
        max_items: int = 20,
    ) -> dict:
        """
        Analyze and prioritize all findings from recent scans.
        Returns a structured triage report designed for LLM decision-making.
        Identifies: attack paths, quick wins, critical issues, credential reuse opportunities.

        host: focus on specific host (empty = all hosts)
        min_severity: minimum severity to include — low, medium, high, critical
        max_items: max findings to analyze (default 20)

        Returns: prioritized attack paths, quick wins, and recommended next actions.
        """
        # Collect findings from recent jobs
        jobs = await job_mgr.list_jobs(100)
        all_findings = []
        host_services: dict[str, list] = {}

        for j in jobs:
            if j.get("status") != "completed":
                continue
            full = await job_mgr.get_job(j["id"])
            output = full.get("output", "")
            if not output:
                continue
            from findings import extract_findings
            findings = extract_findings(j["tool"], output, host or "unknown")
            for f in findings:
                f["job_id"] = j["id"]
                f["tool_name"] = j["tool"]
                all_findings.append(f)
                # Track services per host
                h = f.get("host", "unknown")
                if f.get("service") and f["service"] not in host_services.get(h, []):
                    host_services.setdefault(h, []).append(f["service"])

        # Filter
        sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        min_rank = sev_rank.get(min_severity.lower(), 1)
        if host:
            all_findings = [f for f in all_findings if f.get("host") == host]
        filtered = [f for f in all_findings if sev_rank.get(f.get("severity","info"), 0) >= min_rank]
        filtered = filtered[:max_items]

        # Group by severity
        by_severity: dict[str, list] = {}
        for f in filtered:
            by_severity.setdefault(f["severity"], []).append(f)

        # Identify attack paths
        attack_paths = []
        all_titles = " ".join(f.get("title","").lower() for f in all_findings)
        all_evidence = " ".join(f.get("evidence","").lower() for f in all_findings)

        # SQLi → DB dump path
        if any("sql injection" in f.get("title","").lower() for f in all_findings):
            attack_paths.append({
                "path": "SQL Injection → Data Extraction",
                "steps": ["Confirm injectable parameter", "Enumerate databases with sqlmap --dbs",
                          "Dump credentials table", "Use creds for SSH/admin login"],
                "risk": "critical",
            })

        # Weak SSH creds path
        if any("valid credential" in f.get("title","").lower() or "22/ssh" in f.get("title","").lower()
               for f in all_findings):
            attack_paths.append({
                "path": "Valid Credentials → System Access",
                "steps": ["Use creds_use() to retrieve found credentials",
                          "Run ssh_exec(host, user, pass, 'id')",
                          "Run ssh_enum_privesc() for local privilege escalation"],
                "risk": "critical",
            })

        # Web admin panel path
        if any("/admin" in f.get("evidence","").lower() or "admin" in f.get("title","").lower()
               for f in all_findings):
            attack_paths.append({
                "path": "Admin Panel Discovered",
                "steps": ["Test default credentials (admin/admin, admin/password)",
                          "Check for CVEs in the admin software version",
                          "Look for file upload or RCE functionality"],
                "risk": "high",
            })

        # Quick wins
        quick_wins = []
        for f in filtered:
            if f.get("severity") in ("critical", "high"):
                quick_wins.append({
                    "title": f["title"],
                    "host": f.get("host"),
                    "evidence": f.get("evidence","")[:100],
                    "action": _suggest_action(f),
                })

        # Check credential vault
        try:
            from cred_vault import _conn
            with _conn() as db:
                creds = db.execute("SELECT * FROM creds ORDER BY discovered_at DESC LIMIT 10").fetchall()
                stored_creds = [dict(c) for c in creds]
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


def _suggest_action(finding: dict) -> str:
    title = finding.get("title", "").lower()
    host = finding.get("host", "target")
    if "sql injection" in title:
        return f"sqlmap_scan(url='http://{host}/', enumerate_dbs=True)"
    if "valid credential" in title or "login" in title:
        return "creds_use(host) then ssh_exec() or http_request()"
    if "open port" in title:
        service = finding.get("service","")
        return f"cve_to_exploit(service='{service}', version='...')"
    if "nikto" in finding.get("tool","").lower():
        return "Review finding — may need manual verification"
    return "investigate and exploit if confirmed"


def _build_recommendations(findings: list, creds: list, host_services: dict) -> list:
    recs = []
    sev_counts = {}
    for f in findings:
        sev_counts[f.get("severity","info")] = sev_counts.get(f.get("severity","info"), 0) + 1

    if sev_counts.get("critical", 0) > 0:
        recs.append("IMMEDIATE: Critical findings present — run analyze_findings(min_severity='critical')")
    if creds:
        hosts_with_creds = list(set(c["host"] for c in creds))
        recs.append(f"Credentials found for {hosts_with_creds} — run ssh_enum_privesc or try web admin login")
    if not creds and findings:
        recs.append("No credentials found yet — run hydra_bruteforce on SSH/FTP/HTTP services")
    for host, services in host_services.items():
        if "http" in services:
            recs.append(f"Web app on {host} — run scan_web(url='http://{host}') for full parallel scan")
        if "smb" in services or "microsoft-ds" in services:
            recs.append(f"SMB on {host} — run enum4linux_scan and check for EternalBlue")

    return recs[:5]
