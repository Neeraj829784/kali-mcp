import json
import os
from datetime import datetime, timezone

from parsers import parse_nmap_xml, parse_nuclei_jsonl


async def _generate_pentest_report_impl(
    job_mgr,
    title: str = "Penetration Test Report",
    min_severity: str = "low",
    min_confidence: str = "low",
    host: str = "",
) -> dict:
    from findings import extract_findings, dedup_findings
    from chains import build_attack_chains
    from remediation import get_remediation
    import engagement as eng_mod

    sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    conf_rank = {"low": 0, "medium": 1, "high": 2}

    jobs = await job_mgr.list_jobs(200)
    all_findings = []
    for j in jobs:
        if j.get("status") != "completed":
            continue
        full = await job_mgr.get_job(j["id"])
        all_findings.extend(
            extract_findings(j["tool"], full.get("output", ""), host or "unknown")
        )

    all_findings = dedup_findings(all_findings)

    filtered = [
        f for f in all_findings
        if sev_rank.get(f["severity"], 0) >= sev_rank.get(min_severity, 0)
        and conf_rank.get(f.get("confidence", "low"), 0) >= conf_rank.get(min_confidence, 0)
    ]

    chains = build_attack_chains(filtered)

    eng = eng_mod.get_active()
    eng_name = eng["name"] if eng else "N/A"
    scope = eng["scope"] if eng else []

    count_by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    hosts_set = set()
    for f in filtered:
        count_by_sev[f.get("severity", "info")] = count_by_sev.get(f.get("severity", "info"), 0) + 1
        if f.get("host"):
            hosts_set.add(f["host"])

    risk_statements = {
        "critical": "CRITICAL risk — immediate action required. Remote code execution or full system compromise is achievable.",
        "high": "HIGH risk — significant vulnerabilities exist that could lead to data breach or system access.",
        "medium": "MEDIUM risk — vulnerabilities exist that may aid an attacker in gaining further access.",
        "low": "LOW risk — minor issues found. Standard hardening recommended.",
        "info": "No significant risk — only informational findings present.",
    }
    highest_sev = next(
        (s for s in ("critical", "high", "medium", "low") if count_by_sev[s] > 0),
        "info",
    )
    risk = risk_statements.get(highest_sev, "Risk assessment unavailable.")

    completed_jobs = [j for j in jobs if j.get("status") == "completed"]
    tools_used = sorted({j.get("tool", "unknown") for j in completed_jobs})
    job_count = len(completed_jobs)

    lines = []
    lines.append(f"# {title}")
    lines.append(f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d UTC')}")
    lines.append(f"**Engagement:** {eng_name}")
    lines.append(f"**Scope:** {', '.join(scope) if scope else 'N/A'}")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append(
        f"{len(hosts_set)} host(s) scanned, {len(filtered)} findings: "
        f"{count_by_sev.get('critical',0)} critical, "
        f"{count_by_sev.get('high',0)} high, "
        f"{count_by_sev.get('medium',0)} medium, "
        f"{count_by_sev.get('low',0)} low"
    )
    if chains:
        lines.append(f"{len(chains)} multi-stage attack paths identified")
    lines.append(risk)
    lines.append("")

    if chains:
        lines.append("## Attack Chains")
        for chain in chains:
            lines.append(f"### [{chain['severity'].upper()}] {chain['name']}")
            lines.append(f"**Combined Impact:** {chain['severity']}")
            lines.append(f"**Affected Hosts:** {', '.join(chain['hosts'])}")
            lines.append(chain["narrative"])
            lines.append("**Contributing findings:**")
            for i, step in enumerate(chain["steps"], 1):
                lines.append(
                    f"{i}. {step['title']} (host: {step['host']}, "
                    f"tool: {step['tool']}, severity: {step['severity']}, "
                    f"confidence: {step['confidence']})"
                )
            lines.append("")

    lines.append("## Findings by Severity")
    sev_order = ["critical", "high", "medium", "low", "info"]
    sev_labels = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
    for sev in sev_order:
        group = [f for f in filtered if f.get("severity") == sev]
        if not group:
            continue
        lines.append(f"### {sev_labels[sev]}")
        for finding in group:
            short_title, detail = get_remediation(finding)
            tools = finding.get("tools", [finding.get("tool", "")])
            host_port = finding.get("host", "")
            if finding.get("port"):
                host_port = f"{host_port}:{finding['port']}"
            lines.append(f"#### [{finding.get('severity','').upper()}] [{finding.get('confidence','')} confidence] {finding.get('title','')}")
            lines.append(f"- **Host:** {host_port}")
            lines.append(f"- **Tool:** {', '.join(tools) if tools else 'N/A'}")
            lines.append(f"- **Evidence:** {finding.get('evidence','')}")
            lines.append(f"- **Remediation:** {short_title} — {detail}")
            lines.append("")

    lines.append("## Appendix: Scan Coverage")
    lines.append(f"- **Tools used:** {', '.join(tools_used)}")
    lines.append(f"- **Total completed jobs:** {job_count}")
    lines.append(f"- **Report generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")

    return {"report": "\n".join(lines), "format": "markdown"}


def _register(mcp, job_mgr):

    @mcp.tool()
    async def generate_report(
        job_ids: list[str],
        title: str = "Penetration Test Report",
        format: str = "markdown",
    ) -> dict:
        """
        Generate a structured report from completed job results.
        job_ids: list of job IDs to include (from list_jobs or get_job_status)
        title: report title
        format: 'markdown' or 'json'
        """
        jobs = [await job_mgr.get_job(jid) for jid in job_ids]

        if format == "json":
            return {"report": json.dumps({
                "title": title,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "jobs": jobs,
            }, indent=2), "format": "json"}

        lines = [
            f"# {title}",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            f"**Total Jobs:** {len(jobs)}", "",
        ]
        by_tool: dict[str, list] = {}
        for j in jobs:
            by_tool.setdefault(j.get("tool", "unknown"), []).append(j)

        for tool, tool_jobs in by_tool.items():
            lines.append(f"## {tool.replace('_', ' ').title()}")
            for j in tool_jobs:
                lines.append(f"### Job `{j['id']}` — {j.get('status','?').upper()}")
                lines.append(f"- **Started:** {j.get('created_at','N/A')}")
                lines.append(f"- **Completed:** {j.get('completed_at','N/A')}")
                if j.get("error"):
                    lines.append(f"- **Error:** {j['error']}")
                output = j.get("output", "").strip()
                if output:
                    lines.append("\n**Output:**\n```")
                    lines.append(output[:3000] + ("\n...(truncated)" if len(output) > 3000 else ""))
                    lines.append("```")
                lines.append("")
        return {"report": "\n".join(lines), "format": "markdown"}

    @mcp.tool()
    async def list_completed_jobs(tool_filter: str = "") -> list:
        """
        List completed jobs, optionally filtered by tool name.
        tool_filter: partial tool name e.g. 'nmap', 'nikto', '' (all)
        """
        jobs = [j for j in await job_mgr.list_jobs(100) if j.get("status") == "completed"]
        if tool_filter:
            jobs = [j for j in jobs if tool_filter.lower() in j.get("tool", "").lower()]
        return jobs

    @mcp.tool()
    async def parse_nmap_output(job_id: str) -> dict:
        """
        Parse nmap output from a completed job into structured data.
        Returns hosts, open ports, services, and OS guesses.
        job_id: completed nmap job ID
        """
        job = await job_mgr.get_job(job_id)
        raw = job.get("output", "")
        if raw.startswith("<?xml") or "<nmaprun" in raw[:200]:
            return parse_nmap_xml(raw)
        return {"raw_output": raw, "note": "Run nmap with XML output for structured parsing"}

    @mcp.tool()
    async def parse_nuclei_output(findings_file: str) -> dict:
        """
        Parse a nuclei JSONL findings file into structured vulnerability data.
        findings_file: path returned by nuclei_scan as 'findings_file'
        """
        if not os.path.exists(findings_file):
            return {"error": f"File not found: {findings_file}"}
        with open(findings_file, "r") as f:
            content = f.read()
        return parse_nuclei_jsonl(content)

    @mcp.tool()
    async def generate_pentest_report(
        title: str = "Penetration Test Report",
        min_severity: str = "low",
        min_confidence: str = "low",
        host: str = "",
    ) -> dict:
        """Generate a professional finding-based pentest report with attack chains and remediation."""
        return await _generate_pentest_report_impl(job_mgr, title, min_severity, min_confidence, host)
