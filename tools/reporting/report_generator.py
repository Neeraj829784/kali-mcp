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
    save_to: str = "",
    format: str = "markdown",
    confirmed_only: bool = False,
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

    # Also include findings tagged to the active engagement (may overlap — dedup handles it)
    try:
        import engagement as eng_mod2
        active = eng_mod2.get_active()
        if active:
            import sqlite3
            db_path = eng_mod2.ENGAGEMENT_DB
            with sqlite3.connect(db_path) as db:
                db.row_factory = sqlite3.Row
                status_filter = "AND status='confirmed'" if confirmed_only else ""
                rows = db.execute(
                    f"SELECT * FROM eng_findings WHERE engagement_id=? {status_filter} ORDER BY added_at DESC LIMIT 500",
                    (active["id"],)
                ).fetchall()
            for row in rows:
                all_findings.append({
                    "host": row["host"] or "",
                    "port": row["port"] or 0,
                    "service": row["service"] or "",
                    "title": row["title"] or "",
                    "severity": row["severity"] or "info",
                    "evidence": row["evidence"] or "",
                    "tool": row["tool"] or "",
                    "confidence": "medium",
                })
    except Exception:
        pass

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

    report_md = "\n".join(lines)
    report_out = _md_to_html(title, report_md) if format == "html" else report_md
    result: dict = {
        "report": report_out,
        "format": format if format in ("markdown", "html") else "markdown",
        "findings_count": len(filtered),
        "chains_count": len(chains),
    }

    if save_to:
        from tools.base import safe_save_path as _safe_save_path
        try:
            path = _safe_save_path(save_to)
            dirpath = os.path.dirname(path)
            if dirpath:
                os.makedirs(dirpath, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(report_out)
            result["saved_to"] = path
        except ValueError as e:
            result["save_error"] = str(e)
        except Exception as e:
            result["save_error"] = f"Failed to save: {e}"

    return result


_SEV_COLOR = {
    "critical": "#c0392b", "high": "#e67e22",
    "medium": "#f1c40f", "low": "#27ae60", "info": "#2980b9",
}

_HTML_CSS = """
body{font-family:Arial,sans-serif;max-width:960px;margin:40px auto;padding:0 20px;color:#222;line-height:1.6}
h1{border-bottom:3px solid #2c3e50;padding-bottom:10px;color:#2c3e50}
h2{border-left:4px solid #2980b9;padding-left:10px;color:#2c3e50;margin-top:40px}
h3{margin-top:24px}
.badge{display:inline-block;padding:2px 10px;border-radius:12px;color:#fff;font-size:0.8em;font-weight:bold;text-transform:uppercase;margin-right:6px}
.exec-box{background:#eaf4fb;border-left:4px solid #2980b9;padding:12px 18px;margin:16px 0;border-radius:4px}
.chain-box{background:#fdf6ec;border-left:4px solid #e67e22;padding:12px 18px;margin:16px 0;border-radius:4px}
.finding-card{background:#f9f9f9;border:1px solid #ddd;border-radius:6px;padding:14px 18px;margin:12px 0}
.finding-card .label{font-weight:bold;color:#555;min-width:110px;display:inline-block}
code,pre{background:#f4f4f4;padding:2px 6px;border-radius:3px;font-size:0.9em}
pre{padding:10px;overflow-x:auto;white-space:pre-wrap}
table{border-collapse:collapse;width:100%}
td,th{border:1px solid #ddd;padding:8px 12px;text-align:left}
th{background:#2c3e50;color:#fff}
"""


def _badge(severity: str) -> str:
    color = _SEV_COLOR.get(severity.lower(), "#888")
    return f'<span class="badge" style="background:{color}">{severity.upper()}</span>'


def _md_to_html(title: str, md: str) -> str:
    """Convert the Markdown report to a self-contained, client-ready HTML file."""
    try:
        import markdown as md_lib  # type: ignore
        body = md_lib.markdown(md, extensions=["tables", "fenced_code"])
    except ImportError:
        # Fallback: block-level + inline regex conversion without the markdown library
        import re
        blocks = re.split(r"\n\n+", md)
        parts = []
        for block in blocks:
            block = block.strip()
            if not block:
                continue
            # Inline formatting
            block = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", block)
            block = re.sub(r"`(.+?)`", r"<code>\1</code>", block)
            if re.match(r"^### ", block):
                block = re.sub(r"^### (.+)$", r"<h3>\1</h3>", block, flags=re.MULTILINE)
            elif re.match(r"^## ", block):
                block = re.sub(r"^## (.+)$", r"<h2>\1</h2>", block, flags=re.MULTILINE)
            elif re.match(r"^# ", block):
                block = re.sub(r"^# (.+)$", r"<h1>\1</h1>", block, flags=re.MULTILINE)
            elif re.match(r"^- ", block, re.MULTILINE):
                items = "\n".join(
                    f"<li>{line[2:]}</li>" for line in block.splitlines() if line.startswith("- ")
                )
                block = f"<ul>{items}</ul>"
            elif not block.startswith("<"):
                block = f"<p>{block}</p>"
            parts.append(block)
        body = "\n".join(parts)

    # colour-code severity badges in rendered HTML
    for sev, color in _SEV_COLOR.items():
        body = body.replace(
            f"[{sev.upper()}]",
            f'<span class="badge" style="background:{color}">{sev.upper()}</span>',
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>{_HTML_CSS}</style>
</head>
<body>
{body}
</body>
</html>"""


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
        save_to: str = "",
        format: str = "markdown",
        confirmed_only: bool = False,
    ) -> dict:
        """Generate a professional finding-based pentest report with attack chains and remediation.

        title: report title
        min_severity: minimum severity to include — info, low, medium, high, critical
        min_confidence: minimum confidence to include — low, medium, high
        host: filter by specific host (empty = all hosts)
        save_to: optional file path to save the report (must be under artifacts/, /tmp, or /var/tmp)
        format: 'markdown' (default) or 'html' (self-contained HTML file, suitable for client delivery)
        confirmed_only: if True, only include findings marked 'confirmed' via update_finding_status.
                        Use after running a validation agent for a zero-false-positive report.
        """
        return await _generate_pentest_report_impl(
            job_mgr, title, min_severity, min_confidence, host, save_to, format, confirmed_only
        )
