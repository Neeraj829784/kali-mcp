import json
import os
from datetime import datetime, timezone

from parsers import parse_nmap_xml, parse_nuclei_jsonl


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
        # Try XML path first (if -oX was used), otherwise return structured raw
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
