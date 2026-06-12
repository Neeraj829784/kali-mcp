"""
Finding normalization — extracts structured findings from raw tool output.
Every tool result passes through normalize() which returns a list of Finding dicts.
"""
import json
import re
from typing import Any

# Severity levels
CRITICAL, HIGH, MEDIUM, LOW, INFO = "critical", "high", "medium", "low", "info"


def _finding(host: str, title: str, severity: str, evidence: str,
             tool: str, port: int = 0, service: str = "") -> dict:
    return {
        "host": host,
        "port": port,
        "service": service,
        "title": title,
        "severity": severity,
        "evidence": evidence[:500],
        "tool": tool,
    }


# ── Per-tool extractors ───────────────────────────────────────────────────────

def _from_nuclei_jsonl(output: str, host: str) -> list[dict]:
    findings = []
    for line in output.splitlines():
        try:
            obj = json.loads(line.strip())
        except Exception:
            continue
        info = obj.get("info", {})
        severity = info.get("severity", INFO)
        findings.append(_finding(
            host=obj.get("host", host),
            title=info.get("name", obj.get("template-id", "Unknown")),
            severity=severity,
            evidence=obj.get("matched-at", ""),
            tool="nuclei",
        ))
    return findings


def _from_nmap(output: str, host: str) -> list[dict]:
    findings = []
    # Extract open ports
    for m in re.finditer(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", output):
        port, service, version = int(m.group(1)), m.group(2), m.group(3).strip()
        findings.append(_finding(
            host=host, title=f"Open port {port}/{service}",
            severity=INFO, evidence=version or service,
            tool="nmap", port=port, service=service,
        ))
    # NSE vuln script findings
    for m in re.finditer(r"\|\s+(VULNERABLE|CVE-\d{4}-\d+[^\n]*)", output):
        findings.append(_finding(
            host=host, title=m.group(1).strip(),
            severity=HIGH, evidence=m.group(0).strip(),
            tool="nmap",
        ))
    return findings


def _from_nikto(output: str, host: str) -> list[dict]:
    findings = []
    for line in output.splitlines():
        if line.startswith("+ ") and "OSVDB" not in line and len(line) > 5:
            severity = HIGH if any(k in line.lower() for k in ["xss", "sql", "rce", "exec", "inject"]) else LOW
            findings.append(_finding(
                host=host, title=line[2:80],
                severity=severity, evidence=line[2:],
                tool="nikto",
            ))
    return findings


def _from_gobuster(output: str, host: str) -> list[dict]:
    findings = []
    for m in re.finditer(r"(/\S+)\s+\(Status:\s*(\d+)\)", output):
        path, code = m.group(1), int(m.group(2))
        if code in (200, 301, 302, 403):
            findings.append(_finding(
                host=host, title=f"Found path {path} [{code}]",
                severity=INFO if code in (301, 302) else LOW,
                evidence=f"HTTP {code} at {path}",
                tool="gobuster",
            ))
    return findings


def _from_sqlmap(output: str, host: str) -> list[dict]:
    findings = []
    if "injectable" in output.lower():
        # Extract parameter name
        param = ""
        m = re.search(r"Parameter: (\S+) \(", output)
        if m:
            param = m.group(1)
        findings.append(_finding(
            host=host, title=f"SQL Injection in parameter '{param}'" if param else "SQL Injection found",
            severity=CRITICAL, evidence=output[:300],
            tool="sqlmap",
        ))
    if re.search(r"available databases.*?:\s*\[(.+?)\]", output, re.DOTALL):
        findings.append(_finding(
            host=host, title="Database names enumerated via SQLi",
            severity=HIGH, evidence=re.search(r"\[\*\] databases.*", output, re.DOTALL).group(0)[:200] if re.search(r"\[\*\] databases", output) else "",
            tool="sqlmap",
        ))
    return findings


def _from_hydra(output: str, host: str) -> list[dict]:
    findings = []
    for m in re.finditer(r"\[(\d+)\]\[(\w+)\] host: (\S+)\s+login: (\S+)\s+password: (\S+)", output):
        port, service, target, user, pwd = m.groups()
        findings.append(_finding(
            host=target, title=f"Valid credentials found for {service}",
            severity=CRITICAL, evidence=f"{user}:{pwd}",
            tool="hydra", port=int(port), service=service,
        ))
    return findings


def _from_searchsploit(output: str, host: str) -> list[dict]:
    findings = []
    try:
        data = json.loads(output)
        for e in (data.get("RESULTS_EXPLOIT", []) + data.get("RESULTS_SHELLCODE", []))[:10]:
            findings.append(_finding(
                host=host, title=e.get("Title", "Exploit"),
                severity=HIGH, evidence=e.get("Path", ""),
                tool="searchsploit",
            ))
    except Exception:
        pass
    return findings


# ── Main dispatcher ───────────────────────────────────────────────────────────

_EXTRACTORS = {
    "nuclei": _from_nuclei_jsonl,
    "nmap_port_scan": _from_nmap,
    "nmap_service_detection": _from_nmap,
    "nmap_vuln_scan": _from_nmap,
    "nmap_aggressive_scan": _from_nmap,
    "nikto": _from_nikto,
    "gobuster_dir": _from_gobuster,
    "gobuster_vhost": _from_gobuster,
    "sqlmap": _from_sqlmap,
    "hydra": _from_hydra,
    "searchsploit": _from_searchsploit,
}


def extract_findings(tool: str, output: str, host: str) -> list[dict]:
    """Extract normalized findings from a tool's output."""
    extractor = _EXTRACTORS.get(tool)
    if not extractor or not output:
        return []
    try:
        return extractor(output, host)
    except Exception:
        return []


def _register(mcp, job_mgr):

    @mcp.tool()
    async def get_findings(job_id: str = "", host: str = "", min_severity: str = "info") -> dict:
        """
        Extract and return normalized findings from a completed job.
        job_id: job to extract findings from (leave empty to get all recent findings)
        host: filter findings by host
        min_severity: minimum severity to return — info, low, medium, high, critical
        Returns: list of normalized Finding objects with host, title, severity, evidence, tool
        """
        severity_rank = {INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4}
        min_rank = severity_rank.get(min_severity.lower(), 0)

        if job_id:
            job = await job_mgr.get_job(job_id)
            output = job.get("output", "")
            tool = job.get("tool", "")
            target = host or "unknown"
            all_findings = extract_findings(tool, output, target)
        else:
            # Get all recent completed jobs and extract findings
            jobs = await job_mgr.list_jobs(50)
            all_findings = []
            for j in jobs:
                if j.get("status") != "completed":
                    continue
                full = await job_mgr.get_job(j["id"])
                output = full.get("output", "")
                findings = extract_findings(j["tool"], output, host or "unknown")
                all_findings.extend(findings)

        # Filter by severity and host
        filtered = [f for f in all_findings
                    if severity_rank.get(f["severity"], 0) >= min_rank]
        if host:
            filtered = [f for f in filtered if f["host"] == host]

        # Group by severity
        by_severity: dict[str, list] = {}
        for f in filtered:
            by_severity.setdefault(f["severity"], []).append(f)

        return {
            "total": len(filtered),
            "by_severity": {k: len(v) for k, v in by_severity.items()},
            "findings": filtered,
        }
