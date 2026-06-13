"""
Finding normalization — extracts structured findings from raw tool output.
Every tool result passes through normalize() which returns a list of Finding dicts.
"""
import json
import re
from typing import Any

# Severity levels
CRITICAL, HIGH, MEDIUM, LOW, INFO = "critical", "high", "medium", "low", "info"

# Confidence levels - how sure we are a finding is real (separate from severity).
# HIGH = tool actively confirmed it; MEDIUM = template/script matched; LOW = pattern guess.
CONF_HIGH, CONF_MEDIUM, CONF_LOW = "high", "medium", "low"
_CONF_RANK = {CONF_LOW: 0, CONF_MEDIUM: 1, CONF_HIGH: 2}
_RANK_CONF = {v: k for k, v in _CONF_RANK.items()}


def _finding(host: str, title: str, severity: str, evidence: str,
             tool: str, port: int = 0, service: str = "",
             confidence: str = CONF_MEDIUM) -> dict:
    return {
        "host": host,
        "port": port,
        "service": service,
        "title": title,
        "severity": severity,
        "evidence": evidence[:500],
        "tool": tool,
        "confidence": confidence,
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
            tool="nuclei", confidence=CONF_MEDIUM,
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
            tool="nmap", port=port, service=service, confidence=CONF_HIGH,
        ))
    # NSE vuln script findings
    for m in re.finditer(r"\|\s+(VULNERABLE|CVE-\d{4}-\d+[^\n]*)", output):
        findings.append(_finding(
            host=host, title=m.group(1).strip(),
            severity=HIGH, evidence=m.group(0).strip(),
            tool="nmap", confidence=CONF_MEDIUM,
        ))
    return findings


# Low-value nikto lines that are almost always noise / informational headers.
_NIKTO_NOISE = (
    "server:", "x-powered-by", "allowed http methods", "uncommon header",
    "the anti-clickjacking", "x-frame-options", "x-content-type-options",
    "cookie", "no cgi directories found", "retrieved via header",
    "retrieved x-powered-by", "the x-", "strict-transport-security",
)
# Keywords that always indicate a real, high-signal finding worth keeping.
_NIKTO_HIGH = ("xss", "sql", "rce", "exec", "inject")


def _from_nikto(output: str, host: str) -> list[dict]:
    findings = []
    for line in output.splitlines():
        if not (line.startswith("+ ") and "OSVDB" not in line and len(line) > 5):
            continue
        body = line[2:]
        low = body.lower()
        is_high = any(k in low for k in _NIKTO_HIGH)
        # Drop known noise unless it also matches a high-signal keyword
        if not is_high and any(n in low for n in _NIKTO_NOISE):
            continue
        severity = HIGH if is_high else LOW
        findings.append(_finding(
            host=host, title=body[:78],
            severity=severity, evidence=body,
            tool="nikto", confidence=CONF_LOW,
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
                tool="gobuster", confidence=CONF_LOW,
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
            tool="sqlmap", confidence=CONF_HIGH,
        ))
    if re.search(r"available databases.*?:\s*\[(.+?)\]", output, re.DOTALL):
        db_match = re.search(r"\[\*\] databases.*", output, re.DOTALL)
        findings.append(_finding(
            host=host, title="Database names enumerated via SQLi",
            severity=HIGH, evidence=db_match.group(0)[:200] if db_match else "",
            tool="sqlmap", confidence=CONF_HIGH,
        ))
    return findings


def _from_hydra(output: str, host: str) -> list[dict]:
    findings = []
    for m in re.finditer(r"\[(\d+)\]\[(\w+)\] host: (\S+)\s+login: (\S+)\s+password: (\S+)", output):
        port, service, target, user, pwd = m.groups()
        findings.append(_finding(
            host=target, title=f"Valid credentials found for {service}",
            severity=CRITICAL, evidence=f"{user}:{pwd}",
            tool="hydra", port=int(port), service=service, confidence=CONF_HIGH,
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
                tool="searchsploit", confidence=CONF_LOW,
            ))
    except Exception:
        pass
    return findings


# ── Main dispatcher ───────────────────────────────────────────────────────────


def _from_ffuf(output: str, host: str) -> list[dict]:
    """Extract endpoints found by ffuf (JSON or plain text output)."""
    findings = []
    # Try JSON lines first
    for line in output.splitlines():
        try:
            obj = json.loads(line.strip())
            # ffuf JSON result line: {"input":{"FUZZ":"..."}, "url":"...", "status":200, ...}
            url = obj.get("url", "")
            status = obj.get("status", 0)
            length = obj.get("length", 0)
            if url and status in (200, 301, 302, 403):
                findings.append(_finding(
                    host=host, title=f"Found endpoint {url} [{status}]",
                    severity=LOW, evidence=f"HTTP {status}, {length} bytes",
                    tool="ffuf", confidence=CONF_LOW,
                ))
        except Exception:
            pass
    if findings:
        return findings
    # Fallback: plain text "Status: 200" lines
    for m in re.finditer(r"(https?://\S+)\s+\[Status:\s*(\d+),", output):
        url, status = m.group(1), int(m.group(2))
        if status in (200, 301, 302, 403):
            findings.append(_finding(
                host=host, title=f"Found endpoint {url} [{status}]",
                severity=LOW, evidence=f"HTTP {status}",
                tool="ffuf", confidence=CONF_LOW,
            ))
    return findings


def _from_wpscan(output: str, host: str) -> list[dict]:
    """Extract findings from wpscan JSON output."""
    findings = []
    try:
        data = json.loads(output)
    except Exception:
        # Plain text fallback: look for [!] lines
        for line in output.splitlines():
            if line.strip().startswith("[!]") and len(line) > 5:
                findings.append(_finding(
                    host=host, title=line.strip()[3:80],
                    severity=MEDIUM, evidence=line.strip(),
                    tool="wpscan", confidence=CONF_MEDIUM,
                ))
        return findings
    # JSON: vulnerable plugins
    for name, plugin in (data.get("plugins") or {}).items():
        for vuln in (plugin.get("vulnerabilities") or []):
            title = vuln.get("title", f"WPScan: {name}")
            cvss = vuln.get("cvss", {})
            sev = HIGH if cvss.get("score", 0) >= 7 else MEDIUM
            findings.append(_finding(
                host=host, title=title,
                severity=sev, evidence=str(vuln.get("references", {}))[:300],
                tool="wpscan", confidence=CONF_MEDIUM,
            ))
    # JSON: users found
    for user in (data.get("users") or {}).keys():
        findings.append(_finding(
            host=host, title=f"WordPress user enumerated: {user}",
            severity=LOW, evidence=f"User: {user}",
            tool="wpscan", confidence=CONF_HIGH,
        ))
    return findings


def _from_enum4linux(output: str, host: str) -> list[dict]:
    """Extract users, shares, and policy findings from enum4linux output."""
    findings = []
    # Users
    for m in re.finditer(r"user:\[(\S+)\]\s+rid:\[", output):
        user = m.group(1)
        findings.append(_finding(
            host=host, title=f"SMB user enumerated: {user}",
            severity=LOW, evidence=f"user:[{user}]",
            tool="enum4linux", confidence=CONF_HIGH,
        ))
    # Shares
    for m in re.finditer(r"Sharename\s+Type.*?(?=^[-\\])", output, re.DOTALL | re.MULTILINE):
        block = m.group(0)
        for share_m in re.finditer(r"^(\S+)\s+(Disk|IPC|Printer)", block, re.MULTILINE):
            share = share_m.group(1)
            findings.append(_finding(
                host=host, title=f"SMB share accessible: {share}",
                severity=LOW, evidence=f"Share: {share}",
                tool="enum4linux", confidence=CONF_HIGH,
            ))
    # Null session
    if "allows sessions using username" in output.lower() or "session setup ok" in output.lower():
        findings.append(_finding(
            host=host, title="SMB null session allowed",
            severity=MEDIUM, evidence="Null session enumeration succeeded",
            tool="enum4linux", confidence=CONF_HIGH,
        ))
    return findings


def _from_theharvester(output: str, host: str) -> list[dict]:
    """Extract emails and subdomains from theHarvester output."""
    findings = []
    # Emails
    emails = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", output)
    for email in set(emails):
        findings.append(_finding(
            host=host, title=f"Email found: {email}",
            severity=INFO, evidence=email,
            tool="theharvester", confidence=CONF_HIGH,
        ))
    # Subdomains/IPs
    for m in re.finditer(r"^\s*(\S+\.\S+):\s*(\d+\.\d+\.\d+\.\d+)", output, re.MULTILINE):
        subdomain, ip = m.group(1), m.group(2)
        findings.append(_finding(
            host=host, title=f"Subdomain discovered: {subdomain} ({ip})",
            severity=INFO, evidence=f"{subdomain} -> {ip}",
            tool="theharvester", confidence=CONF_HIGH,
        ))
    return findings


def _from_subdomains(output: str, host: str, tool: str) -> list[dict]:
    """Extract subdomains from amass/subfinder output (one per line)."""
    findings = []
    for line in output.splitlines():
        subdomain = line.strip()
        if subdomain and "." in subdomain and not subdomain.startswith("#"):
            findings.append(_finding(
                host=host, title=f"Subdomain discovered: {subdomain}",
                severity=INFO, evidence=subdomain,
                tool=tool, confidence=CONF_HIGH,
            ))
    return findings[:200]  # cap to avoid flooding from large wordlists


def _from_amass(output: str, host: str) -> list[dict]:
    return _from_subdomains(output, host, "amass")


def _from_subfinder(output: str, host: str) -> list[dict]:
    return _from_subdomains(output, host, "subfinder")


def _from_ssh_enum_privesc(output: str, host: str) -> list[dict]:
    """Extract privilege escalation vectors from ssh_enum_privesc output."""
    findings = []
    # SUID binaries
    suid_binaries = re.findall(r"(/(?:usr/)?(?:bin|sbin)/\S+)", output)
    if suid_binaries:
        findings.append(_finding(
            host=host, title=f"SUID binaries found ({len(suid_binaries)} total)",
            severity=MEDIUM, evidence=", ".join(suid_binaries[:10]),
            tool="ssh_enum_privesc", confidence=CONF_HIGH,
        ))
    # Sudo permissions
    if re.search(r"\(ALL\).*NOPASSWD|\(root\)", output):
        findings.append(_finding(
            host=host, title="Sudo NOPASSWD or root permissions found",
            severity=HIGH, evidence=re.search(r"sudo.*", output, re.IGNORECASE).group(0)[:200] if re.search(r"sudo.*", output, re.IGNORECASE) else "",
            tool="ssh_enum_privesc", confidence=CONF_HIGH,
        ))
    # Capabilities
    caps = re.findall(r"(/\S+) = (cap_\S+)", output)
    if caps:
        findings.append(_finding(
            host=host, title=f"Linux capabilities found: {caps[0][1]}",
            severity=MEDIUM, evidence=str(caps[:5]),
            tool="ssh_enum_privesc", confidence=CONF_HIGH,
        ))
    return findings


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
    "ffuf": _from_ffuf,
    "wpscan": _from_wpscan,
    "enum4linux": _from_enum4linux,
    "theharvester": _from_theharvester,
    "amass": _from_amass,
    "subfinder": _from_subfinder,
    "ssh_enum_privesc": _from_ssh_enum_privesc,
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


_SEV_RANK = {INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4}


def _normalize_title(title: str) -> str:
    """Lowercase and strip trailing bracketed status codes / whitespace so that
    e.g. 'Found path /admin [200]' and 'Found path /admin [301]' collapse."""
    t = re.sub(r"\s*\[\d{3}\]\s*$", "", title.strip())
    return t.lower()


def dedup_findings(findings: list[dict]) -> list[dict]:
    """Merge duplicate findings keyed on (host, port, normalized_title).

    Keeps the highest severity, collects every contributing tool into a 'tools'
    list, and — when two or more DISTINCT tools agree — boosts confidence one
    level (capped at HIGH) as cross-tool corroboration.
    """
    merged: dict[tuple, dict] = {}
    for f in findings:
        key = (f.get("host", ""), f.get("port", 0), _normalize_title(f.get("title", "")))
        if key not in merged:
            nf = dict(f)
            nf["tools"] = [f.get("tool", "")] if f.get("tool") else []
            merged[key] = nf
            continue
        existing = merged[key]
        # collect tool
        tool = f.get("tool", "")
        if tool and tool not in existing["tools"]:
            existing["tools"].append(tool)
        # keep highest severity
        if _SEV_RANK.get(f.get("severity", INFO), 0) > _SEV_RANK.get(existing.get("severity", INFO), 0):
            existing["severity"] = f.get("severity", INFO)
        # keep longest evidence
        if len(f.get("evidence", "")) > len(existing.get("evidence", "")):
            existing["evidence"] = f.get("evidence", "")
        # keep highest base confidence
        if _CONF_RANK.get(f.get("confidence", CONF_MEDIUM), 1) > _CONF_RANK.get(existing.get("confidence", CONF_MEDIUM), 1):
            existing["confidence"] = f.get("confidence", CONF_MEDIUM)

    # corroboration: >=2 distinct tools -> bump confidence one level
    result = []
    for nf in merged.values():
        if len(nf.get("tools", [])) >= 2:
            rank = min(_CONF_RANK.get(nf.get("confidence", CONF_MEDIUM), 1) + 1, _CONF_RANK[CONF_HIGH])
            nf["confidence"] = _RANK_CONF[rank]
        result.append(nf)
    return result


# Tools whose path findings can be actively re-checked over HTTP.
_WEB_PATH_TOOLS = ("gobuster", "ffuf")
_PATH_RE = re.compile(r"\bat\s+(/\S*)")


def _extract_path(finding: dict) -> str:
    """Pull the URL path out of a gobuster/ffuf finding's evidence."""
    m = _PATH_RE.search(finding.get("evidence", ""))
    return m.group(1) if m else ""


async def verify_web_findings(findings: list[dict], base_url: str,
                              length_tolerance: int = 64) -> list[dict]:
    """Soft-404 / wildcard filtering + active confirmation for web path findings.

    Requests a random non-existent path to establish a wildcard baseline. Any
    gobuster/ffuf path whose response matches that baseline (same status and a
    near-identical body length) is treated as a soft-404 and dropped. Paths that
    respond differently are actively confirmed and promoted to HIGH confidence.

    Non-web findings pass through untouched. Never raises — on any network error
    the findings are returned unchanged so verification failure can't lose data.
    """
    if not base_url or not findings:
        return findings

    import secrets
    from urllib.parse import urljoin

    try:
        import httpx
    except Exception:
        return findings

    base = base_url if base_url.endswith("/") else base_url + "/"

    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=8, verify=False) as client:
            # Wildcard baseline from a path that should not exist
            rand = secrets.token_hex(16)
            try:
                bl = await client.get(urljoin(base, rand))
                baseline = (bl.status_code, len(bl.content))
            except Exception:
                baseline = None

            verified: list[dict] = []
            for f in findings:
                if f.get("tool") not in _WEB_PATH_TOOLS:
                    verified.append(f)
                    continue
                path = _extract_path(f)
                if not path:
                    verified.append(f)
                    continue
                try:
                    resp = await client.get(urljoin(base, path.lstrip("/")))
                except Exception:
                    verified.append(f)  # leave unchanged on error
                    continue
                # Soft-404: same status as wildcard baseline and ~same body length
                if baseline and resp.status_code == baseline[0] and \
                        abs(len(resp.content) - baseline[1]) <= length_tolerance:
                    continue  # drop false positive
                # Actively confirmed distinct response
                nf = dict(f)
                nf["confidence"] = CONF_HIGH
                nf["evidence"] = f"HTTP {resp.status_code} at {path} (confirmed, {len(resp.content)} bytes)"
                verified.append(nf)
            return verified
    except Exception:
        return findings


def _register(mcp, job_mgr):

    @mcp.tool()
    async def get_findings(job_id: str = "", host: str = "", min_severity: str = "info", min_confidence: str = "low") -> dict:
        """
        Extract and return normalized findings from a completed job.
        job_id: job to extract findings from (leave empty to get all recent findings)
        host: filter findings by host
        min_severity: minimum severity to return — info, low, medium, high, critical
        min_confidence: minimum confidence to return — low, medium, high
        Returns: list of normalized Finding objects with host, title, severity, evidence, tool
        """
        severity_rank = {INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4}
        min_rank = severity_rank.get(min_severity.lower(), 0)
        conf_rank = {"low": 0, "medium": 1, "high": 2}

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

        # Deduplicate across tools (merges + corroboration confidence boost)
        all_findings = dedup_findings(all_findings)

        # Filter by severity, confidence, and host
        filtered = [f for f in all_findings
                    if severity_rank.get(f["severity"], 0) >= min_rank
                    and conf_rank.get(f.get("confidence", "low"), 0) >= conf_rank.get(min_confidence, 0)]
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
