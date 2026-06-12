import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

from mcp.server.fastmcp import FastMCP

from config import AUDIT_LOG_PATH
from job_manager import JobManager
from scope import check_scope, add_scope, list_scope, set_scope, remove_scope, clear_scope
import cred_vault
import findings as findings_mod
import health
import engagement
import workflow
import triage
from tools import file_tools
from tools.reconnaissance import nmap, whois_tool, dig_tool, subfinder, theharvester, amass
from tools.scanning import nikto, gobuster, enum4linux, smbclient_tool, ffuf
from tools.scanning import fast_port_scan
from tools.vulnerability import searchsploit, nuclei, wpscan
from tools.vulnerability import cve_to_exploit
from tools.exploitation import sqlmap, hydra, metasploit, netcat, ssh_tools
from tools.reporting import report_generator, pcap_parser
from tools.web import web_tools, web_crawler, screenshot

# Audit logger — every tool call gets a line in audit.log
audit = logging.getLogger("audit")
audit.setLevel(logging.INFO)
_fh = logging.FileHandler(AUDIT_LOG_PATH)
_fh.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
audit.addHandler(_fh)

job_mgr = JobManager()


@asynccontextmanager
async def lifespan(server: FastMCP) -> AsyncIterator[None]:
    await job_mgr.init_db()
    yield


mcp = FastMCP("kali-mcp", lifespan=lifespan)

# Register all tool modules
for module in [nmap, whois_tool, dig_tool, subfinder, theharvester, amass,
               nikto, gobuster, enum4linux, smbclient_tool, ffuf, fast_port_scan,
               searchsploit, nuclei, wpscan, cve_to_exploit,
               sqlmap, hydra, metasploit, netcat, ssh_tools,
               report_generator, pcap_parser, web_tools, web_crawler, screenshot,
               health, file_tools,
               cred_vault, findings_mod,
               engagement, workflow, triage]:
    module._register(mcp, job_mgr)


# ── Job management tools ──────────────────────────────────────────────────────

@mcp.tool(annotations={"readOnlyHint": True})
async def get_job_status(job_id: str) -> dict:
    """Get status and result of an async job by its ID."""
    audit.info(f"get_job_status job_id={job_id}")
    return await job_mgr.get_job(job_id)


@mcp.tool(annotations={"readOnlyHint": True})
async def get_job_output(job_id: str, tail: int = 100) -> dict:
    """
    Get partial output from a running or completed job.
    Useful for checking progress before a job finishes.
    job_id: job ID to read
    tail: number of lines from the end to return (default 100, 0 = all)
    """
    audit.info(f"get_job_output job_id={job_id} tail={tail}")
    return await job_mgr.get_job(job_id, tail=tail)


@mcp.tool(annotations={"readOnlyHint": True})
async def list_jobs(limit: int = 20) -> list:
    """List recent jobs with their statuses."""
    return await job_mgr.list_jobs(limit)


@mcp.tool(annotations={"destructiveHint": True})
async def cancel_job(job_id: str) -> dict:
    """Cancel a running job and kill its process group."""
    audit.info(f"cancel_job job_id={job_id}")
    cancelled = await job_mgr.cancel_job(job_id)
    return {"cancelled": cancelled, "job_id": job_id}


# ── Scope management tools ────────────────────────────────────────────────────

@mcp.tool(annotations={"readOnlyHint": True})
async def scope_list() -> dict:
    """
    List all authorized targets in scope.
    Empty list means lab mode — all targets allowed.
    """
    entries = list_scope()
    return {
        "scope": entries,
        "mode": "lab (all targets allowed)" if not entries else "restricted",
    }


@mcp.tool(annotations={"idempotentHint": True})
async def scope_add(target: str) -> dict:
    """
    Add a single target to the authorized scope.
    target: IP, CIDR (e.g. '192.168.1.0/24'), domain, or '*.example.com'
    """
    add_scope(target)
    audit.info(f"scope_add target={target}")
    return {"added": target, "scope": list_scope()}


@mcp.tool(annotations={"destructiveHint": True})
async def scope_set(targets: list[str]) -> dict:
    """
    Replace the entire scope with a new list of targets.
    Use this at the start of an engagement to set all authorized targets at once.
    targets: list of IPs, CIDRs, domains e.g. ['192.168.1.0/24', 'example.com', '*.example.com']
    """
    set_scope(targets)
    audit.info(f"scope_set targets={targets}")
    return {"scope": list_scope(), "mode": "restricted"}


@mcp.tool()
async def scope_remove(target: str) -> dict:
    """Remove a specific target from scope."""
    removed = remove_scope(target)
    audit.info(f"scope_remove target={target} removed={removed}")
    return {"removed": removed, "scope": list_scope()}


@mcp.tool(annotations={"destructiveHint": True})
async def scope_clear() -> dict:
    """
    Clear all scope restrictions — reverts to lab mode (all targets allowed).
    Use at end of engagement.
    """
    clear_scope()
    audit.info("scope_clear")
    return {"mode": "lab (all targets allowed)", "scope": []}


# ── MCP Prompts — reusable workflow templates ─────────────────────────────────

@mcp.prompt()
def recon_domain(domain: str) -> str:
    """Full reconnaissance workflow for a domain."""
    return f"""Perform comprehensive reconnaissance on the domain: {domain}

Run these steps in order:
1. whois_lookup("{domain}") — gather registrar and contact info
2. dig_lookup("{domain}", "A") and dig_lookup("{domain}", "NS") — resolve IPs and nameservers
3. dig_lookup("{domain}", "MX") and dig_lookup("{domain}", "TXT") — mail and SPF records
4. subfinder_enumerate("{domain}") — passive subdomain enumeration (async, poll job)
5. theharvester_search("{domain}") — OSINT: emails, subdomains, IPs (async, poll job)
6. amass_enum("{domain}", passive=True) — deep subdomain enumeration (async, poll job)

After all jobs complete, call generate_report([job_ids]) with all async job IDs.
Always check scope_list() first to confirm {domain} is authorized."""


@mcp.prompt()
def web_pentest(url: str) -> str:
    """Web application penetration testing workflow."""
    return f"""Perform web application penetration testing on: {url}

Run these steps in order:
1. nmap_port_scan(target, ports="80,443,8080,8443") — confirm web ports open
2. nikto_scan("{url}") — web server vulnerability scan (async)
3. gobuster_dir("{url}") — directory and file brute-force (async)
4. gobuster_vhost("{url}") — virtual host discovery (async)
5. ffuf_fuzz("{url}/FUZZ") — fast endpoint fuzzing (async)
6. nuclei_scan("{url}", severity="medium,high,critical") — template-based vuln scan (async)
7. If WordPress detected: wpscan_scan("{url}") (async)
8. If login forms found: sqlmap_scan(url_with_param) for SQL injection (async)

Wait for all jobs, then generate_report([all_job_ids]).
Always check scope_list() first."""


@mcp.prompt()
def smb_enum(target: str) -> str:
    """SMB/NetBIOS enumeration workflow for Windows/Samba hosts."""
    return f"""Perform SMB enumeration on host: {target}

Run these steps in order:
1. nmap_port_scan("{target}", ports="135,139,445") — confirm SMB ports
2. smbclient_list_shares("{target}") — list accessible shares (anonymous)
3. enum4linux_scan("{target}") — full SMB enumeration: users, shares, groups, policy (async)
4. nmap_vuln_scan("{target}", ports="445", scripts="smb-vuln-ms17-010,smb-security-mode,smb2-security-mode") — check for EternalBlue and SMB misconfigs (async)

If credentials found during enumeration, re-run smbclient_list_shares with creds.
Always check scope_list() first."""


if __name__ == "__main__":
    mcp.run(transport="stdio")
