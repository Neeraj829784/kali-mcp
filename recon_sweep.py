"""
Passive recon sweep — continuous change detection (Phase 2, piece 2).

Runs passive-only recon tools (subfinder, amass -passive, theHarvester) against a
domain within the active program scope, ingests every result under a scan-run id,
then diffs the run against the previous one and reports only what changed.

This is the "what's new since last time?" workflow: new subdomains, new IPs/ports,
new endpoints, new vulns, and assets that disappeared. Newly-appeared assets are
surfaced as high-priority because freshly-deployed surface is often less tested.

Passive-only by design so it is safe to run repeatedly/unattended without tripping
WAFs or violating rules of engagement.
"""
import asyncio

import asset_inventory
from scope import check_scope

# Passive tools and the command each runs. Tool NAME keys must match the
# extractor keys in findings.py so run_and_wait auto-parses their output.
_PASSIVE_TOOLS = {
    "subfinder": lambda d: ["subfinder", "-d", d, "-silent"],
    "amass": lambda d: ["amass", "enum", "-passive", "-d", d, "-timeout", "5"],
    "theharvester": lambda d: [
        "theHarvester", "-d", d, "-l", "300",
        "-b", "crtsh,hackertarget,otx,rapiddns,urlscan,duckduckgo",
    ],
}
_TOOL_TIMEOUTS = {"subfinder": 300, "amass": 600, "theharvester": 300}
# theHarvester's binary name differs from its extractor key.
_TOOL_NAME_FOR_RUN = {"theharvester": "theharvester"}


def normalize_recon_findings(findings: list[dict], domain: str) -> list[dict]:
    """Pure transform: turn 'Subdomain discovered: X' findings into host=X records.

    Passive tools attribute subdomain findings to the parent domain (host=domain,
    subdomain in the title/evidence). For change detection we want each discovered
    subdomain to be its own host so a NEW subdomain shows up as a NEW asset.
    Non-subdomain findings (emails, etc.) pass through unchanged.
    Fully unit-testable — no I/O.
    """
    out: list[dict] = []
    for f in findings:
        title = str(f.get("title", ""))
        if title.lower().startswith("subdomain discovered:"):
            # evidence is either 'sub.example.com' or 'sub.example.com -> 1.2.3.4'
            evidence = str(f.get("evidence", "")).strip()
            sub = evidence.split()[0].strip() if evidence else ""
            # fall back to parsing the title after the colon
            if not sub or "." not in sub:
                sub = title.split(":", 1)[1].strip().split()[0] if ":" in title else ""
            if sub and "." in sub:
                nf = dict(f)
                nf["host"] = sub
                nf["title"] = f"Subdomain: {sub}"
                nf["severity"] = "info"
                nf.setdefault("service", "")
                out.append(nf)
                continue
        # pass through unchanged (keep parent-domain attribution)
        if not f.get("host"):
            f = {**f, "host": domain}
        out.append(f)
    return out


async def _run_passive_tools(job_mgr, domain: str, tools: list[str],
                             tool_budget: int) -> tuple[list[dict], dict]:
    """Run the requested passive tools and collect their findings.

    Returns (findings, per_tool_status). Isolated so tests can monkeypatch
    job_mgr.run_and_wait and avoid real network calls.
    """
    findings: list[dict] = []
    status: dict = {}
    ran = 0
    for tool in tools:
        if tool not in _PASSIVE_TOOLS:
            status[tool] = "skipped (not a passive tool)"
            continue
        if tool_budget and ran >= tool_budget:
            status[tool] = "skipped (budget exhausted)"
            continue
        cmd = _PASSIVE_TOOLS[tool](domain)
        run_name = _TOOL_NAME_FOR_RUN.get(tool, tool)
        try:
            result = await job_mgr.run_and_wait(
                run_name, cmd, _TOOL_TIMEOUTS.get(tool, 300), target=domain
            )
        except Exception as e:  # a single tool failure must not abort the sweep
            status[tool] = f"error: {e}"
            continue
        ran += 1
        tool_findings = result.get("findings", []) or []
        findings.extend(tool_findings)
        status[tool] = {
            "job_status": result.get("status"),
            "findings": len(tool_findings),
        }
    return findings, status


async def sweep(job_mgr, domain: str, program: str = "",
                tools: list[str] | None = None, tool_budget: int = 0) -> dict:
    """
    Run a passive recon sweep and return the change report vs the previous run.

    domain: target domain (must be in the active program scope)
    program: program name to group runs under (defaults to the domain)
    tools: which passive tools to run (default: all)
    tool_budget: max number of tools to run this sweep (0 = no limit)
    """
    check_scope(domain)  # enforces active program in/out-of-scope
    program = program or domain
    tools = tools or list(_PASSIVE_TOOLS.keys())

    run_id = await asset_inventory.start_run(program, "passive",
                                             notes=f"passive sweep of {domain}")
    raw_findings, tool_status = await _run_passive_tools(job_mgr, domain, tools, tool_budget)
    normalized = normalize_recon_findings(raw_findings, domain)
    await asset_inventory.auto_ingest_findings(normalized, host=domain, run_id=run_id)
    run_summary = await asset_inventory.finish_run(run_id)

    # Diff against the previous completed run for this program
    recent = await asset_inventory.latest_runs(program, limit=2)
    result: dict = {
        "domain": domain,
        "program": program,
        "run_id": run_id,
        "tools": tool_status,
        "observed": run_summary,
    }
    if len(recent) < 2:
        result["baseline"] = True
        result["note"] = "First run for this program — baseline established, no diff yet."
        return result

    curr, prev = recent[0], recent[1]
    report = await asset_inventory.compare_runs(prev["id"], curr["id"])
    changes = report.get("changes", {})
    priority_new = []
    for t in ("host", "service"):
        priority_new.extend(changes.get(t, {}).get("new", []))
    result["baseline"] = False
    result["changes"] = changes
    result["total_changes"] = report.get("total_changes", 0)
    result["priority_new_assets"] = priority_new
    return result


def _register(mcp, job_mgr):

    @mcp.tool()
    async def recon_sweep(
        domain: str,
        program: str = "",
        tools: list[str] | None = None,
        tool_budget: int = 0,
    ) -> dict:
        """
        Passive recon sweep with change detection.

        Runs passive-only recon (subfinder, amass -passive, theHarvester) against
        a domain, records everything under a scan run, then reports what changed
        since the previous sweep: new subdomains, new IPs/ports, new endpoints,
        new vulnerabilities, and assets that disappeared.

        Safe to run repeatedly/unattended (passive only). Newly-appeared assets
        are surfaced under 'priority_new_assets' because fresh surface is often
        less tested.

        domain: target domain (must be within the active program scope)
        program: program name to group runs under (defaults to the domain)
        tools: subset of ['subfinder','amass','theharvester'] (default: all)
        tool_budget: max number of tools to run this sweep (0 = no limit)
        """
        return await sweep(job_mgr, domain, program, tools, tool_budget)
