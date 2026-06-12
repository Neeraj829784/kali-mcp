from config import TOOL_TIMEOUTS
from scope import check_scope


def _register(mcp, job_mgr):

    @mcp.tool()
    async def subfinder_enumerate(
        domain: str,
        all_sources: bool = False,
        threads: int = 10,
        output_json: bool = True,
    ) -> dict:
        """
        Passive subdomain enumeration using subfinder.
        domain: target domain (e.g. 'example.com')
        all_sources: use all available sources (slower but thorough)
        threads: concurrent goroutines for resolving (default 10)
        output_json: return JSONL output for structured parsing
        """
        check_scope(domain)
        cmd = ["subfinder", "-d", domain, "-t", str(threads), "-silent"]
        if all_sources:
            cmd += ["-all"]
        if output_json:
            cmd += ["-oJ"]
        return await job_mgr.run_and_wait("subfinder", cmd, TOOL_TIMEOUTS["subfinder"])
