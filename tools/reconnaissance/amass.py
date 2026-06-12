from config import TOOL_TIMEOUTS
from scope import check_scope


def _register(mcp, job_mgr):

    @mcp.tool()
    async def amass_enum(
        domain: str,
        passive: bool = True,
        brute_force: bool = False,
        timeout_mins: int = 5,
    ) -> dict:
        """
        In-depth subdomain enumeration using OWASP Amass.
        domain: target domain (e.g. 'example.com')
        passive: passive-only mode (no active probing) — safer, faster
        brute_force: enable brute-force subdomain discovery (slow)
        timeout_mins: max runtime in minutes (default 5)
        """
        check_scope(domain)
        cmd = ["amass", "enum", "-d", domain, "-timeout", str(timeout_mins)]
        if passive:
            cmd += ["-passive"]
        if brute_force:
            cmd += ["-brute"]
        return await job_mgr.run_and_wait("amass", cmd, TOOL_TIMEOUTS["amass"])
