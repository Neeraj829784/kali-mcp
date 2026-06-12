from scope import check_scope
from tools.base import ToolExecutor

_ex = ToolExecutor()


def _register(mcp, job_mgr):

    @mcp.tool()
    async def whois_lookup(target: str) -> dict:
        """
        WHOIS lookup for a domain or IP address.
        target: domain (e.g. 'example.com') or IP address
        """
        check_scope(target)
        return await _ex.run(["whois", target], timeout=30)
