"""asnmap — map ASN / IP / domain / org to announced network ranges (ProjectDiscovery)."""
from config import TOOL_TIMEOUTS
from scope import check_scope
from tools.base import ToolExecutor, guard_token

_ex = ToolExecutor()

_FLAGS = {"domain": "-d", "asn": "-a", "ip": "-i", "org": "-org"}


def _register(mcp, job_mgr):

    @mcp.tool()
    async def asnmap_lookup(query: str, query_type: str = "domain") -> dict:
        """
        Map an ASN / IP / domain / organization to its announced CIDR ranges
        using asnmap (ProjectDiscovery). Useful for expanding attack surface.
        query: value to look up (e.g. 'example.com', 'AS15169', '8.8.8.8', 'GOOGLE')
        query_type: one of 'domain', 'asn', 'ip', 'org' (default 'domain')
        Returns JSON with the network ranges.
        """
        qt = query_type.lower().strip()
        flag = _FLAGS.get(qt)
        if not flag:
            return {"error": f"query_type must be one of {sorted(_FLAGS)}", "return_code": -1}
        try:
            guard_token(query, "query")
        except ValueError as e:
            return {"error": str(e), "return_code": -1}
        if qt == "domain":
            check_scope(query)
        cmd = ["asnmap", flag, query, "-json", "-silent"]
        return await _ex.run(cmd, timeout=TOOL_TIMEOUTS["asnmap"], tool_name="asnmap")
