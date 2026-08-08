"""dnsx — fast DNS resolution / record lookup (ProjectDiscovery)."""
from config import TOOL_TIMEOUTS
from scope import check_scope
from tools.base import guard_token

_RECORDS = {"a", "aaaa", "cname", "ns", "txt", "ptr", "mx"}


def _register(mcp, job_mgr):

    @mcp.tool()
    async def dnsx_resolve(
        targets: str,
        record_type: str = "a",
        show_response: bool = True,
    ) -> dict:
        """
        Fast DNS resolution / record lookup using dnsx (ProjectDiscovery).
        targets: hostname(s) to resolve — single or comma-separated
                 (e.g. 'a.example.com,b.example.com')
        record_type: a, aaaa, cname, ns, txt, ptr, mx (default 'a')
        show_response: include the resolved record values in output
        Returns JSONL (one line per host) on stdout.
        """
        rt = record_type.lower().strip()
        if rt not in _RECORDS:
            return {"error": f"record_type must be one of {sorted(_RECORDS)}", "return_code": -1}
        hosts = [h.strip() for h in targets.split(",") if h.strip()]
        if not hosts:
            return {"error": "no targets provided", "return_code": -1}
        for h in hosts:
            try:
                guard_token(h, "target")
            except ValueError as e:
                return {"error": str(e), "return_code": -1}
            check_scope(h)
        cmd = ["dnsx", "-l", ",".join(hosts), f"-{rt}", "-silent", "-j"]
        if show_response:
            cmd += ["-resp"]
        return await job_mgr.run_and_wait("dnsx", cmd, TOOL_TIMEOUTS["dnsx"], target=hosts[0])
