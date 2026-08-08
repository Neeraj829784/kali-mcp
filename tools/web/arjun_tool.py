"""arjun — HTTP parameter discovery."""
from config import TOOL_TIMEOUTS
from scope import check_scope
from tools.base import guard_token

_METHODS = {"GET", "POST", "JSON", "XML"}


def _register(mcp, job_mgr):

    @mcp.tool()
    async def arjun_params(
        url: str,
        method: str = "GET",
        threads: int = 5,
        stable: bool = False,
        headers: str = "",
        delay: int = 0,
    ) -> dict:
        """
        Discover hidden HTTP parameters on an endpoint using arjun.
        url: target URL (e.g. 'https://example.com/api/item')
        method: GET, POST, JSON, or XML (default GET)
        threads: concurrent threads (default 5)
        stable: prefer stability over speed (fewer false positives)
        headers: extra headers, newline-separated (e.g. 'Authorization: Bearer x')
        delay: delay between requests in seconds
        Returns the discovered parameters on stdout.
        """
        m = method.upper().strip()
        if m not in _METHODS:
            return {"error": f"method must be one of {sorted(_METHODS)}", "return_code": -1}
        try:
            guard_token(url, "url")
        except ValueError as e:
            return {"error": str(e), "return_code": -1}
        check_scope(url)
        cmd = ["arjun", "-u", url, "-m", m, "-t", str(threads)]
        if delay:
            cmd += ["-d", str(delay)]
        if stable:
            cmd += ["--stable"]
        if headers:
            cmd += ["--headers", headers]
        return await job_mgr.run_and_wait("arjun", cmd, TOOL_TIMEOUTS["arjun"], target=url)
