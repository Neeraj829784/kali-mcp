from config import TOOL_TIMEOUTS
from scope import check_scope


def _register(mcp, job_mgr):

    @mcp.tool()
    async def nikto_scan(
        target: str,
        port: int = 80,
        ssl: bool = False,
        max_time: str = "10m",
        timeout: int = 600,
    ) -> dict:
        """
        Web server vulnerability scan using Nikto.
        target: host or URL (e.g. 'example.com' or 'http://example.com')
        port: target port (default 80; use 443 with ssl=True)
        ssl: force SSL/HTTPS
        max_time: nikto's internal max scan time e.g. '10m', '20m', '1h'
        timeout: server-side timeout in seconds (default 600 = 10 min)
        """
        check_scope(target)
        cmd = ["nikto", "-h", target, "-p", str(port),
               "-maxtime", max_time, "-nointeractive"]
        if ssl:
            cmd += ["-ssl"]
        return await job_mgr.run_and_wait("nikto", cmd, timeout)
