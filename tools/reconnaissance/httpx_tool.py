"""httpx — HTTP probing & enrichment (ProjectDiscovery).

NOTE: the ProjectDiscovery binary is invoked as `httpx-toolkit` on Kali because
the plain `httpx` name collides with the Python httpx library's CLI.
"""
from config import TOOL_TIMEOUTS
from scope import check_scope
from tools.base import guard_token


def _register(mcp, job_mgr):

    @mcp.tool()
    async def httpx_probe(
        targets: str,
        ports: str = "",
        follow_redirects: bool = False,
        match_codes: str = "",
        tech_detect: bool = True,
    ) -> dict:
        """
        Probe live HTTP/HTTPS services with httpx (ProjectDiscovery).
        Reports status code, page title, web server, technologies, CDN/WAF and IP.
        targets: host/URL or comma-separated list (e.g. 'example.com,api.example.com')
        ports: optional ports in nmap syntax (e.g. '80,443,8080-8090')
        follow_redirects: follow HTTP redirects
        match_codes: keep only these status codes (e.g. '200,301,403')
        tech_detect: run Wappalyzer technology detection (default True)
        Returns JSONL (one line per live host) on stdout.
        """
        hosts = [h.strip() for h in targets.split(",") if h.strip()]
        if not hosts:
            return {"error": "no targets provided", "return_code": -1}
        for h in hosts:
            try:
                guard_token(h, "target")
            except ValueError as e:
                return {"error": str(e), "return_code": -1}
            check_scope(h)
        cmd = ["httpx-toolkit", "-u", ",".join(hosts),
               "-silent", "-json", "-sc", "-title", "-web-server", "-ip", "-cdn"]
        if tech_detect:
            cmd += ["-td"]
        if follow_redirects:
            cmd += ["-fr"]
        if ports:
            cmd += ["-p", ports]
        if match_codes:
            cmd += ["-mc", match_codes]
        return await job_mgr.run_and_wait("httpx", cmd, TOOL_TIMEOUTS["httpx"], target=hosts[0])
