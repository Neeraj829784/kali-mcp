"""gau — passive URL discovery from web archives (Wayback, CommonCrawl, OTX, URLScan)."""
from config import TOOL_TIMEOUTS
from scope import check_scope
from tools.base import guard_token


def _register(mcp, job_mgr):

    @mcp.tool()
    async def gau_urls(
        domain: str,
        include_subs: bool = True,
        providers: str = "",
        match_codes: str = "",
        threads: int = 5,
        from_date: str = "",
        to_date: str = "",
    ) -> dict:
        """
        Fetch known URLs for a domain from public archives using gau
        (getallurls). Passive — pulls from Wayback Machine, CommonCrawl, OTX,
        and URLScan without touching the target. Great for finding forgotten
        endpoints and parameters.
        domain: target domain (e.g. 'example.com')
        include_subs: also include URLs for subdomains
        providers: comma-separated subset of wayback,commoncrawl,otx,urlscan
        match_codes: keep only these HTTP status codes (e.g. '200,301')
        threads: worker count (default 5)
        from_date / to_date: limit to a date range, format YYYYMM
        Returns one URL per line on stdout.
        """
        try:
            guard_token(domain, "domain")
        except ValueError as e:
            return {"error": str(e), "return_code": -1}
        check_scope(domain)
        cmd = ["gau", "--threads", str(threads)]
        if include_subs:
            cmd += ["--subs"]
        if providers:
            cmd += ["--providers", providers]
        if match_codes:
            cmd += ["--mc", match_codes]
        if from_date:
            cmd += ["--from", from_date]
        if to_date:
            cmd += ["--to", to_date]
        cmd += [domain]
        return await job_mgr.run_and_wait("gau", cmd, TOOL_TIMEOUTS["gau"], target=domain)
