from config import TOOL_TIMEOUTS
from scope import check_scope

# Sources verified working without API keys in current theHarvester version
_SAFE_SOURCES = "crtsh,duckduckgo,hackertarget,otx,rapiddns,urlscan,commoncrawl"


def _register(mcp, job_mgr):

    @mcp.tool()
    async def theharvester_search(
        domain: str,
        source: str = _SAFE_SOURCES,
        limit: int = 500,
        dns_resolve: bool = False,
    ) -> dict:
        """
        OSINT gathering using theHarvester (emails, subdomains, IPs, URLs).
        domain: target domain or company name
        source: comma-separated data sources. Defaults to sources that work
                without API keys. Full list: google, bing, linkedin, github,
                dnsdumpster, crtsh, hackertarget, otx, rapiddns, shodan (needs key),
                sublist3r, threatminer, urlscan, duckduckgo
                Use 'all' only if you have API keys configured.
        limit: max search results (default 500)
        dns_resolve: perform DNS resolution on discovered subdomains
        """
        check_scope(domain)
        cmd = ["theHarvester", "-d", domain, "-l", str(limit), "-b", source]
        if dns_resolve:
            cmd += ["-r"]
        return await job_mgr.run_and_wait("theharvester", cmd, TOOL_TIMEOUTS["theharvester"])
