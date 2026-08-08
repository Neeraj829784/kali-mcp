"""katana — next-generation web crawler (ProjectDiscovery)."""
from config import TOOL_TIMEOUTS
from scope import check_scope
from tools.base import guard_token


def _register(mcp, job_mgr):

    @mcp.tool()
    async def katana_crawl(
        url: str,
        depth: int = 3,
        js_crawl: bool = True,
        concurrency: int = 10,
        rate_limit: int = 150,
        headless: bool = False,
        crawl_duration: str = "",
    ) -> dict:
        """
        Crawl a web application with katana (ProjectDiscovery) to discover
        endpoints, including those referenced only in JavaScript.
        url: starting URL (e.g. 'https://example.com')
        depth: maximum crawl depth (default 3)
        js_crawl: parse and crawl endpoints found in JavaScript (default True)
        concurrency: concurrent fetchers (default 10)
        rate_limit: max requests per second (default 150)
        headless: use a headless browser (experimental, catches JS-rendered links)
        crawl_duration: optional cap like '30s', '5m', '1h'
        Returns discovered URLs as JSONL on stdout.
        """
        try:
            guard_token(url, "url")
        except ValueError as e:
            return {"error": str(e), "return_code": -1}
        check_scope(url)
        cmd = ["katana", "-u", url, "-d", str(depth),
               "-c", str(concurrency), "-rl", str(rate_limit), "-silent", "-jsonl"]
        if js_crawl:
            cmd += ["-jc"]
        if headless:
            cmd += ["-hl"]
        if crawl_duration:
            cmd += ["-ct", crawl_duration]
        return await job_mgr.run_and_wait("katana", cmd, TOOL_TIMEOUTS["katana"], target=url)
