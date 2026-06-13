from config import TOOL_TIMEOUTS, find_wordlist
from scope import check_scope


def _register(mcp, job_mgr):

    @mcp.tool()
    async def ffuf_fuzz(
        url: str,
        wordlist: str = "",
        keyword: str = "FUZZ",
        match_codes: str = "200,204,301,302,307,401,403",
        filter_codes: str = "",
        threads: int = 40,
        data: str = "",
        method: str = "GET",
        headers: str = "",
        auto_calibrate: bool = False,
    ) -> dict:
        """
        Fast web fuzzer using ffuf. Place FUZZ keyword in URL, headers, or POST data.
        url: target URL with FUZZ keyword (e.g. 'http://example.com/FUZZ')
        wordlist: path to wordlist (auto-selects common.txt if empty)
        keyword: fuzzing placeholder (default FUZZ)
        match_codes: show responses matching these HTTP codes
        filter_codes: hide responses with these HTTP codes
        threads: concurrent threads (default 40)
        data: POST data — setting this switches to POST automatically
        method: HTTP method GET/POST/PUT/DELETE/PATCH
        headers: extra header e.g. 'Authorization: Bearer <token>'
        auto_calibrate: auto-filter similar responses to reduce noise (-ac)
        """
        check_scope(url)
        wl = wordlist if wordlist else find_wordlist("dirb_common")
        cmd = ["ffuf", "-w", f"{wl}:{keyword}", "-u", url,
               "-t", str(threads), "-json"]
        if match_codes and not filter_codes:
            cmd += ["-mc", match_codes]
        if filter_codes:
            cmd += ["-fc", filter_codes]
        if data:
            cmd += ["-d", data, "-X", "POST"]
        elif method.upper() != "GET":
            cmd += ["-X", method.upper()]
        if headers:
            cmd += ["-H", headers]
        if auto_calibrate:
            cmd += ["-ac"]
        return await job_mgr.run_and_wait("ffuf", cmd, TOOL_TIMEOUTS["ffuf"])
