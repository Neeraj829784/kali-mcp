import os

from config import TOOL_TIMEOUTS, find_wordlist
from scope import check_scope


def _resolve_wordlist(path: str, key: str) -> str:
    """Use provided path if it exists, otherwise fall back to known locations."""
    if path and os.path.exists(path):
        return path
    try:
        return find_wordlist(key)
    except FileNotFoundError as e:
        raise ValueError(str(e))


def _register(mcp, job_mgr):

    @mcp.tool()
    async def gobuster_dir(
        url: str,
        wordlist: str = "",
        extensions: str = "",
        threads: int = 10,
        exclude_codes: str = "404",
        follow_redirect: bool = False,
    ) -> dict:
        """
        Directory and file brute-force using Gobuster.
        url: target URL (e.g. 'http://example.com')
        wordlist: path to wordlist (auto-selects common.txt from dirb/seclists if empty)
        extensions: file extensions to search e.g. 'php,html,txt'
        threads: concurrent threads (default 10)
        exclude_codes: HTTP codes to hide (default '404'), use '' to show all
        follow_redirect: follow 3xx redirects
        """
        check_scope(url)
        wl = _resolve_wordlist(wordlist, "dirb_common")
        cmd = ["gobuster", "dir", "-u", url, "-w", wl, "-t", str(threads), "--no-error", "-q"]
        if exclude_codes:
            cmd += ["-b", exclude_codes]
        if extensions:
            cmd += ["-x", extensions]
        if follow_redirect:
            cmd += ["-r"]
        return await job_mgr.run_and_wait("gobuster_dir", cmd, TOOL_TIMEOUTS["gobuster_dir"])

    @mcp.tool()
    async def gobuster_dns(
        domain: str,
        wordlist: str = "",
        threads: int = 10,
        show_ips: bool = False,
    ) -> dict:
        """
        DNS subdomain brute-force using Gobuster.
        domain: target domain (e.g. 'example.com')
        wordlist: path to wordlist (auto-selects subdomains list from seclists if empty)
        show_ips: show IP addresses of found subdomains
        """
        check_scope(domain)
        wl = _resolve_wordlist(wordlist, "dns_subdomains")
        cmd = ["gobuster", "dns", "-d", domain, "-w", wl, "-t", str(threads), "-q"]
        if show_ips:
            cmd += ["-i"]
        return await job_mgr.run_and_wait("gobuster_dns", cmd, TOOL_TIMEOUTS["gobuster_dns"])

    @mcp.tool()
    async def gobuster_vhost(
        url: str,
        wordlist: str = "",
        threads: int = 10,
        append_domain: bool = False,
    ) -> dict:
        """
        Virtual host discovery using Gobuster.
        url: base URL (e.g. 'http://example.com')
        wordlist: path to wordlist (auto-selects if empty)
        append_domain: append base domain to each vhost word
        """
        check_scope(url)
        wl = _resolve_wordlist(wordlist, "dirb_common")
        cmd = ["gobuster", "vhost", "-u", url, "-w", wl, "-t", str(threads), "-q"]
        if append_domain:
            cmd += ["--append-domain"]
        return await job_mgr.run_and_wait("gobuster_vhost", cmd, TOOL_TIMEOUTS["gobuster_vhost"])
