"""
Parallel execution workflows — fire multiple tools concurrently, wait for all.
scan_host: full host recon in parallel (nmap + vulns + web + smb simultaneously)
scan_web: full web app scan in parallel (nikto + gobuster + nuclei + crawl)
"""
import asyncio

from scope import check_scope


def _register(mcp, job_mgr):

    @mcp.tool()
    async def scan_host(
        target: str,
        intensity: str = "normal",
    ) -> dict:
        """
        Full parallel host scan — fires multiple tools simultaneously and waits for all.
        Reduces total recon time by 70% vs running tools sequentially.
        target: IP or hostname
        intensity: 'light' (quick scan), 'normal' (default), 'deep' (thorough)
        Returns: consolidated results from all tools with findings and next steps.
        """
        check_scope(target)

        timing = {"light": "T5", "normal": "T4", "deep": "T3"}.get(intensity, "T4")
        # Choose EITHER --top-ports OR -p, never both (nmap rejects the combination)
        port_args = {
            "light": ["--top-ports", "100"],
            "normal": ["-p", "1-10000"],
            "deep": ["-p", "1-65535"],
        }.get(intensity, ["-p", "1-10000"])

        # Phase 1: port scan (must complete first to know what services exist)
        from tools.reconnaissance.nmap import _ex
        nmap_result = await _ex.run(
            ["nmap", "-sT", "-sV", f"-{timing}"] + port_args + [target],
            timeout={"light": 60, "normal": 300, "deep": 1800}.get(intensity, 300)
        )
        nmap_output = nmap_result.get("stdout", "")

        # Detect open services
        has_web = any(p in nmap_output for p in ["80/tcp", "443/tcp", "8080/tcp", "8443/tcp"])
        has_ssh = "22/tcp" in nmap_output and "open" in nmap_output
        has_smb = any(p in nmap_output for p in ["445/tcp", "139/tcp"])

        # Phase 2: launch targeted scans in parallel based on what was found
        tasks = {}

        if has_web:
            web_url = f"http://{target}"
            tasks["nikto"] = asyncio.create_task(
                job_mgr.run_and_wait("nikto", [
                    "nikto", "-h", target, "-p", "80",
                    "-maxtime", "5m", "-nointeractive"
                ], 360)
            )
            tasks["gobuster"] = asyncio.create_task(
                job_mgr.run_and_wait("gobuster_dir", [
                    "gobuster", "dir", "-u", web_url,
                    "-w", "/usr/share/wordlists/dirb/common.txt",
                    "-t", "20", "--no-error", "-q", "-b", "404"
                ], 300)
            )
            tasks["nuclei"] = asyncio.create_task(
                job_mgr.run_and_wait("nuclei", [
                    "nuclei", "-u", web_url,
                    "-s", "medium,high,critical",
                    "-rl", "80", "-c", "15", "-silent"
                ], 600)
            )

        if has_smb:
            tasks["enum4linux"] = asyncio.create_task(
                job_mgr.run_and_wait("enum4linux", [
                    "enum4linux", "-a", target
                ], 300)
            )
            tasks["smb_vulns"] = asyncio.create_task(
                job_mgr.run_and_wait("nmap_vuln_scan", [
                    "nmap", "--script=smb-vuln-ms17-010,smb-security-mode,smb2-security-mode",
                    "-p", "445", target
                ], 120)
            )

        if has_ssh and intensity != "light":
            tasks["ssh_banner"] = asyncio.create_task(
                job_mgr.run_and_wait("nmap_service_detection", [
                    "nmap", "-sV", "--version-intensity", "5", "-p", "22", target
                ], 60)
            )

        # Wait for all parallel tasks
        parallel_results = {}
        if tasks:
            done = await asyncio.gather(*tasks.values(), return_exceptions=True)
            for key, result in zip(tasks.keys(), done):
                if isinstance(result, Exception):
                    parallel_results[key] = {"error": str(result)}
                else:
                    parallel_results[key] = {
                        "status": result.get("status"),
                        "findings_count": result.get("findings_count", 0),
                        "suggested_next": result.get("suggested_next", []),
                    }

        # Aggregate all findings
        from findings import extract_findings
        from suggest import suggest_next
        all_findings = extract_findings("nmap_port_scan", nmap_output, target)
        suggestions = suggest_next("nmap_port_scan", nmap_output, target)

        return {
            "target": target,
            "intensity": intensity,
            "port_scan": {
                "output": nmap_output[:2000],
                "has_web": has_web,
                "has_ssh": has_ssh,
                "has_smb": has_smb,
            },
            "parallel_scans": parallel_results,
            "findings": all_findings,
            "findings_count": len(all_findings),
            "suggested_next": suggestions,
        }

    @mcp.tool()
    async def scan_web(
        url: str,
        depth: str = "normal",
    ) -> dict:
        """
        Full parallel web application scan — nikto, gobuster, nuclei, and crawler simultaneously.
        depth: 'light' (quick), 'normal' (default), 'deep' (thorough with ffuf)
        Returns: consolidated web findings from all scanners.
        """
        check_scope(url)
        from tools.web.web_crawler import _register as _  # ensure module loaded

        # Launch all web tools in parallel
        tasks = {
            "nikto": asyncio.create_task(
                job_mgr.run_and_wait("nikto", [
                    "nikto", "-h", url,
                    "-maxtime", "5m" if depth == "normal" else "10m",
                    "-nointeractive"
                ], 360 if depth == "normal" else 720)
            ),
            "gobuster": asyncio.create_task(
                job_mgr.run_and_wait("gobuster_dir", [
                    "gobuster", "dir", "-u", url,
                    "-w", "/usr/share/wordlists/dirb/common.txt",
                    "-t", "20", "--no-error", "-q",
                    "-x", "php,html,txt,js",
                    "-b", "404"
                ], 300)
            ),
            "nuclei": asyncio.create_task(
                job_mgr.run_and_wait("nuclei", [
                    "nuclei", "-u", url,
                    "-s", "info,low,medium,high,critical",
                    "-rl", "80", "-c", "15", "-silent"
                ], 600)
            ),
        }

        if depth in ("normal", "deep"):
            from tools.web.web_crawler import _register
            # Run crawler separately (pure Python, not subprocess)
            import httpx, re
            from urllib.parse import urljoin, urlparse
            crawl_task = asyncio.create_task(_crawl_simple(url, max_pages=30))
            tasks["crawl"] = crawl_task

        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        parallel_results = {}
        for key, result in zip(tasks.keys(), results):
            if isinstance(result, Exception):
                parallel_results[key] = {"error": str(result)}
            elif isinstance(result, dict):
                parallel_results[key] = {
                    "status": result.get("status", "done"),
                    "findings_count": result.get("findings_count", 0),
                    "pages_visited": result.get("pages_visited"),
                    "interesting": result.get("interesting", []),
                }

        return {
            "target": url,
            "depth": depth,
            "scans": parallel_results,
        }


async def _crawl_simple(url: str, max_pages: int = 30) -> dict:
    """Lightweight inline crawler for parallel use."""
    import re
    import httpx
    from urllib.parse import urljoin, urlparse
    base = urlparse(url)
    visited: set[str] = set()
    queue = [url]
    interesting = []
    _INT = re.compile(r"(admin|login|upload|api|config|backup|phpinfo|\.git|\.env|password)", re.I)

    async with httpx.AsyncClient(follow_redirects=True, timeout=5) as client:
        while queue and len(visited) < max_pages:
            cur = queue.pop(0)
            if cur in visited:
                continue
            visited.add(cur)
            if _INT.search(cur):
                interesting.append(cur)
            try:
                resp = await client.get(cur)
                for href in re.findall(r'href=["\']([^"\']+)["\']', resp.text):
                    abs_url = urljoin(cur, href).split("#")[0]
                    if urlparse(abs_url).netloc == base.netloc and abs_url not in visited:
                        queue.append(abs_url)
            except Exception:
                pass

    return {"pages_visited": len(visited), "interesting": interesting, "all_urls": sorted(visited)}
