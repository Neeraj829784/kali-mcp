"""Screenshot tool using gowitness for visual web recon."""
import os
import tempfile

from config import ARTIFACTS_DIR, TOOL_TIMEOUTS
from scope import check_scope


def _register(mcp, job_mgr):

    @mcp.tool()
    async def screenshot_url(
        url: str,
        timeout: int = 30,
    ) -> dict:
        """
        Take a screenshot of a single web URL using gowitness.
        Useful for quick visual triage of login panels, admin interfaces, etc.
        url: target URL (e.g. 'http://example.com/admin')
        timeout: per-request timeout in seconds
        Returns: path to saved screenshot PNG file
        """
        check_scope(url)
        screenshots_dir = os.path.join(ARTIFACTS_DIR, "screenshots")
        os.makedirs(screenshots_dir, exist_ok=True)
        cmd = [
            "gowitness", "scan", "single",
            "--url", url,
            "--screenshot-path", screenshots_dir,
            "--timeout", str(timeout),
            "--write-jsonl", os.path.join(screenshots_dir, "results.jsonl"),
            "--quiet",
        ]
        result = await job_mgr.run_and_wait("gowitness", cmd, TOOL_TIMEOUTS.get("default", 120))
        # Find the screenshot file
        screenshots = [
            os.path.join(screenshots_dir, f)
            for f in os.listdir(screenshots_dir)
            if f.endswith(".png")
        ]
        result["screenshot_dir"] = screenshots_dir
        result["screenshots"] = sorted(screenshots)
        return result

    @mcp.tool()
    async def screenshot_urls(
        urls: list[str],
        threads: int = 4,
        timeout: int = 30,
    ) -> dict:
        """
        Take screenshots of multiple URLs using gowitness.
        Use after gobuster/crawl to visually triage all discovered endpoints at once.
        urls: list of URLs to screenshot
        threads: concurrent screenshot workers (default 4)
        timeout: per-request timeout in seconds
        Returns: directory containing all PNG screenshots + JSONL results
        """
        for url in urls:  # every URL must be in scope
            check_scope(url)

        screenshots_dir = os.path.join(ARTIFACTS_DIR, "screenshots")
        os.makedirs(screenshots_dir, exist_ok=True)

        # Write URLs to temp file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, dir=ARTIFACTS_DIR
        ) as f:
            f.write("\n".join(urls))
            url_file = f.name

        cmd = [
            "gowitness", "scan", "file",
            "--file", url_file,
            "--screenshot-path", screenshots_dir,
            "--threads", str(threads),
            "--timeout", str(timeout),
            "--write-jsonl", os.path.join(screenshots_dir, "results.jsonl"),
            "--quiet",
        ]
        result = await job_mgr.run_and_wait("gowitness", cmd, TOOL_TIMEOUTS.get("default", 120) * len(urls) // 4 + 60)
        os.unlink(url_file)

        screenshots = [
            os.path.join(screenshots_dir, f)
            for f in os.listdir(screenshots_dir)
            if f.endswith(".png")
        ]
        result["screenshot_dir"] = screenshots_dir
        result["screenshots"] = sorted(screenshots)
        result["count"] = len(screenshots)
        return result
