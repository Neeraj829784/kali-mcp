"""LinkFinder — extract endpoints/links from JavaScript.

LinkFinder has no clean system package; it is run from a git checkout via its
own venv. Locations are overridable with env vars so deployments can relocate it:
  KALI_MCP_LINKFINDER_DIR    (default: ~/tools/LinkFinder)
"""
import os

from config import TOOL_TIMEOUTS
from scope import check_scope
from tools.base import ToolExecutor, guard_token

_ex = ToolExecutor()

_LF_DIR = os.environ.get("KALI_MCP_LINKFINDER_DIR", os.path.expanduser("~/tools/LinkFinder"))
_LF_SCRIPT = os.path.join(_LF_DIR, "linkfinder.py")
_LF_PYTHON = os.path.join(_LF_DIR, ".venv", "bin", "python")


def _register(mcp, job_mgr):

    @mcp.tool()
    async def linkfinder_extract(
        input_url: str,
        domain_mode: bool = False,
        regex: str = "",
        cookies: str = "",
        timeout: int = 10,
    ) -> dict:
        """
        Extract endpoints and links from JavaScript files using LinkFinder.
        input_url: a URL, a .js file URL, a local file, or a folder wildcard
                   (e.g. 'https://example.com/app.js')
        domain_mode: treat input as a domain/page and recursively parse all its JS
        regex: optional regex to filter endpoints (e.g. '^/api/')
        cookies: cookies for fetching authenticated JS
        timeout: per-request timeout in seconds
        Returns extracted endpoints as CLI text on stdout.
        """
        try:
            guard_token(input_url, "input_url")
        except ValueError as e:
            return {"error": str(e), "return_code": -1}
        # Only scope-check network inputs; local file/folder inputs are allowed.
        if input_url.startswith("http://") or input_url.startswith("https://"):
            check_scope(input_url)
        python = _LF_PYTHON if os.path.exists(_LF_PYTHON) else "python3"
        cmd = [python, _LF_SCRIPT, "-i", input_url, "-o", "cli", "-t", str(timeout)]
        if domain_mode:
            cmd += ["-d"]
        if regex:
            cmd += ["-r", regex]
        if cookies:
            cmd += ["-c", cookies]
        return await _ex.run(cmd, timeout=TOOL_TIMEOUTS["linkfinder"], tool_name="linkfinder")
