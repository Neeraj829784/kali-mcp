"""Autonomous single-program hunt tool (safe / read-only first pass)."""
import os
import re
import tempfile

import httpx

from config import TLS_VERIFY, TOOL_TIMEOUTS, DATA_DIR
from scope import check_scope
from tools.base import guard_token
import oracles
import hunt

# Oracles that need NO injection point — safe to run on any base URL.
_AUTO_CLASSES = ["cors", "git_exposure", "env_exposure"]


def _register(mcp, job_mgr):

    @mcp.tool()
    async def hunt_program(scope: str, max_assets: int = 20) -> dict:
        """
        Autonomous single-program hunt (SAFE, read-only). Discovers live hosts for
        a domain (subfinder -> httpx), then runs the no-injection proof oracles
        (CORS, exposed .git, exposed .env) on each, and returns a
        confirmed-findings-with-proof report + a coverage ledger + a needs-human list.

        scope: a domain (e.g. 'example.com') — must be in scope
        max_assets: cap on live hosts to test (default 20)

        This first pass runs ONLY safe read-only checks: it does not exploit,
        submit, brute-force, or send parameter-injection payloads.
        """
        try:
            guard_token(scope, "scope")
        except ValueError as e:
            return {"error": str(e), "return_code": -1}
        check_scope(scope)

        async def recon_fn(domain: str) -> list[str]:
            # 1) passive subdomain enumeration
            try:
                sf = await job_mgr.run_and_wait(
                    "subfinder", ["subfinder", "-d", domain, "-silent"],
                    TOOL_TIMEOUTS["subfinder"], target=domain)
                subs = [l.strip() for l in (sf.get("stdout", "") or "").splitlines() if l.strip()]
            except Exception:
                subs = []
            subs = (subs or [domain])[: max_assets * 3]
            # 2) probe which are live (httpx). Feed via a temp list file.
            fd, path = tempfile.mkstemp(prefix="hunt_", dir=DATA_DIR)
            try:
                with os.fdopen(fd, "w") as f:
                    f.write("\n".join(subs))
                hx = await job_mgr.run_and_wait(
                    "httpx", ["httpx-toolkit", "-l", path, "-silent"],
                    TOOL_TIMEOUTS["httpx"], target=domain)
            finally:
                try:
                    os.unlink(path)
                except OSError:
                    pass
            urls = [l.strip() for l in (hx.get("stdout", "") or "").splitlines()
                    if l.strip().startswith("http")]
            # de-dupe, cap
            seen, live = set(), []
            for u in urls:
                if u not in seen:
                    seen.add(u)
                    live.append(u)
            return live[:max_assets]

        async def verify_fn(url: str) -> dict:
            results = []
            async with httpx.AsyncClient(
                follow_redirects=False, timeout=10, verify=TLS_VERIFY,
                headers={"User-Agent": "Mozilla/5.0"},
            ) as client:
                for vc in _AUTO_CLASSES:
                    try:
                        results.append(await oracles.ORACLES[vc](client, url))
                    except Exception as e:
                        results.append({"vuln_class": vc, "url": url,
                                        "confirmed": None, "proof": f"error: {e}"})
            return {"checks": _AUTO_CLASSES, "verifications": results}

        return await hunt.run_hunt(scope, recon_fn, verify_fn)
