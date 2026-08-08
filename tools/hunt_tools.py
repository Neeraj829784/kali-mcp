"""Autonomous single-program hunt tool (safe / read-only first pass)."""
import os
import re
import tempfile
from urllib.parse import urlsplit, parse_qsl

import httpx

from config import TLS_VERIFY, TOOL_TIMEOUTS, DATA_DIR
from scope import check_scope
from tools.base import guard_token
import oracles
import hunt

# Oracles that need NO injection point — safe to run on any base URL.
_AUTO_CLASSES = ["cors", "git_exposure", "env_exposure"]
# Oracles that inject a (non-destructive, read-only) payload into a query param.
_INJECTION_CLASSES = ["open_redirect", "lfi", "reflected_xss", "ssti"]


def _register(mcp, job_mgr):

    @mcp.tool()
    async def hunt_program(scope: str, max_assets: int = 20, format: str = "json",
                           include_injection: bool = False) -> dict:
        """
        Autonomous single-program hunt. Discovers live hosts for a domain
        (subfinder -> httpx), then runs the no-injection proof oracles (CORS,
        exposed .git, exposed .env) on each. Returns a confirmed-findings-with-proof
        report + a coverage ledger + a needs-human list.

        scope: a domain (e.g. 'example.com') — must be in scope
        max_assets: cap on hosts / parameterized URLs to test (default 20)
        format: 'json' (default) or 'markdown' (adds a rendered `report_markdown`)
        include_injection: also harvest parameterized URLs (gau) and run the
            read-only injection oracles (open_redirect, LFI, reflected XSS, SSTI).
            Default False. These send non-destructive GET payloads only — still no
            exploitation, brute-force, state changes, or submission.
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

        async def injection_phase(domain: str):
            # Harvest parameterized URLs passively (gau), then run read-only
            # injection oracles on each (auto-injects into the first query param).
            try:
                g = await job_mgr.run_and_wait(
                    "gau", ["gau", "--subs", domain], TOOL_TIMEOUTS["gau"], target=domain)
                raw = [l.strip() for l in (g.get("stdout", "") or "").splitlines()
                       if l.strip().startswith("http") and "?" in l and "=" in l]
            except Exception:
                raw = []
            seen, cand = set(), []
            for u in raw:
                try:
                    check_scope(u)
                except Exception:
                    continue
                p = urlsplit(u)
                key = (p.netloc, p.path, tuple(sorted(k for k, _ in parse_qsl(p.query))))
                if key in seen:
                    continue
                seen.add(key)
                cand.append(u)
                if len(cand) >= max_assets:
                    break
            cov, ver = [], []
            async with httpx.AsyncClient(
                follow_redirects=False, timeout=10, verify=TLS_VERIFY,
                headers={"User-Agent": "Mozilla/5.0"},
            ) as client:
                for u in cand:
                    checks = []
                    for vc in _INJECTION_CLASSES:
                        try:
                            ver.append(await oracles.ORACLES[vc](client, u))
                            checks.append(vc)
                        except Exception as e:
                            ver.append({"vuln_class": vc, "url": u,
                                        "confirmed": None, "proof": f"error: {e}"})
                    cov.append({"target": u, "checks": checks})
            return (cov, ver)

        report = await hunt.run_hunt(
            scope, recon_fn, verify_fn,
            extra_phase=(injection_phase if include_injection else None))
        if format.lower() == "markdown":
            report["report_markdown"] = hunt.render_report_markdown(report)
        return report
