"""Autonomous single-program hunt — orchestration + confirmed-findings report.

Pure assembly helpers (split_verifications, build_report) have no I/O and are
unit-tested. The async orchestrator (run_hunt) takes injected phase callables so
it is testable offline and reuses the existing recon/scan/verify tools at runtime.
"""


def split_verifications(results: list[dict]) -> tuple[list[dict], list[dict]]:
    """Split oracle results into (confirmed, needs_human).

    confirmed  = oracle returned confirmed is True (proven, with proof pack)
    needs_human = confirmed is False/None (unproven leads to review manually)
    """
    confirmed, needs_human = [], []
    for r in results or []:
        if r.get("confirmed") is True:
            confirmed.append(r)
        else:
            needs_human.append(r)
    return confirmed, needs_human


def build_report(scope: str, assets: list[str], coverage: list[dict],
                 verifications: list[dict], errors: list[str] | None = None) -> dict:
    """Assemble the final confirmed-findings-with-proof report.

    scope: program scope tested
    assets: live assets/URLs discovered
    coverage: list of {"target": url, "checks": [vuln_class, ...]} — the honest
              ledger of what was tested where
    verifications: oracle result dicts (each {vuln_class, url, confirmed, proof, ...})
    errors: any phase errors encountered
    """
    confirmed, needs_human = split_verifications(verifications)
    checks_run = sum(len(c.get("checks", [])) for c in coverage)
    return {
        "scope": scope,
        "summary": {
            "assets_discovered": len(assets),
            "checks_run": checks_run,
            "confirmed_findings": len(confirmed),
            "needs_human_review": len(needs_human),
        },
        "confirmed_findings": confirmed,     # proven bugs, each with its proof pack
        "needs_human_review": needs_human,   # unproven leads for manual verification
        "coverage": coverage,                # what was tested where (honesty ledger)
        "assets": assets,
        "errors": errors or [],
    }


async def run_hunt(scope: str, recon_fn, verify_fn, errors: list[str] | None = None) -> dict:
    """Orchestrate a single-program hunt.

    recon_fn(scope) -> list[str] of live assets/URLs to test.
    verify_fn(asset) -> {"checks": [vuln_class,...], "verifications": [oracle result,...]}
    Both are injected so this is fully testable offline and reuses the real
    recon/verify tools at runtime. Never raises: per-asset errors are collected.
    """
    errs = list(errors or [])
    try:
        assets = await recon_fn(scope)
    except Exception as e:
        return build_report(scope, [], [], [], errs + [f"recon failed: {e}"])

    coverage: list[dict] = []
    verifications: list[dict] = []
    for asset in assets:
        try:
            res = await verify_fn(asset) or {}
            coverage.append({"target": asset, "checks": res.get("checks", [])})
            verifications.extend(res.get("verifications", []))
        except Exception as e:
            errs.append(f"{asset}: {e}")
    return build_report(scope, assets, coverage, verifications, errs)
