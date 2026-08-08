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


async def run_hunt(scope: str, recon_fn, verify_fn, extra_phase=None,
                   errors: list[str] | None = None) -> dict:
    """Orchestrate a single-program hunt.

    recon_fn(scope) -> list[str] of live assets/URLs to test.
    verify_fn(asset) -> {"checks": [vuln_class,...], "verifications": [oracle result,...]}
    extra_phase(scope) -> ([coverage_item,...], [verification,...]) — optional extra
        pass (e.g. parameter-injection oracles over harvested URLs).
    All are injected so this is fully testable offline. Never raises: per-asset and
    phase errors are collected into the report.
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

    if extra_phase is not None:
        try:
            extra_cov, extra_ver = await extra_phase(scope)
            coverage.extend(extra_cov or [])
            verifications.extend(extra_ver or [])
        except Exception as e:
            errs.append(f"injection phase: {e}")

    return build_report(scope, assets, coverage, verifications, errs)


def render_report_markdown(report: dict) -> str:
    """Render a hunt report dict as a readable Markdown document."""
    s = report.get("summary", {})
    out = [
        f"# Hunt Report — {report.get('scope', '')}",
        "",
        f"- Assets discovered: **{s.get('assets_discovered', 0)}**",
        f"- Checks run: **{s.get('checks_run', 0)}**",
        f"- Confirmed findings: **{s.get('confirmed_findings', 0)}**",
        f"- Needs human review: **{s.get('needs_human_review', 0)}**",
        "",
        "## Confirmed findings (proven)",
    ]
    conf = report.get("confirmed_findings", [])
    if not conf:
        out.append("_None proven in this run._")
    for f in conf:
        out.append(f"### {f.get('vuln_class', '?')} — {f.get('url', '')}")
        out.append(f"- **Proof:** {f.get('proof', '')}")
        req = f.get("request")
        if req:
            out.append(f"- **Request:** `{req.get('method', '')} {req.get('url', '')}`")
        if f.get("response"):
            out.append(f"- **Response:** `{f.get('response')}`")
        out.append("")
    out.append("## Needs human review (unproven leads)")
    nh = report.get("needs_human_review", [])
    if not nh:
        out.append("_None._")
    for f in nh:
        out.append(f"- {f.get('vuln_class', '?')} @ {f.get('url', '')} — {f.get('proof', '')}")
    errs = report.get("errors", [])
    if errs:
        out += ["", "## Errors"] + [f"- {e}" for e in errs]
    return "\n".join(out)
