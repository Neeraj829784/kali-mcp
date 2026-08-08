"""Tests for the autonomous hunt report core (hunt.py) — offline."""
import hunt as H


def test_split_verifications():
    results = [
        {"vuln_class": "lfi", "confirmed": True, "proof": "root:..."},
        {"vuln_class": "xss", "confirmed": False, "proof": "escaped"},
        {"vuln_class": "ssti", "confirmed": None, "proof": "error"},
    ]
    confirmed, needs = H.split_verifications(results)
    assert len(confirmed) == 1 and confirmed[0]["vuln_class"] == "lfi"
    assert len(needs) == 2


def test_split_verifications_empty():
    assert H.split_verifications([]) == ([], [])
    assert H.split_verifications(None) == ([], [])


def test_build_report_structure():
    assets = ["https://a.example.com", "https://b.example.com"]
    coverage = [
        {"target": "https://a.example.com", "checks": ["cors", "lfi"]},
        {"target": "https://b.example.com", "checks": ["cors"]},
    ]
    verifications = [
        {"vuln_class": "lfi", "url": "https://a.example.com/read", "confirmed": True,
         "proof": "root:...:0:0:"},
        {"vuln_class": "cors", "url": "https://b.example.com", "confirmed": False,
         "proof": "no ACAO"},
    ]
    rep = H.build_report("*.example.com", assets, coverage, verifications, errors=["dns timeout"])
    assert rep["scope"] == "*.example.com"
    assert rep["summary"] == {
        "assets_discovered": 2,
        "checks_run": 3,               # 2 + 1
        "confirmed_findings": 1,
        "needs_human_review": 1,
    }
    assert rep["confirmed_findings"][0]["vuln_class"] == "lfi"
    assert rep["needs_human_review"][0]["vuln_class"] == "cors"
    assert rep["errors"] == ["dns timeout"]


import pytest


@pytest.mark.asyncio
async def test_run_hunt_orchestration():
    async def recon(scope):
        return ["https://a.example.com", "https://b.example.com"]

    async def verify(asset):
        if asset.startswith("https://a"):
            return {"checks": ["lfi", "cors"],
                    "verifications": [{"vuln_class": "lfi", "url": asset, "confirmed": True,
                                       "proof": "root:...:0:0:"}]}
        return {"checks": ["cors"],
                "verifications": [{"vuln_class": "cors", "url": asset, "confirmed": False}]}

    rep = await H.run_hunt("*.example.com", recon, verify)
    assert rep["summary"]["assets_discovered"] == 2
    assert rep["summary"]["checks_run"] == 3
    assert rep["summary"]["confirmed_findings"] == 1
    assert rep["confirmed_findings"][0]["vuln_class"] == "lfi"


@pytest.mark.asyncio
async def test_run_hunt_recon_failure_is_safe():
    async def recon(scope):
        raise RuntimeError("dns down")

    async def verify(asset):
        return {}

    rep = await H.run_hunt("x", recon, verify)
    assert rep["summary"]["assets_discovered"] == 0
    assert any("recon failed" in e for e in rep["errors"])


@pytest.mark.asyncio
async def test_run_hunt_per_asset_error_collected():
    async def recon(scope):
        return ["good", "bad"]

    async def verify(asset):
        if asset == "bad":
            raise ValueError("boom")
        return {"checks": ["cors"], "verifications": []}

    rep = await H.run_hunt("x", recon, verify)
    assert rep["summary"]["assets_discovered"] == 2
    assert any("bad: boom" in e for e in rep["errors"])


def test_render_report_markdown():
    rep = H.build_report(
        "*.example.com", ["https://a.example.com"],
        [{"target": "https://a.example.com", "checks": ["lfi"]}],
        [{"vuln_class": "lfi", "url": "https://a.example.com/read", "confirmed": True,
          "proof": "root:...:0:0:", "request": {"method": "GET", "url": "https://a.example.com/read?x=/etc/passwd"}},
         {"vuln_class": "cors", "url": "https://a.example.com", "confirmed": False, "proof": "no ACAO"}],
        errors=["dns timeout"])
    md = H.render_report_markdown(rep)
    assert "# Hunt Report — *.example.com" in md
    assert "Confirmed findings: **1**" in md
    assert "### lfi — https://a.example.com/read" in md
    assert "root:...:0:0:" in md
    assert "Needs human review" in md and "cors @" in md
    assert "## Errors" in md and "dns timeout" in md
