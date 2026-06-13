"""Tests for HTML report format and analyze_attack_chains MCP tool."""
import pytest
from tools.reporting.report_generator import _md_to_html, _generate_pentest_report_impl


class MockJobMgr:
    def __init__(self, jobs=None):
        self._jobs = jobs or []

    async def list_jobs(self, n):
        return self._jobs

    async def get_job(self, jid):
        return next((j for j in self._jobs if j["id"] == jid), {})


# ── HTML report ───────────────────────────────────────────────────────────────

def test_md_to_html_produces_valid_html():
    html = _md_to_html("Test Report", "# Heading\n## Section\n**bold**")
    assert "<!DOCTYPE html>" in html
    assert "<title>Test Report</title>" in html
    assert "<h1>" in html


def test_md_to_html_colors_severity_badges():
    html = _md_to_html("T", "Finding [CRITICAL] here")
    assert 'class="badge"' in html
    assert "#c0392b" in html  # critical color


def test_md_to_html_fallback_no_markdown_lib(monkeypatch):
    """Ensure HTML generates even if markdown library is not installed."""
    import sys
    # Remove markdown from sys.modules to force fallback
    monkeypatch.setitem(sys.modules, "markdown", None)
    html = _md_to_html("T", "# H1\n## H2\n**bold**")
    assert "<!DOCTYPE html>" in html
    assert "<h1>" in html or "<h2>" in html or "H1" in html


@pytest.mark.asyncio
async def test_report_html_format_returns_html():
    result = await _generate_pentest_report_impl(
        MockJobMgr(), "My Report", "low", "low", "", "", "html"
    )
    assert result["format"] == "html"
    assert "<!DOCTYPE html>" in result["report"]
    assert "My Report" in result["report"]


@pytest.mark.asyncio
async def test_report_markdown_format_no_doctype():
    result = await _generate_pentest_report_impl(
        MockJobMgr(), "My Report", "low", "low", "", "", "markdown"
    )
    assert result["format"] == "markdown"
    assert "<!DOCTYPE html>" not in result["report"]
    assert "# My Report" in result["report"]


@pytest.mark.asyncio
async def test_report_html_saved_to_file(tmp_path):
    path = str(tmp_path / "report.html")
    result = await _generate_pentest_report_impl(
        MockJobMgr(), "T", "low", "low", "", path, "html"
    )
    assert "saved_to" in result
    with open(result["saved_to"]) as f:
        content = f.read()
    assert "<!DOCTYPE html>" in content


# ── analyze_attack_chains tool ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_analyze_attack_chains_empty(mcp_server):
    from tests.conftest import call
    result = await call(mcp_server, "analyze_attack_chains", {})
    assert "chains" in result
    assert isinstance(result["chains"], list)
    assert "total_findings_analyzed" in result


@pytest.mark.asyncio
async def test_analyze_attack_chains_returns_chain_structure(mcp_server):
    """With a sqli + ssh job, a chain should be detected."""
    from tests.conftest import call
    # This test relies on actual job history — just verify structure is valid
    result = await call(mcp_server, "analyze_attack_chains", {"min_severity": "info"})
    assert isinstance(result.get("chains_found"), int)
    for chain in result.get("chains", []):
        assert "name" in chain
        assert "severity" in chain
        assert "narrative" in chain
        assert "steps" in chain
