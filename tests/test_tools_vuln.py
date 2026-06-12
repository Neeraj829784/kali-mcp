"""Tests for vulnerability analysis tools."""
import os
import pytest
from tests.conftest import call
from scope import clear_scope


@pytest.fixture(autouse=True)
def lab_mode():
    clear_scope()
    yield
    clear_scope()


@pytest.mark.asyncio
async def test_searchsploit_search_returns_results(mcp_server):
    import json
    r = await call(mcp_server, "searchsploit_search", {"query": "apache"})
    assert r.get("return_code") == 0
    data = json.loads(r.get("stdout", "{}"))
    assert len(data.get("RESULTS_EXPLOIT", [])) > 0


@pytest.mark.asyncio
async def test_searchsploit_json_output(mcp_server):
    """searchsploit must return parseable JSON."""
    import json
    r = await call(mcp_server, "searchsploit_search", {"query": "ssh"})
    try:
        json.loads(r.get("stdout", ""))
    except json.JSONDecodeError:
        pytest.fail("searchsploit did not return valid JSON")


@pytest.mark.asyncio
async def test_searchsploit_get_path(mcp_server):
    r = await call(mcp_server, "searchsploit_get_path", {"edb_id": "9901"})
    assert r.get("return_code") == 0
    assert "/usr/share" in r.get("stdout", "") or "exploit" in r.get("stdout", "").lower()


@pytest.mark.asyncio
async def test_searchsploit_cve_lookup(mcp_server):
    r = await call(mcp_server, "searchsploit_search", {
        "query": "", "cve": "2021-44228"
    })
    assert r.get("return_code") == 0


@pytest.mark.asyncio
@pytest.mark.slow
@pytest.mark.timeout(600)
async def test_nuclei_scan_returns_findings_file(mcp_server):
    """Regression: findings_file must be present in result after run_and_wait."""
    r = await call(mcp_server, "nuclei_scan", {
        "target": "http://example.com",
        "severity": "info,low,medium,high,critical",
        "rate_limit": 30,
        "concurrency": 5
    })
    assert r.get("status") == "completed"
    assert "findings_file" in r, "findings_file must be in result — regression check"
    ffile = r["findings_file"]
    assert ffile and os.path.exists(ffile), f"findings_file path must exist: {ffile}"


@pytest.mark.asyncio
async def test_nuclei_parse_output(mcp_server):
    """parse_nuclei_output must handle empty file gracefully."""
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
        f.write('')
        path = f.name
    r = await call(mcp_server, "parse_nuclei_output", {"findings_file": path})
    assert r.get("total") == 0
    os.unlink(path)


@pytest.mark.asyncio
async def test_nuclei_parse_valid_jsonl(mcp_server):
    import tempfile
    finding = '{"template-id":"test","info":{"name":"Test","severity":"high","tags":["rce"]},"host":"http://example.com","matched-at":"http://example.com/"}'
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
        f.write(finding)
        path = f.name
    r = await call(mcp_server, "parse_nuclei_output", {"findings_file": path})
    assert r.get("total") == 1
    assert "high" in r.get("by_severity", {})
    os.unlink(path)


@pytest.mark.asyncio
async def test_wpscan_auto_updates_db(mcp_server):
    """Regression: wpscan must not abort with 'database file missing'."""
    r = await call(mcp_server, "wpscan_scan", {
        "url": "http://example.com", "enumerate": "vp"
    })
    output = r.get("output", "")
    assert "Update required" not in output, \
        "wpscan DB not initialized — regression"
    assert r.get("status") == "completed"
