"""Tests for scanning tools."""
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
async def test_gobuster_dir_no_status_codes_conflict(mcp_server):
    """Regression: gobuster must not fail with status-codes conflict."""
    r = await call(mcp_server, "gobuster_dir", {
        "url": "http://example.com/", "threads": 5
    })
    output = r.get("output", "")
    assert "both set" not in output, "Status-codes conflict bug re-introduced"
    assert r.get("status") == "completed"
    assert r.get("result", {}).get("return_code") == 0


@pytest.mark.asyncio
async def test_gobuster_dir_with_extensions(mcp_server):
    r = await call(mcp_server, "gobuster_dir", {
        "url": "http://example.com/", "extensions": "php,html", "threads": 5
    })
    assert r.get("status") == "completed"


@pytest.mark.asyncio
async def test_gobuster_dns_runs(mcp_server):
    r = await call(mcp_server, "gobuster_dns", {
        "domain": "example.com", "threads": 5
    })
    assert r.get("status") == "completed"


@pytest.mark.asyncio
@pytest.mark.slow
@pytest.mark.timeout(300)
async def test_gobuster_vhost_runs(mcp_server):
    """gobuster vhost scans take 2+ min — run with pytest -m slow."""
    r = await call(mcp_server, "gobuster_vhost", {
        "url": "http://example.com", "threads": 5
    })
    assert r.get("status") == "completed"


@pytest.mark.asyncio
async def test_ffuf_w_before_u_flag_order(mcp_server):
    """Regression: ffuf -w must come before -u, otherwise help is printed."""
    r = await call(mcp_server, "ffuf_fuzz", {
        "url": "http://example.com/FUZZ",
        "threads": 5,
        "match_codes": "200"
    })
    output = r.get("output", "")
    # If -w/-u order was wrong, ffuf prints full help text
    assert "Usage:" not in output[:100], "ffuf printed help — arg order regression"
    assert r.get("status") == "completed"


@pytest.mark.asyncio
async def test_ffuf_with_header_does_not_break(mcp_server):
    """Regression: ffuf with headers parameter must not print help."""
    r = await call(mcp_server, "ffuf_fuzz", {
        "url": "http://example.com/FUZZ",
        "headers": "X-Test: value",
        "threads": 5,
        "match_codes": "200"
    })
    output = r.get("output", "")
    assert "Usage:" not in output[:200], "ffuf+header printed help — regression"


@pytest.mark.asyncio
async def test_nikto_runs_and_does_not_timeout_early(mcp_server):
    """Regression: nikto must respect timeout param, not cut out at 180s."""
    r = await call(mcp_server, "nikto_scan", {
        "target": "example.com", "port": 80, "max_time": "30s", "timeout": 60
    })
    output = r.get("output", "")
    assert r.get("status") == "completed"
    assert "0 items reported" not in output or "30 seconds" in output, \
        "Nikto may have exited early before scanning"


@pytest.mark.asyncio
async def test_smbclient_graceful_fail(mcp_server):
    """smbclient against non-SMB host must return error, not crash."""
    r = await call(mcp_server, "smbclient_list_shares", {"target": "127.0.0.1"})
    assert r.get("return_code") is not None


@pytest.mark.asyncio
async def test_nc_port_check(mcp_server):
    r = await call(mcp_server, "nc_port_check", {
        "host": "127.0.0.1", "ports": "22,80,443"
    })
    assert isinstance(r, dict)
    assert all(k in r for k in ["22", "80", "443"])
    assert all("open" in v for v in r.values())


@pytest.mark.asyncio
async def test_nc_banner_grab_closed_port(mcp_server):
    """nc_banner_grab on closed port must return gracefully."""
    r = await call(mcp_server, "nc_banner_grab", {
        "host": "127.0.0.1", "port": 19999, "timeout": 2
    })
    assert r.get("return_code") is not None or "error" in r or "note" in r
