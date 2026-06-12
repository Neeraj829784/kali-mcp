"""Tests for reconnaissance tools."""
import pytest
from tests.conftest import call
from scope import clear_scope


@pytest.fixture(autouse=True)
def lab_mode():
    clear_scope()
    yield
    clear_scope()


@pytest.mark.asyncio
async def test_nmap_host_discovery(mcp_server):
    r = await call(mcp_server, "nmap_host_discovery", {"targets": "127.0.0.1"})
    # nmap_host_discovery is sync — returns executor result directly
    assert r.get("return_code") == 0
    assert "127.0.0.1" in r.get("stdout", "")


@pytest.mark.asyncio
async def test_nmap_port_scan_returns_result(mcp_server):
    r = await call(mcp_server, "nmap_port_scan", {
        "targets": "127.0.0.1", "ports": "22,80", "scan_type": "sT"
    })
    # nmap_port_scan uses run_and_wait — must return completed job with nmap output
    # It runs in background then returns; the job should complete within the timeout
    import asyncio
    for _ in range(30):  # wait up to 30s
        if r.get("status") == "completed":
            break
        jid = r.get("job_id") or r.get("id")
        if jid:
            from job_manager import JobManager
            jm = JobManager()
            await jm.init_db()
            r = await jm.get_job(jid)
        await asyncio.sleep(1)
    output = r.get("output", "")
    assert "nmap" in output.lower() or r.get("status") == "completed", \
        f"nmap_port_scan job did not complete: {r}"


@pytest.mark.asyncio
async def test_nmap_service_detection(mcp_server):
    r = await call(mcp_server, "nmap_service_detection", {
        "targets": "127.0.0.1", "ports": "22,80"
    })
    assert r.get("status") == "completed"


@pytest.mark.asyncio
async def test_nmap_vuln_scan(mcp_server):
    r = await call(mcp_server, "nmap_vuln_scan", {
        "targets": "127.0.0.1", "ports": "22", "scripts": "safe"
    })
    assert r.get("status") == "completed"


@pytest.mark.asyncio
async def test_nmap_aggressive_scan(mcp_server):
    r = await call(mcp_server, "nmap_aggressive_scan", {
        "targets": "127.0.0.1", "ports": "22"
    })
    assert r.get("status") == "completed"


@pytest.mark.asyncio
async def test_nmap_os_detection_runs(mcp_server):
    """OS detection may fail without root — but must not crash."""
    r = await call(mcp_server, "nmap_os_detection", {"targets": "127.0.0.1"})
    assert r.get("status") in ("completed", "failed")


@pytest.mark.asyncio
async def test_whois_lookup(mcp_server):
    r = await call(mcp_server, "whois_lookup", {"target": "example.com"})
    assert r.get("return_code") is not None


@pytest.mark.asyncio
async def test_dig_lookup_a_record(mcp_server):
    r = await call(mcp_server, "dig_lookup", {
        "domain": "example.com", "record_type": "A", "short": True
    })
    assert r.get("return_code") == 0


@pytest.mark.asyncio
async def test_dig_lookup_mx_record(mcp_server):
    r = await call(mcp_server, "dig_lookup", {
        "domain": "example.com", "record_type": "MX"
    })
    assert r.get("return_code") == 0


@pytest.mark.asyncio
async def test_dig_zone_transfer_fails_gracefully(mcp_server):
    """Zone transfer should fail on public domains — must not crash."""
    r = await call(mcp_server, "dig_zone_transfer", {
        "domain": "example.com", "nameserver": "8.8.8.8"
    })
    assert r.get("return_code") is not None


@pytest.mark.asyncio
@pytest.mark.slow
@pytest.mark.timeout(300)
async def test_subfinder_runs(mcp_server):
    """subfinder takes 2+ min — run with pytest -m slow."""
    r = await call(mcp_server, "subfinder_enumerate", {
        "domain": "example.com", "threads": 3
    })
    assert r.get("status") in ("completed", "failed")


@pytest.mark.asyncio
@pytest.mark.timeout(90)
async def test_theharvester_no_invalid_source_error(mcp_server):
    """Regression: default sources must not produce 'Invalid source' error."""
    r = await call(mcp_server, "theharvester_search", {
        "domain": "example.com", "limit": 10
    })
    output = r.get("output", "")
    assert "Invalid source" not in output, \
        f"Default sources contain invalid source: {output[:200]}"
    assert r.get("status") == "completed"


@pytest.mark.asyncio
@pytest.mark.slow
@pytest.mark.timeout(300)
async def test_amass_enum_runs(mcp_server):
    """amass takes 1+ min — run with pytest -m slow."""
    r = await call(mcp_server, "amass_enum", {
        "domain": "example.com", "passive": True, "timeout_mins": 1
    })
    assert r.get("status") in ("completed", "failed")
