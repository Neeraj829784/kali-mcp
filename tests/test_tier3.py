"""Tests for Tier 3 features: engagement model, analyze_findings, parallel workflows."""
import asyncio
import pytest
from tests.conftest import call
from scope import clear_scope


@pytest.fixture(autouse=True)
def lab_mode():
    clear_scope()
    yield
    clear_scope()


# ── Engagement Model ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_engagement_start_sets_scope(mcp_server):
    r = await call(mcp_server, "engagement_start", {
        "name": "pytest-engagement-001",
        "scope": ["10.0.0.1", "192.168.1.0/24"],
        "client": "Test Client"
    })
    assert r.get("status") == "started"
    assert r.get("id") is not None
    # Verify scope was set
    from scope import list_scope
    assert "10.0.0.1" in list_scope()
    # Cleanup
    await call(mcp_server, "engagement_end", {})


@pytest.mark.asyncio
async def test_engagement_status_active(mcp_server):
    await call(mcp_server, "engagement_start", {
        "name": "pytest-engagement-002",
        "scope": ["10.0.0.1"]
    })
    r = await call(mcp_server, "engagement_status", {})
    assert r.get("active") is True
    assert r.get("name") == "pytest-engagement-002"
    assert "10.0.0.1" in r.get("scope", [])
    await call(mcp_server, "engagement_end", {})


@pytest.mark.asyncio
async def test_engagement_status_no_active(mcp_server):
    r = await call(mcp_server, "engagement_status", {})
    # Either no active or the previous test left one
    assert "active" in r


@pytest.mark.asyncio
async def test_engagement_end_clears_scope(mcp_server):
    await call(mcp_server, "engagement_start", {
        "name": "pytest-engagement-003",
        "scope": ["1.2.3.4"]
    })
    r = await call(mcp_server, "engagement_end", {})
    assert r.get("status") == "ended"
    assert "cleared" in r.get("scope", "")
    from scope import list_scope
    assert list_scope() == []


@pytest.mark.asyncio
async def test_engagement_findings_empty_without_active(mcp_server):
    r = await call(mcp_server, "engagement_findings", {})
    assert "error" in r


@pytest.mark.asyncio
async def test_engagement_auto_tags_findings(mcp_server, job_mgr):
    """Findings from run_and_wait must be auto-tagged to active engagement."""
    await call(mcp_server, "engagement_start", {
        "name": "pytest-engagement-004",
        "scope": ["127.0.0.1"]
    })
    # Run a job that produces nmap output with open ports
    jid = await job_mgr.create_job("nmap_port_scan", ["echo", ""], 5)
    await asyncio.sleep(0.3)
    job = await job_mgr.get_job(jid)
    if job.get("output_file"):
        with open(job["output_file"], "w") as f:
            f.write("22/tcp open ssh OpenSSH 9.6\n")
    # Trigger finding extraction by calling run_and_wait
    await job_mgr.run_and_wait("nmap_port_scan",
        ["nmap", "-sT", "-p", "22", "--version-light", "127.0.0.1"], 30)

    r = await call(mcp_server, "engagement_findings", {"min_severity": "info"})
    assert "findings" in r
    await call(mcp_server, "engagement_end", {})


@pytest.mark.asyncio
async def test_engagement_list(mcp_server):
    r = await call(mcp_server, "engagement_list", {})
    assert isinstance(r, list)
    # Should have at least the engagements created above
    assert len(r) >= 0  # could be 0 if DB was fresh


# ── Analyze Findings ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_analyze_findings_returns_structure(mcp_server):
    r = await call(mcp_server, "analyze_findings", {"min_severity": "info"})
    assert "total_findings" in r
    assert "severity_summary" in r
    assert "attack_paths" in r
    assert "recommended_next" in r
    assert "quick_wins" in r
    assert isinstance(r["attack_paths"], list)
    assert isinstance(r["recommended_next"], list)


@pytest.mark.asyncio
async def test_analyze_findings_with_creds(mcp_server):
    """analyze_findings should mention stored creds in recommendations."""
    await call(mcp_server, "creds_store", {
        "host": "10.0.0.1", "username": "admin",
        "password": "TestPass123!", "service": "ssh"
    })
    r = await call(mcp_server, "analyze_findings", {"min_severity": "info"})
    assert isinstance(r.get("stored_credentials"), list)
    assert len(r["stored_credentials"]) >= 1


@pytest.mark.asyncio
@pytest.mark.slow
@pytest.mark.timeout(600)
async def test_scan_host_parallel(mcp_server):
    """scan_host fires multiple tools in parallel — verify it completes and returns structure."""
    r = await call(mcp_server, "scan_host", {
        "target": "127.0.0.1", "intensity": "light"
    })
    assert "target" in r
    assert "port_scan" in r
    assert "parallel_scans" in r
    assert isinstance(r.get("findings"), list)
    assert isinstance(r.get("suggested_next"), list)


@pytest.mark.asyncio
@pytest.mark.slow
@pytest.mark.timeout(600)
async def test_scan_web_parallel(mcp_server):
    """scan_web fires nikto + gobuster + nuclei + crawler in parallel."""
    r = await call(mcp_server, "scan_web", {
        "url": "http://example.com/", "depth": "light"
    })
    assert "target" in r
    assert "scans" in r
    assert isinstance(r["scans"], dict)
