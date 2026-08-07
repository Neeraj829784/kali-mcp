"""Tests for the persistent asset inventory (asset_inventory.py)."""
import os
import tempfile

import pytest
import pytest_asyncio

import asset_inventory
from tests.conftest import call


@pytest_asyncio.fixture
async def temp_assets(monkeypatch):
    """Point the asset inventory at a throwaway DB and create its tables."""
    path = tempfile.mktemp(suffix=".db")
    monkeypatch.setattr(asset_inventory, "PROGRAMS_DB_PATH", path)
    await asset_inventory.init_db()
    yield path
    for p in (path, path + "-wal", path + "-shm"):
        if os.path.exists(p):
            os.unlink(p)


@pytest.mark.asyncio
async def test_ingest_creates_host_service_vuln(temp_assets):
    f = {
        "host": "10.0.0.5", "port": 445, "service": "smb",
        "title": "SMB null session allowed", "severity": "medium",
        "confidence": "high", "evidence": "Null session enumeration succeeded",
    }
    r = await asset_inventory.ingest_finding(f)
    assert r["host_ip"] == "10.0.0.5"
    assert r["host_id"] is not None
    assert r["service_id"] is not None
    assert r["vuln_id"] is not None


@pytest.mark.asyncio
async def test_ingest_extracts_cve(temp_assets):
    f = {
        "host": "10.0.0.6", "port": 445, "service": "smb",
        "title": "VULNERABLE: EternalBlue", "severity": "critical",
        "confidence": "medium", "evidence": "CVE-2017-0144 detected",
    }
    await asset_inventory.ingest_finding(f)
    async with asset_inventory._get_db() as db:
        async with db.execute("SELECT cve_id FROM vulnerabilities WHERE host_id IN "
                              "(SELECT id FROM hosts WHERE ip='10.0.0.6')") as cur:
            row = await cur.fetchone()
    assert row[0] == "CVE-2017-0144"


@pytest.mark.asyncio
async def test_reingest_dedupes_and_increments_scan_count(temp_assets):
    f = {
        "host": "10.0.0.7", "port": 22, "service": "ssh",
        "title": "Open port 22/ssh", "severity": "info", "confidence": "high",
    }
    await asset_inventory.ingest_finding(f)
    await asset_inventory.ingest_finding(f)
    async with asset_inventory._get_db() as db:
        async with db.execute("SELECT scan_count FROM hosts WHERE ip='10.0.0.7'") as cur:
            scan_count = (await cur.fetchone())[0]
        async with db.execute("SELECT COUNT(*) FROM vulnerabilities v JOIN hosts h "
                              "ON v.host_id=h.id WHERE h.ip='10.0.0.7'") as cur:
            vuln_count = (await cur.fetchone())[0]
    assert scan_count == 2, "host scan_count should increment on re-ingest"
    assert vuln_count == 1, "identical finding must not create a duplicate vuln"


@pytest.mark.asyncio
async def test_ingest_missing_host_returns_error(temp_assets):
    r = await asset_inventory.ingest_finding({"title": "x", "severity": "low"})
    assert "error" in r


@pytest.mark.asyncio
async def test_list_hosts_and_get_host(temp_assets, mcp_server):
    await asset_inventory.ingest_finding({
        "host": "10.0.0.8", "port": 80, "service": "http",
        "title": "Found path /admin", "severity": "low", "confidence": "medium",
    })
    listed = await call(mcp_server, "asset_list_hosts", {})
    assert listed["total"] >= 1
    assert any(h["ip"] == "10.0.0.8" for h in listed["hosts"])

    detail = await call(mcp_server, "asset_get_host", {"host_ip": "10.0.0.8"})
    assert detail["host"]["ip"] == "10.0.0.8"
    assert any(s["port"] == 80 for s in detail["services"])
    assert len(detail["vulnerabilities"]) >= 1


@pytest.mark.asyncio
async def test_list_vulnerabilities_severity_filter(temp_assets, mcp_server):
    await asset_inventory.ingest_finding({
        "host": "10.0.0.9", "port": 443, "service": "https",
        "title": "SQL Injection found", "severity": "critical", "confidence": "high",
    })
    await asset_inventory.ingest_finding({
        "host": "10.0.0.9", "port": 443, "service": "https",
        "title": "Server header disclosed", "severity": "info", "confidence": "low",
    })
    res = await call(mcp_server, "asset_list_vulnerabilities",
                     {"host_ip": "10.0.0.9", "min_severity": "high"})
    assert res["total"] == 1
    assert res["vulnerabilities"][0]["title"] == "SQL Injection found"


@pytest.mark.asyncio
async def test_search_by_ip_and_cve(temp_assets, mcp_server):
    await asset_inventory.ingest_finding({
        "host": "10.0.0.10", "port": 445, "service": "smb",
        "title": "VULNERABLE", "severity": "high", "confidence": "medium",
        "evidence": "CVE-2021-34527 PrintNightmare",
    })
    by_ip = await call(mcp_server, "asset_search", {"query": "10.0.0.10"})
    assert any(h["ip"] == "10.0.0.10" for h in by_ip["hosts"])
    by_cve = await call(mcp_server, "asset_search", {"query": "CVE-2021-34527"})
    assert len(by_cve["vulnerabilities"]) >= 1


@pytest.mark.asyncio
async def test_mark_host_and_vuln(temp_assets, mcp_server):
    r = await asset_inventory.ingest_finding({
        "host": "10.0.0.11", "port": 22, "service": "ssh",
        "title": "Weak SSH credentials", "severity": "high", "confidence": "high",
    })
    marked = await call(mcp_server, "asset_mark_host",
                        {"host_ip": "10.0.0.11", "status": "confirmed"})
    assert marked["updated"] is True
    bad = await call(mcp_server, "asset_mark_host",
                     {"host_ip": "10.0.0.11", "status": "bogus"})
    assert "error" in bad

    vmarked = await call(mcp_server, "asset_mark_vuln",
                         {"vuln_id": r["vuln_id"], "status": "false_positive"})
    assert vmarked["updated"] is True


@pytest.mark.asyncio
async def test_auto_ingest_findings_batch(temp_assets):
    findings = [
        {"host": "10.0.0.12", "port": 80, "title": "A", "severity": "low", "confidence": "low"},
        {"port": 443, "title": "B", "severity": "medium", "confidence": "medium"},
    ]
    results = await asset_inventory.auto_ingest_findings(findings, host="10.0.0.12")
    assert len(results) == 2
    assert all(r.get("host_ip") == "10.0.0.12" for r in results)
