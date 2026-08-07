"""Tests for continuous-recon: snapshot/diff layer + passive sweep."""
import os
import tempfile

import pytest
import pytest_asyncio

import asset_inventory
import recon_sweep
from tests.conftest import call


@pytest_asyncio.fixture
async def temp_assets(monkeypatch):
    path = tempfile.mktemp(suffix=".db")
    monkeypatch.setattr(asset_inventory, "PROGRAMS_DB_PATH", path)
    await asset_inventory.init_db()
    yield path
    for p in (path, path + "-wal", path + "-shm"):
        if os.path.exists(p):
            os.unlink(p)


# ── Pure diff_snapshots ──────────────────────────────────────────────────────

def test_diff_snapshots_new_disappeared_changed():
    prev = {"host": {1: "", 2: ""}, "service": {10: "nginx 1.0"}, "vuln": {}}
    curr = {"host": {2: "", 3: ""}, "service": {10: "nginx 1.2"}, "vuln": {}}
    d = asset_inventory.diff_snapshots(prev, curr)
    assert d["host"]["new"] == [3]
    assert d["host"]["disappeared"] == [1]
    assert d["service"]["changed"] == [10]


def test_diff_snapshots_empty():
    d = asset_inventory.diff_snapshots({}, {})
    assert d["host"] == {"new": [], "disappeared": [], "changed": []}


# ── DB-backed run tracking + compare_runs ────────────────────────────────────

@pytest.mark.asyncio
async def test_run_membership_and_compare(temp_assets):
    r1 = await asset_inventory.start_run("ProgA", "passive")
    await asset_inventory.ingest_finding(
        {"host": "a.com", "port": 80, "service": "http",
         "title": "Open port 80/http", "severity": "info", "confidence": "high"},
        run_id=r1)
    s1 = await asset_inventory.finish_run(r1)
    assert s1["host_count"] == 1 and s1["service_count"] == 1

    r2 = await asset_inventory.start_run("ProgA", "passive")
    await asset_inventory.ingest_finding(
        {"host": "a.com", "port": 80, "service": "http",
         "title": "Open port 80/http", "severity": "info", "confidence": "high"},
        run_id=r2)
    await asset_inventory.ingest_finding(
        {"host": "new.a.com", "port": 443, "service": "https",
         "title": "Open port 443/https", "severity": "info", "confidence": "high"},
        run_id=r2)
    await asset_inventory.finish_run(r2)

    report = await asset_inventory.compare_runs(r1, r2)
    assert report["total_changes"] >= 2
    new_hosts = report["changes"]["host"]["new"]
    assert any("new.a.com" in h for h in new_hosts)


@pytest.mark.asyncio
async def test_disappeared_detection(temp_assets):
    r1 = await asset_inventory.start_run("P", "passive")
    await asset_inventory.ingest_finding(
        {"host": "gone.com", "title": "Subdomain: gone.com", "severity": "info",
         "confidence": "high"}, run_id=r1)
    await asset_inventory.finish_run(r1)
    r2 = await asset_inventory.start_run("P", "passive")
    await asset_inventory.ingest_finding(
        {"host": "still.com", "title": "Subdomain: still.com", "severity": "info",
         "confidence": "high"}, run_id=r2)
    await asset_inventory.finish_run(r2)
    report = await asset_inventory.compare_runs(r1, r2)
    disappeared = report["changes"]["host"]["disappeared"]
    assert any("gone.com" in h for h in disappeared)


@pytest.mark.asyncio
async def test_asset_list_and_diff_tools(temp_assets, mcp_server):
    r1 = await asset_inventory.start_run("ToolProg", "passive")
    await asset_inventory.ingest_finding(
        {"host": "t.com", "port": 22, "service": "ssh", "title": "Open port 22/ssh",
         "severity": "info", "confidence": "high"}, run_id=r1)
    await asset_inventory.finish_run(r1)

    runs = await call(mcp_server, "asset_list_runs", {"program": "ToolProg"})
    assert runs["total"] >= 1

    r2 = await asset_inventory.start_run("ToolProg", "passive")
    await asset_inventory.ingest_finding(
        {"host": "t2.com", "port": 80, "service": "http", "title": "Open port 80/http",
         "severity": "info", "confidence": "high"}, run_id=r2)
    await asset_inventory.finish_run(r2)

    diff = await call(mcp_server, "asset_diff_runs",
                      {"prev_run_id": r1, "curr_run_id": r2})
    assert diff["total_changes"] >= 1

    latest = await call(mcp_server, "asset_latest_changes", {"program": "ToolProg"})
    assert "priority_new_assets" in latest


@pytest.mark.asyncio
async def test_latest_changes_needs_two_runs(temp_assets, mcp_server):
    r1 = await asset_inventory.start_run("Solo", "passive")
    await asset_inventory.ingest_finding(
        {"host": "solo.com", "title": "Subdomain: solo.com", "severity": "info",
         "confidence": "high"}, run_id=r1)
    await asset_inventory.finish_run(r1)
    res = await call(mcp_server, "asset_latest_changes", {"program": "Solo"})
    assert res.get("runs_found") == 1


# ── normalize_recon_findings (pure) ──────────────────────────────────────────

def test_normalize_subdomain_becomes_host():
    findings = [
        {"host": "example.com", "title": "Subdomain discovered: api.example.com",
         "evidence": "api.example.com", "severity": "info", "tool": "subfinder"},
        {"host": "example.com", "title": "Subdomain discovered: dev.example.com",
         "evidence": "dev.example.com -> 1.2.3.4", "severity": "info", "tool": "theharvester"},
    ]
    out = recon_sweep.normalize_recon_findings(findings, "example.com")
    hosts = {f["host"] for f in out}
    assert "api.example.com" in hosts
    assert "dev.example.com" in hosts


def test_normalize_passes_through_non_subdomain():
    findings = [{"host": "example.com", "title": "Email found: a@example.com",
                 "evidence": "a@example.com", "severity": "info", "tool": "theharvester"}]
    out = recon_sweep.normalize_recon_findings(findings, "example.com")
    assert out[0]["host"] == "example.com"
    assert out[0]["title"] == "Email found: a@example.com"


def test_normalize_fills_missing_host():
    out = recon_sweep.normalize_recon_findings(
        [{"title": "Something", "severity": "low"}], "example.com")
    assert out[0]["host"] == "example.com"


# ── sweep() end-to-end with a fake job_mgr (no network) ──────────────────────

class _FakeJobMgr:
    """Returns canned findings per tool so sweep() runs without network."""
    def __init__(self, per_tool):
        self._per_tool = per_tool

    async def run_and_wait(self, tool, cmd, timeout, target=""):
        return {"status": "completed", "findings": self._per_tool.get(tool, [])}


@pytest.mark.asyncio
async def test_sweep_baseline_then_change(temp_assets, monkeypatch):
    monkeypatch.setattr(recon_sweep, "check_scope", lambda t: None)

    # First sweep — one subdomain
    jm1 = _FakeJobMgr({"subfinder": [
        {"host": "x.com", "title": "Subdomain discovered: a.x.com",
         "evidence": "a.x.com", "severity": "info", "tool": "subfinder"}]})
    r1 = await recon_sweep.sweep(jm1, "x.com", program="XProg", tools=["subfinder"])
    assert r1["baseline"] is True
    assert r1["observed"]["host_count"] >= 1

    # Second sweep — a NEW subdomain appears
    jm2 = _FakeJobMgr({"subfinder": [
        {"host": "x.com", "title": "Subdomain discovered: a.x.com",
         "evidence": "a.x.com", "severity": "info", "tool": "subfinder"},
        {"host": "x.com", "title": "Subdomain discovered: new.x.com",
         "evidence": "new.x.com", "severity": "info", "tool": "subfinder"}]})
    r2 = await recon_sweep.sweep(jm2, "x.com", program="XProg", tools=["subfinder"])
    assert r2["baseline"] is False
    assert any("new.x.com" in a for a in r2["priority_new_assets"])


@pytest.mark.asyncio
async def test_sweep_respects_tool_budget(temp_assets, monkeypatch):
    monkeypatch.setattr(recon_sweep, "check_scope", lambda t: None)
    jm = _FakeJobMgr({"subfinder": [], "amass": [], "theharvester": []})
    r = await recon_sweep.sweep(jm, "b.com", program="B",
                                tools=["subfinder", "amass", "theharvester"],
                                tool_budget=1)
    ran = [t for t, v in r["tools"].items() if isinstance(v, dict)]
    skipped = [t for t, v in r["tools"].items() if "budget" in str(v)]
    assert len(ran) == 1
    assert len(skipped) == 2
