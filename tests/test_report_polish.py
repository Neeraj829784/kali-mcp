"""Tests for report polish: min_confidence filter, engagement findings, save_to."""
import os
import pytest
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


# ── Task 1: min_confidence filter logic ──────────────────────────────────────

def test_conf_rank_low_passes_all():
    from findings import CONF_HIGH, CONF_MEDIUM, CONF_LOW
    conf_rank = {"low": 0, "medium": 1, "high": 2}
    findings = [
        {"confidence": CONF_HIGH, "severity": "high"},
        {"confidence": CONF_MEDIUM, "severity": "high"},
        {"confidence": CONF_LOW, "severity": "high"},
    ]
    filtered = [f for f in findings
                if conf_rank.get(f.get("confidence", "low"), 0) >= conf_rank.get("low", 0)]
    assert len(filtered) == 3


def test_conf_rank_high_passes_only_high():
    from findings import CONF_HIGH, CONF_MEDIUM, CONF_LOW
    conf_rank = {"low": 0, "medium": 1, "high": 2}
    findings = [
        {"confidence": CONF_HIGH, "severity": "high"},
        {"confidence": CONF_MEDIUM, "severity": "high"},
        {"confidence": CONF_LOW, "severity": "high"},
    ]
    filtered = [f for f in findings
                if conf_rank.get(f.get("confidence", "low"), 0) >= conf_rank.get("high", 0)]
    assert len(filtered) == 1
    assert filtered[0]["confidence"] == CONF_HIGH


def test_conf_rank_medium_passes_medium_and_high():
    from findings import CONF_HIGH, CONF_MEDIUM, CONF_LOW
    conf_rank = {"low": 0, "medium": 1, "high": 2}
    findings = [
        {"confidence": CONF_HIGH, "severity": "high"},
        {"confidence": CONF_MEDIUM, "severity": "high"},
        {"confidence": CONF_LOW, "severity": "high"},
    ]
    filtered = [f for f in findings
                if conf_rank.get(f.get("confidence", "low"), 0) >= conf_rank.get("medium", 0)]
    assert len(filtered) == 2
    confs = {f["confidence"] for f in filtered}
    assert confs == {CONF_HIGH, CONF_MEDIUM}


# ── Task 3: save_to option ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_report_saves_to_file(tmp_path):
    from tools.reporting.report_generator import _generate_pentest_report_impl

    class MockJobMgr:
        async def list_jobs(self, n):
            return []
        async def get_job(self, jid):
            return {}

    save_path = str(tmp_path / "report.md")
    result = await _generate_pentest_report_impl(
        MockJobMgr(), "Test Report", "low", "low", "", save_path
    )
    assert "saved_to" in result
    assert os.path.exists(result["saved_to"])
    with open(result["saved_to"], "r") as f:
        content = f.read()
    assert "Test Report" in content


@pytest.mark.asyncio
async def test_report_save_to_bad_path_returns_error():
    from tools.reporting.report_generator import _generate_pentest_report_impl

    class MockJobMgr:
        async def list_jobs(self, n):
            return []
        async def get_job(self, jid):
            return {}

    result = await _generate_pentest_report_impl(
        MockJobMgr(), "Test", "low", "low", "", "/etc/passwd"
    )
    assert "save_error" in result


@pytest.mark.asyncio
async def test_report_returns_findings_and_chains_counts():
    from tools.reporting.report_generator import _generate_pentest_report_impl

    class MockJobMgr:
        async def list_jobs(self, n):
            return [{"id": "j1", "tool": "nmap_port_scan", "status": "completed"}]
        async def get_job(self, jid):
            return {"output": "22/tcp open ssh OpenSSH 8.2\n80/tcp open http Apache 2.4.41"}

    result = await _generate_pentest_report_impl(MockJobMgr(), "Test", "info", "low")
    assert "findings_count" in result
    assert "chains_count" in result
    assert isinstance(result["findings_count"], int)
    assert isinstance(result["chains_count"], int)
