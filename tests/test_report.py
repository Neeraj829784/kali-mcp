"""Tests for pentest report generator — mocks job_mgr, no I/O."""
import pytest
from tools.reporting.report_generator import _generate_pentest_report_impl


class MockJobManager:
    def __init__(self, jobs):
        self._jobs = jobs

    async def list_jobs(self, limit=200):
        return [{"id": j["id"], "tool": j["tool"], "status": j["status"]} for j in self._jobs]

    async def get_job(self, job_id):
        for j in self._jobs:
            if j["id"] == job_id:
                return j
        return {}


def _job(id_, tool, output, status="completed"):
    return {"id": id_, "tool": tool, "output": output, "status": status}


@pytest.mark.asyncio
async def test_report_contains_exec_summary():
    jm = MockJobManager([
        _job("j1", "nmap_port_scan", "22/tcp open ssh OpenSSH 8.2\n80/tcp open http Apache 2.4.41"),
    ])
    result = await _generate_pentest_report_impl(jm, min_severity="info", min_confidence="low")
    assert "Executive Summary" in result["report"]


@pytest.mark.asyncio
async def test_report_contains_attack_chains_section():
    jm = MockJobManager([
        _job("j1", "sqlmap", "Parameter: id (GET)\n[*] the parameter 'id' is injectable"),
        _job("j2", "nmap_port_scan", "22/tcp open ssh OpenSSH 8.2"),
    ])
    result = await _generate_pentest_report_impl(jm, min_severity="info", min_confidence="low")
    assert "Attack Chains" in result["report"]


@pytest.mark.asyncio
async def test_report_filters_by_min_severity():
    jm = MockJobManager([
        _job("j1", "nmap_port_scan", "80/tcp open http Apache 2.4.41"),
        _job("j2", "sqlmap", "Parameter: id (GET)\n[*] the parameter 'id' is injectable"),
    ])
    result_low = await _generate_pentest_report_impl(jm, min_severity="low", min_confidence="low")
    result_info = await _generate_pentest_report_impl(jm, min_severity="info", min_confidence="low")
    # Info-only report should have more findings than low-only
    assert "Open port" in result_info["report"]
    assert "Open port" not in result_low["report"]


@pytest.mark.asyncio
async def test_report_contains_remediation():
    jm = MockJobManager([
        _job("j1", "sqlmap", "Parameter: id (GET)\n[*] the parameter 'id' is injectable"),
    ])
    result = await _generate_pentest_report_impl(jm, min_severity="low", min_confidence="low")
    assert "Parameterised Queries" in result["report"]


@pytest.mark.asyncio
async def test_report_empty_findings_graceful():
    jm = MockJobManager([])
    result = await _generate_pentest_report_impl(jm, min_severity="low", min_confidence="low")
    assert result["format"] == "markdown"
    assert "Executive Summary" in result["report"]
    assert "Findings by Severity" in result["report"]
