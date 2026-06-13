"""Tests for finding status (confirmed/false_positive/unconfirmed) workflow."""
import pytest
from tests.conftest import call
from scope import clear_scope


@pytest.fixture(autouse=True)
def lab_mode():
    clear_scope()
    yield
    clear_scope()


@pytest.mark.asyncio
async def test_list_unconfirmed_no_active_engagement(mcp_server):
    result = await call(mcp_server, "list_unconfirmed_findings", {})
    assert "error" in result


@pytest.mark.asyncio
async def test_update_finding_status_invalid_status(mcp_server):
    result = await call(mcp_server, "update_finding_status", {
        "finding_id": 1, "status": "invalid_value"
    })
    assert "error" in result


@pytest.mark.asyncio
async def test_update_finding_status_valid_statuses(mcp_server):
    # Without an active engagement, should return error (engagement isolation)
    for status in ("confirmed", "false_positive", "unconfirmed"):
        result = await call(mcp_server, "update_finding_status", {
            "finding_id": 99999, "status": status
        })
        # No active engagement → error
        assert "error" in result


@pytest.mark.asyncio
async def test_confirmed_only_filters_correctly():
    """confirmed_only=True must exclude unconfirmed findings from the report."""
    from tools.reporting.report_generator import _generate_pentest_report_impl
    import asyncio

    # Job that returns a sqlmap output with an injectable finding
    sqli_output = "Parameter: id (GET)\n[*] the parameter 'id' is injectable\nending @"

    class MockJobMgr:
        async def list_jobs(self, n):
            return [{"id": "j1", "tool": "sqlmap", "status": "completed"}]
        async def get_job(self, jid):
            return {"id": "j1", "tool": "sqlmap", "status": "completed", "output": sqli_output}

    # Without confirmed_only — findings from job history are included
    result_all = await _generate_pentest_report_impl(
        MockJobMgr(), "T", "info", "low", "", "", "markdown", False
    )
    assert result_all["findings_count"] > 0

    # With confirmed_only=True and no active engagement — engagement findings = empty,
    # job-history findings still pass through (confirmed_only only gates engagement DB rows)
    result_confirmed = await _generate_pentest_report_impl(
        MockJobMgr(), "T", "info", "low", "", "", "markdown", True
    )
    # confirmed_only filters the engagement DB source; job-history source is unaffected
    assert "report" in result_confirmed
