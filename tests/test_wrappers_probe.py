"""Probe: confirm the fake_exec seam intercepts both execution paths."""
import pytest
from tests.conftest import call
from scope import clear_scope


@pytest.fixture(autouse=True)
def lab_mode():
    clear_scope()
    yield
    clear_scope()


@pytest.mark.asyncio
async def test_fake_intercepts_direct_ex_run(mcp_server, fake_exec):
    # whois_lookup uses _ex.run(...) directly (no job manager)
    fake_exec.set_output("Domain Name: EXAMPLE.COM\nRegistrar: Test")
    r = await call(mcp_server, "whois_lookup", {"target": "example.com"})
    assert fake_exec.cmd_contains("whois", "example.com")
    assert "EXAMPLE.COM" in r.get("stdout", "")


@pytest.mark.asyncio
async def test_fake_intercepts_run_and_wait(mcp_server, fake_exec):
    # subfinder_enumerate goes through job_manager.run_and_wait
    fake_exec.set_output("")   # empty output — just checking command construction
    r = await call(mcp_server, "subfinder_enumerate", {"domain": "example.com"})
    assert fake_exec.cmd_contains("subfinder", "-d", "example.com")
    assert r.get("status") == "completed"
