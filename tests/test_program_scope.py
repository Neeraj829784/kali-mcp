"""Tests for the program scope & policy engine (program_scope.py)."""
import os
import tempfile

import pytest
import pytest_asyncio

import program_scope
import scope
from tests.conftest import call


@pytest_asyncio.fixture
async def temp_programs(monkeypatch):
    """Point the program scope engine at a throwaway DB and reset scope state."""
    path = tempfile.mktemp(suffix=".db")
    monkeypatch.setattr(program_scope, "PROGRAMS_DB_PATH", path)
    program_scope._active_program = None
    scope.clear_scope()
    scope.clear_denylist()
    await program_scope.init_db()
    yield path
    program_scope._active_program = None
    scope.clear_scope()
    scope.clear_denylist()
    for p in (path, path + "-wal", path + "-shm"):
        if os.path.exists(p):
            os.unlink(p)


@pytest.mark.asyncio
async def test_start_sets_scope_and_denylist(temp_programs, mcp_server):
    r = await call(mcp_server, "program_scope_start", {
        "name": "Acme-2026",
        "in_scope": ["10.10.10.0/24", "example.com"],
        "out_of_scope": ["10.10.10.254"],
        "client": "Acme",
        "rules": {"max_findings": 100},
    })
    assert r["status"] == "started"
    assert scope.list_scope() == ["10.10.10.0/24", "example.com"]
    assert "10.10.10.254" in scope.list_denylist()


@pytest.mark.asyncio
async def test_in_scope_allowed_out_of_scope_blocked(temp_programs, mcp_server):
    await call(mcp_server, "program_scope_start", {
        "name": "P1",
        "in_scope": ["10.10.10.0/24"],
        "out_of_scope": ["10.10.10.254"],
    })
    # in-scope host is allowed
    scope.check_scope("10.10.10.5")
    # out-of-scope host is blocked even though it's inside the in-scope CIDR
    with pytest.raises(ValueError, match="OUT OF SCOPE"):
        scope.check_scope("10.10.10.254")
    # host outside the in-scope CIDR is rejected as not-in-scope
    with pytest.raises(ValueError, match="not in scope"):
        scope.check_scope("192.168.1.1")


@pytest.mark.asyncio
async def test_status_and_list(temp_programs, mcp_server):
    await call(mcp_server, "program_scope_start", {
        "name": "P2", "in_scope": ["example.com"],
    })
    status = await call(mcp_server, "program_scope_status", {})
    assert status["active"] is True
    assert status["name"] == "P2"
    listed = await call(mcp_server, "program_scope_list", {})
    assert any(p["name"] == "P2" for p in listed)


@pytest.mark.asyncio
async def test_add_and_remove_targets(temp_programs, mcp_server):
    await call(mcp_server, "program_scope_start", {"name": "P3", "in_scope": ["a.com"]})
    added = await call(mcp_server, "program_scope_add_targets", {"targets": ["b.com"]})
    assert "b.com" in added["in_scope"]
    assert "b.com" in scope.list_scope()
    removed = await call(mcp_server, "program_scope_remove_targets", {"targets": ["a.com"]})
    assert "a.com" not in removed["in_scope"]
    assert "a.com" not in scope.list_scope()


@pytest.mark.asyncio
async def test_out_of_scope_and_deny_tools(temp_programs, mcp_server):
    await call(mcp_server, "program_scope_start", {"name": "P4", "in_scope": ["10.0.0.0/8"]})
    r = await call(mcp_server, "program_scope_out_of_scope", {"targets": ["10.1.2.3"]})
    assert "10.1.2.3" in r["out_of_scope"]
    with pytest.raises(ValueError, match="OUT OF SCOPE"):
        scope.check_scope("10.1.2.3")


@pytest.mark.asyncio
async def test_end_clears_scope(temp_programs, mcp_server):
    await call(mcp_server, "program_scope_start", {
        "name": "P5", "in_scope": ["x.com"], "out_of_scope": ["y.com"],
    })
    ended = await call(mcp_server, "program_scope_end", {})
    assert ended["status"] == "ended"
    assert scope.list_scope() == []
    assert scope.list_denylist() == []


@pytest.mark.asyncio
async def test_start_when_none_active_status(temp_programs, mcp_server):
    program_scope._active_program = None
    status = await call(mcp_server, "program_scope_status", {})
    assert status.get("active") is False
