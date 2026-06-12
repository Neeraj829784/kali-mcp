"""Tests for core infrastructure: ToolExecutor, JobManager, scope."""
import asyncio
import os

import pytest
import aiosqlite
from datetime import datetime, timezone

from tools.base import ToolExecutor
from job_manager import JobManager
from scope import check_scope, set_scope, clear_scope
from config import JOBS_DB_PATH


# ── ToolExecutor ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_executor_runs_command():
    r = await ToolExecutor().run(["echo", "hello"], timeout=5)
    assert r["stdout"] == "hello"
    assert r["return_code"] == 0
    assert r["timed_out"] is False


@pytest.mark.asyncio
async def test_executor_missing_binary_gives_hint():
    """Regression: missing binary must return error + actionable hint."""
    r = await ToolExecutor().run(["nonexistent_tool_xyz"])
    assert "error" in r
    assert "hint" in r, "Missing binary must include install hint"
    assert r["return_code"] == -1


@pytest.mark.asyncio
async def test_executor_timeout_kills_process():
    r = await ToolExecutor().run(["sleep", "60"], timeout=1)
    assert r["timed_out"] is True
    assert r["return_code"] == -1


@pytest.mark.asyncio
async def test_executor_large_output_no_oom():
    """Streams to disk — must handle 100KB+ without OOM or deadlock."""
    r = await ToolExecutor().run(["python3", "-c", "print('x'*100000)"], timeout=10)
    assert len(r["stdout"]) >= 100000


# ── JobManager ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_job_create_and_complete():
    jm = JobManager()
    await jm.init_db()
    jid = await jm.create_job("test", ["echo", "done"], 10)
    await asyncio.sleep(0.5)
    job = await jm.get_job(jid)
    assert job["status"] == "completed"
    assert "done" in job.get("output", "")


@pytest.mark.asyncio
async def test_run_and_wait_blocks_and_returns():
    """Regression: run_and_wait must block until done, return result directly."""
    jm = JobManager()
    await jm.init_db()
    result = await jm.run_and_wait("test", ["echo", "wait_result"], 10)
    assert result["status"] == "completed"
    assert "wait_result" in result.get("output", "")


@pytest.mark.asyncio
async def test_job_partial_output_tail():
    jm = JobManager()
    await jm.init_db()
    jid = await jm.create_job("test", ["python3", "-c",
        "import sys\n[print(f'line_{i}') for i in range(1,21)]"], 10)
    await asyncio.sleep(1)
    job = await jm.get_job(jid, tail=5)
    lines = [l for l in job.get("output", "").strip().splitlines() if l]
    assert len(lines) <= 5
    assert "line_20" in job.get("output", "")


@pytest.mark.asyncio
async def test_job_cancel():
    jm = JobManager()
    await jm.init_db()
    jid = await jm.create_job("test", ["sleep", "60"], 120)
    await asyncio.sleep(0.3)
    assert await jm.cancel_job(jid) is True
    assert (await jm.get_job(jid))["status"] == "cancelled"


@pytest.mark.asyncio
async def test_ghost_job_reaper():
    """Regression: jobs stuck 'running' on restart must be marked failed."""
    jm = JobManager()
    await jm.init_db()
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(JOBS_DB_PATH) as db:
        await db.execute(
            "INSERT OR REPLACE INTO jobs (id,tool,status,created_at) VALUES (?,?,?,?)",
            ("ghost_test_001", "test", "running", now)
        )
        await db.commit()
    await jm.init_db()
    assert (await jm.get_job("ghost_test_001"))["status"] == "failed"


# ── Scope ─────────────────────────────────────────────────────────────────────

def test_scope_lab_mode_allows_all():
    clear_scope()
    check_scope("1.2.3.4")   # must not raise
    check_scope("evil.com")


def test_scope_blocks_out_of_scope():
    set_scope(["10.0.0.0/24", "example.com"])
    check_scope("10.0.0.5")
    check_scope("example.com")
    with pytest.raises(ValueError):
        check_scope("8.8.8.8")
    clear_scope()


def test_scope_wildcard_subdomain():
    set_scope(["*.example.com"])
    check_scope("sub.example.com")
    with pytest.raises(ValueError):
        check_scope("other.com")
    clear_scope()


def test_scope_url_extracts_hostname():
    set_scope(["example.com"])
    check_scope("http://example.com/path?q=1")
    clear_scope()
