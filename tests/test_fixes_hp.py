"""
Tests for the 3 high-priority fixes:
  Fix 1 — engagement.py async (aiosqlite)
  Fix 2 — triage fast path via engagement DB
  Fix 3 — rate limiting in ToolExecutor
"""
import asyncio
import time

import pytest
import pytest_asyncio


# ── Fix 1: engagement.py is fully async ──────────────────────────────────────

@pytest.mark.asyncio
async def test_engagement_init_db_is_async(tmp_path, monkeypatch):
    """init_db() must be awaitable and create tables without blocking."""
    import engagement
    monkeypatch.setattr(engagement, "ENGAGEMENT_DB", str(tmp_path / "test_eng.db"))
    # Should not raise, should complete without asyncio.to_thread
    await engagement.init_db()
    # Verify tables were created
    import aiosqlite
    async with aiosqlite.connect(str(tmp_path / "test_eng.db")) as db:
        async with db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ) as cur:
            tables = {row[0] for row in await cur.fetchall()}
    assert "engagements" in tables
    assert "eng_findings" in tables


@pytest.mark.asyncio
async def test_tag_finding_is_async(tmp_path, monkeypatch):
    """tag_finding() must be a native coroutine — no to_thread wrapper needed."""
    import inspect
    import engagement

    db_path = str(tmp_path / "eng_tag.db")
    monkeypatch.setattr(engagement, "ENGAGEMENT_DB", db_path)
    await engagement.init_db()

    # Verify it's a coroutine function
    assert inspect.iscoroutinefunction(engagement.tag_finding), \
        "tag_finding must be async def"

    # Create a real engagement row so FK constraint passes
    import aiosqlite
    from datetime import datetime, timezone
    async with aiosqlite.connect(db_path) as db:
        await db.execute("PRAGMA foreign_keys=OFF")
        await db.execute(
            "INSERT INTO engagements (id,name,status,scope,notes,created_at) VALUES (1,'t','active','[]','',?)",
            (datetime.now(timezone.utc).isoformat(),)
        )
        await db.commit()

    monkeypatch.setattr(engagement, "_active", {"id": 1, "name": "test", "scope": [], "client": ""})

    # Must complete without error
    await engagement.tag_finding(
        {"host": "10.0.0.1", "title": "Test", "severity": "low",
         "evidence": "x", "tool": "nmap", "port": 80, "service": "http"},
        job_id="abc123",
    )

    # Verify the row was inserted
    async with aiosqlite.connect(db_path) as db:
        async with db.execute("SELECT COUNT(*) FROM eng_findings") as cur:
            count = (await cur.fetchone())[0]
    assert count == 1


@pytest.mark.asyncio
async def test_engagement_start_and_status(tmp_path, monkeypatch):
    """Full engagement_start → engagement_status round-trip via async DB."""
    import engagement

    db_path = str(tmp_path / "eng2.db")
    monkeypatch.setattr(engagement, "ENGAGEMENT_DB", db_path)
    monkeypatch.setattr(engagement, "_active", None)

    import scope as scope_mod
    monkeypatch.setattr(scope_mod, "set_scope", lambda entries: None)
    monkeypatch.setattr(scope_mod, "clear_scope", lambda: None)

    await engagement.init_db()

    called = {}

    class FakeMCP:
        def tool(self):
            def decorator(fn):
                called[fn.__name__] = fn
                return fn
            return decorator

    engagement._register(FakeMCP(), None)

    result = await called["engagement_start"](
        name="TestEng", scope=["10.0.0.1"], client="ACME"
    )
    assert result["status"] == "started"
    assert result["engagement"] == "TestEng"

    status = await called["engagement_status"]()
    assert status["active"] is True
    assert status["name"] == "TestEng"


# ── Fix 2: triage fast path ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_triage_fast_path_uses_db(tmp_path, monkeypatch):
    """When an engagement is active, _load_findings_fast must read from DB
    and NOT call job_mgr.list_jobs (the slow O(n) path)."""
    import aiosqlite
    import engagement
    import triage

    db_path = str(tmp_path / "eng_fast.db")
    monkeypatch.setattr(engagement, "ENGAGEMENT_DB", db_path)
    monkeypatch.setattr(engagement, "_active", {"id": 1, "name": "FastTest", "scope": [], "client": ""})

    # Create the table and insert a pre-tagged finding
    async with aiosqlite.connect(db_path) as db:
        await db.execute("""
            CREATE TABLE eng_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                host TEXT, port INTEGER, service TEXT,
                title TEXT, severity TEXT, evidence TEXT,
                tool TEXT, job_id TEXT, added_at TEXT,
                status TEXT DEFAULT 'unconfirmed'
            )
        """)
        await db.execute(
            "INSERT INTO eng_findings "
            "(engagement_id,host,port,service,title,severity,evidence,tool,job_id,added_at) "
            "VALUES (1,'10.0.0.1',22,'ssh','Open port 22/ssh','info','ssh','nmap','j1','2026-01-01T00:00:00')"
        )
        await db.commit()

    # job_mgr must NOT be called (fast path skips it)
    class StrictJobMgr:
        async def list_jobs(self, *a, **kw):
            raise AssertionError("Fast path should not call list_jobs when engagement is active")

    findings, host_services = await triage._load_findings_fast(StrictJobMgr(), host="")
    assert len(findings) == 1
    assert findings[0]["title"] == "Open port 22/ssh"
    assert "10.0.0.1" in host_services


@pytest.mark.asyncio
async def test_triage_fallback_path_no_engagement(monkeypatch):
    """When no engagement is active, _load_findings_fast falls back to job scan."""
    import engagement
    import triage

    monkeypatch.setattr(engagement, "_active", None)

    jobs_called = []

    class FakeJobMgr:
        async def list_jobs(self, limit):
            jobs_called.append(limit)
            return []  # empty — just verifying the path is taken

    findings, host_services = await triage._load_findings_fast(FakeJobMgr(), host="")
    assert jobs_called, "Fallback path must call list_jobs when no engagement is active"
    assert findings == []


# ── Fix 3: rate limiting ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rate_gate_enforces_interval(monkeypatch):
    """_rate_gate must enforce minimum inter-call spacing for rate-limited tools."""
    from tools.base import _rate_gate, _rate_last, _rate_locks

    # Clean state for this test
    _rate_last.clear()
    _rate_locks.clear()

    # Monkeypatch RATE_LIMITS to 2 req/sec for a fake tool
    import config
    monkeypatch.setitem(config.RATE_LIMITS, "test_tool_rl", 2)  # 0.5s interval

    t0 = time.monotonic()
    await _rate_gate("test_tool_rl")   # first call — no wait
    await _rate_gate("test_tool_rl")   # second call — must wait ~0.5s
    elapsed = time.monotonic() - t0

    assert elapsed >= 0.45, f"Rate gate should enforce ~0.5s interval, got {elapsed:.3f}s"


@pytest.mark.asyncio
async def test_rate_gate_no_limit_passes_immediately(monkeypatch):
    """Tools with rate limit 0 must pass through instantly."""
    from tools.base import _rate_gate, _rate_last, _rate_locks

    _rate_last.clear()
    _rate_locks.clear()

    import config
    monkeypatch.setitem(config.RATE_LIMITS, "unlimited_tool", 0)

    t0 = time.monotonic()
    for _ in range(5):
        await _rate_gate("unlimited_tool")
    elapsed = time.monotonic() - t0

    assert elapsed < 0.1, f"Zero rate limit should not throttle, got {elapsed:.3f}s"


@pytest.mark.asyncio
async def test_tool_executor_passes_tool_name_to_rate_gate(monkeypatch):
    """ToolExecutor.run() must pass tool_name to _rate_gate, not just binary name."""
    from tools import base

    gated: list[str] = []

    async def fake_rate_gate(name: str):
        gated.append(name)

    monkeypatch.setattr(base, "_rate_gate", fake_rate_gate)

    ex = base.ToolExecutor()
    # Use 'true' — guaranteed to exist on Linux, exits 0 immediately
    await ex.run(["true"], timeout=5, tool_name="gobuster_dir")

    assert "gobuster_dir" in gated, \
        "ToolExecutor must pass tool_name to _rate_gate"
