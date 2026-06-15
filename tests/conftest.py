"""Shared fixtures for kali-mcp tests."""
import asyncio
import os
import sys

import pytest
import pytest_asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Use scope=session so the event loop persists across all async tests
@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def job_mgr():
    """Initialized JobManager for the test session."""
    from job_manager import JobManager
    jm = JobManager()
    await jm.init_db()
    return jm


@pytest_asyncio.fixture(scope="session")
async def mcp_server(job_mgr):
    """Fully registered MCP server."""
    # Clear scope so all targets are allowed in tests
    from scope import clear_scope
    clear_scope()
    import server as srv
    import engagement
    srv.job_mgr = job_mgr
    await engagement.init_db()   # ensure engagement tables exist before any tool call
    return srv.mcp


async def call(mcp, tool_name: str, args: dict) -> dict:
    """Helper: call an MCP tool and return the result dict."""
    r = await mcp._tool_manager.call_tool(tool_name, args)
    return r.structuredContent if hasattr(r, "structuredContent") else r
