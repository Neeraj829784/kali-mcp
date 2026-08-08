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


class _FakeExecCtl:
    """Handle returned by the fake_exec fixture for inspecting/controlling calls."""
    def __init__(self):
        self.calls = []          # list of {"cmd", "tool_name", "timeout"}
        self._output = ""        # str or callable(cmd, tool_name) -> str

    def set_output(self, value):
        """Set the fake stdout: a string, or a callable(cmd, tool_name) -> str."""
        self._output = value

    def _resolve(self, cmd, tool_name):
        out = self._output
        return out(cmd, tool_name) if callable(out) else out

    @property
    def last_cmd(self):
        return self.calls[-1]["cmd"] if self.calls else None

    @property
    def last_cmd_str(self):
        return " ".join(self.last_cmd) if self.last_cmd else ""

    def cmd_contains(self, *fragments):
        """True if every fragment appears in the most recent command line."""
        s = self.last_cmd_str
        return all(f in s for f in fragments)

    def any_cmd_contains(self, *fragments):
        """True if any recorded command line contains all fragments."""
        for c in self.calls:
            s = " ".join(c["cmd"])
            if all(f in s for f in fragments):
                return True
        return False


@pytest.fixture
def fake_exec(monkeypatch):
    """Replace ToolExecutor.run with a fake — no real binaries, no network.

    This is THE seam that covers the tool-wrapper layer: every tool (whether it
    calls `_ex.run(...)` directly or goes through `job_manager.run_and_wait`,
    which uses its own ToolExecutor) invokes `ToolExecutor.run`. Patching the
    class method intercepts all of them.

    The fake records each command for assertions and returns canned stdout,
    writing it to `output_file` when given so the JobManager's file-based read
    path works too.
    """
    ctl = _FakeExecCtl()

    async def fake_run(self, cmd, timeout=120, output_file="",
                       pid_holder=None, tool_name=""):
        ctl.calls.append({"cmd": list(cmd), "tool_name": tool_name, "timeout": timeout})
        out = ctl._resolve(cmd, tool_name)
        if output_file:
            try:
                with open(output_file, "w") as fh:
                    fh.write(out)
            except OSError:
                pass
        return {
            "stdout": out.strip(),
            "stderr": "",
            "return_code": 0,
            "timed_out": False,
            "output_file": output_file or None,
        }

    monkeypatch.setattr("tools.base.ToolExecutor.run", fake_run)

    # Defense against test-ordering leaks: some tests patch the *instance*
    # attribute `job_manager._executor.run`, which (via a monkeypatch quirk) can
    # leave a stale instance attribute shadowing the class method — bypassing the
    # class-level patch above for the run_and_wait path. Drop any such shadow so
    # `_executor.run` resolves to our patched class method.
    import job_manager
    if "run" in job_manager._executor.__dict__:
        del job_manager._executor.__dict__["run"]

    return ctl
