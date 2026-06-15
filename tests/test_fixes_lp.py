"""
Tests for the 5 low-priority fixes:
  Fix 1 — nmap XML output mode (nmap_xml_scan)
  Fix 2 — masscan first-pass in scan_host deep mode
  Fix 3 — screenshots in scan_web
  Fix 4 — unified wait= param on nmap_port_scan
  Fix 5 — webhook notification on critical/high findings
"""
import asyncio
import pytest
import pytest_asyncio


# ── Fix 1: nmap XML output mode ───────────────────────────────────────────────

def test_parse_nmap_xml_structured_output():
    """parse_nmap_xml must return hosts[] with ports[] and services."""
    from parsers import parse_nmap_xml
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <status state="up"/>
        <address addr="10.0.0.1" addrtype="ipv4"/>
        <hostnames><hostname name="target"/></hostnames>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH" version="8.9"/>
          </port>
          <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http" product="nginx" version="1.24"/>
          </port>
        </ports>
      </host>
    </nmaprun>"""
    result = parse_nmap_xml(xml)
    assert result["total"] == 1
    host = result["hosts"][0]
    assert host["ip"] == "10.0.0.1"
    assert len(host["ports"]) == 2
    ports_by_num = {p["port"]: p for p in host["ports"]}
    assert ports_by_num[22]["service"] == "ssh"
    assert "OpenSSH" in ports_by_num[22]["version"]
    assert ports_by_num[80]["service"] == "http"


def test_nmap_xml_scan_registered():
    """nmap_xml_scan must be importable and have the right signature."""
    import inspect
    # Import the module — we can't call the tool directly without a live nmap
    # but we can verify the function exists with the right params
    import tools.reconnaissance.nmap as nmap_mod
    # The module defines _register; after registration nmap_xml_scan would exist
    # We verify the source contains the tool definition
    import ast
    source = open("tools/reconnaissance/nmap.py").read()
    tree = ast.parse(source)
    func_names = [n.name for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef)]
    assert "nmap_xml_scan" in func_names, "nmap_xml_scan must be defined"


# ── Fix 2: masscan first-pass in scan_host deep ───────────────────────────────

def test_workflow_imports_shutil():
    """workflow.py must import shutil (used for masscan binary check)."""
    import ast
    source = open("workflow.py").read()
    tree = ast.parse(source)
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)
    assert "shutil" in imports, "workflow.py must import shutil for masscan check"


def test_masscan_path_in_scan_host_deep():
    """scan_host deep mode must reference masscan binary check."""
    source = open("workflow.py").read()
    assert 'shutil.which("masscan")' in source, \
        "scan_host deep mode must check for masscan binary"
    assert "10000" in source, \
        "deep mode masscan rate should be 10000 pps"


# ── Fix 3: screenshots in scan_web ───────────────────────────────────────────

def test_scan_web_includes_screenshots_key():
    """scan_web must return a 'screenshots' key in its result."""
    import ast
    source = open("workflow.py").read()
    assert '"screenshots"' in source or "'screenshots'" in source, \
        "scan_web must include screenshots in its return dict"
    assert 'shutil.which("gowitness")' in source, \
        "scan_web must check for gowitness binary before screenshotting"


def test_screenshot_inline_helper_exists():
    """_screenshot_urls_inline helper must be defined in workflow.py."""
    import ast
    source = open("workflow.py").read()
    tree = ast.parse(source)
    func_names = [n.name for n in ast.walk(tree)
                  if isinstance(n, (ast.AsyncFunctionDef, ast.FunctionDef))]
    assert "_screenshot_urls_inline" in func_names


# ── Fix 4: unified wait= param ───────────────────────────────────────────────

def test_nmap_port_scan_has_wait_param():
    """nmap_port_scan must have a wait: bool parameter."""
    import ast
    source = open("tools/reconnaissance/nmap.py").read()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "nmap_port_scan":
            args = [a.arg for a in node.args.args]
            assert "wait" in args, "nmap_port_scan must have a 'wait' parameter"
            return
    pytest.fail("nmap_port_scan function not found")


@pytest.mark.asyncio
async def test_nmap_port_scan_wait_false_returns_job_id(tmp_path, monkeypatch):
    """wait=False (default) must return a job_id dict, not block."""
    import job_manager as jm_mod
    from job_manager import JobManager

    monkeypatch.setattr(jm_mod, "JOBS_DB_PATH", str(tmp_path / "jobs.db"))
    monkeypatch.setattr(jm_mod, "ARTIFACTS_DIR", str(tmp_path))

    async def mock_run(*a, **kw):
        return {"timed_out": False, "return_code": 0, "stdout": "mock nmap output"}

    monkeypatch.setattr(jm_mod._executor, "run", mock_run)

    jm = JobManager()
    await jm.init_db()

    # Simulate the nmap tool registration inline
    from scope import clear_scope
    clear_scope()

    from tools.base import ToolExecutor
    import tools.reconnaissance.nmap as nmap_mod
    monkeypatch.setattr(nmap_mod, "_IS_ROOT", False)

    called_wait = {}

    class FakeMCP:
        def tool(self):
            def decorator(fn):
                called_wait[fn.__name__] = fn
                return fn
            return decorator

    nmap_mod._register(FakeMCP(), jm)

    result = await called_wait["nmap_port_scan"]("127.0.0.1", ports="80", wait=False)
    assert "job_id" in result, f"wait=False must return job_id, got: {result}"


# ── Fix 5: webhook notification ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_webhook_fires_on_critical(monkeypatch):
    """notify() must POST to webhook URL for critical findings."""
    import webhook as wh

    monkeypatch.setattr(wh, "WEBHOOK_URL", "https://hooks.example.com/test")
    monkeypatch.setattr(wh, "WEBHOOK_MIN_SEVERITY", "critical")

    posted: list[dict] = []

    import httpx

    class MockResponse:
        status_code = 200
        text = "ok"

    class MockClient:
        def __init__(self, **kwargs):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            pass
        async def post(self, url, content, headers):
            import json
            posted.append({"url": url, "body": json.loads(content)})
            return MockResponse()

    monkeypatch.setattr(httpx, "AsyncClient", MockClient)

    finding = {
        "title": "SQL Injection confirmed",
        "severity": "critical",
        "host": "10.0.0.1",
        "tool": "sqlmap",
        "evidence": "injectable parameter id",
    }
    await wh.notify(finding, engagement_name="TestEng")

    assert len(posted) == 1
    assert posted[0]["url"] == "https://hooks.example.com/test"


@pytest.mark.asyncio
async def test_webhook_skips_below_threshold(monkeypatch):
    """notify() must NOT fire for findings below min severity."""
    import webhook as wh

    monkeypatch.setattr(wh, "WEBHOOK_URL", "https://hooks.example.com/test")
    monkeypatch.setattr(wh, "WEBHOOK_MIN_SEVERITY", "critical")

    import httpx
    posted = []

    class MockClient:
        def __init__(self, **kwargs):
            pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
        async def post(self, *a, **kw): posted.append(1)

    monkeypatch.setattr(httpx, "AsyncClient", MockClient)

    await wh.notify({"title": "Info", "severity": "low", "host": "x", "tool": "nmap", "evidence": ""})
    assert not posted, "Low severity must not trigger webhook when threshold is critical"


@pytest.mark.asyncio
async def test_webhook_disabled_when_no_url(monkeypatch):
    """notify() must silently skip when WEBHOOK_URL is empty."""
    import webhook as wh
    monkeypatch.setattr(wh, "WEBHOOK_URL", "")

    # Should not raise, not call anything
    await wh.notify({"title": "Critical!", "severity": "critical",
                     "host": "10.0.0.1", "tool": "nmap", "evidence": ""})


def test_webhook_slack_payload_shape(monkeypatch):
    """_build_payload must produce Slack-compatible shape for Slack URLs."""
    import webhook as wh
    monkeypatch.setattr(wh, "WEBHOOK_URL", "https://hooks.slack.com/services/XXX")
    finding = {"title": "RCE", "severity": "critical", "host": "10.0.0.1",
               "tool": "metasploit", "evidence": "shell spawned"}
    payload = wh._build_payload(finding, "TestEng")
    assert "text" in payload
    assert "attachments" in payload
    assert "critical" in payload["text"].upper() or "CRITICAL" in payload["text"]


def test_webhook_discord_payload_shape(monkeypatch):
    """_build_payload must produce Discord embed shape for Discord URLs."""
    import webhook as wh
    monkeypatch.setattr(wh, "WEBHOOK_URL", "https://discord.com/api/webhooks/123/abc")
    finding = {"title": "SQLi", "severity": "high", "host": "10.0.0.2",
               "tool": "sqlmap", "evidence": "injectable"}
    payload = wh._build_payload(finding, "")
    assert "embeds" in payload
    assert len(payload["embeds"]) == 1


def test_webhook_generic_payload_shape(monkeypatch):
    """_build_payload must produce flat JSON for generic endpoints."""
    import webhook as wh
    monkeypatch.setattr(wh, "WEBHOOK_URL", "https://api.example.com/alerts")
    finding = {"title": "Open port", "severity": "info", "host": "10.0.0.3",
               "tool": "nmap", "evidence": "22/tcp open"}
    payload = wh._build_payload(finding, "EngX")
    assert payload["severity"] == "info"
    assert payload["host"] == "10.0.0.3"
    assert payload["engagement"] == "EngX"
