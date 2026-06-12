"""Tests for reporting, PCAP, and file tools."""
import os
import tempfile
import pytest
from tests.conftest import call
from scope import clear_scope


@pytest.fixture(autouse=True)
def lab_mode():
    clear_scope()
    yield
    clear_scope()


@pytest.mark.asyncio
async def test_generate_report_markdown(mcp_server, job_mgr):
    result = await job_mgr.run_and_wait("test", ["echo", "scan_output"], 10)
    jid = (await job_mgr.list_jobs(1))[0]["id"]
    r = await call(mcp_server, "generate_report", {
        "job_ids": [jid], "title": "Test Report", "format": "markdown"
    })
    report = r.get("report", "")
    assert "# Test Report" in report
    assert len(report) > 50


@pytest.mark.asyncio
async def test_generate_report_json(mcp_server, job_mgr):
    await job_mgr.run_and_wait("test", ["echo", "json_test"], 10)
    jid = (await job_mgr.list_jobs(1))[0]["id"]
    r = await call(mcp_server, "generate_report", {
        "job_ids": [jid], "format": "json"
    })
    import json
    data = json.loads(r.get("report", "{}"))
    assert "jobs" in data
    assert "generated_at" in data


@pytest.mark.asyncio
async def test_list_completed_jobs(mcp_server, job_mgr):
    await job_mgr.run_and_wait("whois", ["echo", "whois_test"], 10)
    r = await call(mcp_server, "list_completed_jobs", {"tool_filter": "whois"})
    assert isinstance(r, list)
    assert all(j["status"] == "completed" for j in r)


@pytest.mark.asyncio
async def test_parse_nmap_xml(mcp_server, job_mgr):
    import subprocess
    xml = subprocess.run(
        ["nmap", "-oX", "-", "-sT", "-p", "80", "-Pn", "127.0.0.1"],
        capture_output=True, text=True
    ).stdout
    jid = await job_mgr.create_job("nmap_port_scan", ["echo", ""], 5)
    import asyncio; await asyncio.sleep(0.3)
    job = await job_mgr.get_job(jid)
    if job.get("output_file"):
        with open(job["output_file"], "w") as f:
            f.write(xml)
        r = await call(mcp_server, "parse_nmap_output", {"job_id": jid})
        assert "hosts" in r
        assert r["total"] >= 1


@pytest.mark.asyncio
async def test_pcap_protocols(mcp_server):
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
        pcap_path = f.name
    import subprocess
    subprocess.run(
        ["tshark", "-i", "lo", "-w", pcap_path, "-a", "duration:1"],
        capture_output=True
    )
    r = await call(mcp_server, "pcap_protocols", {"pcap_path": pcap_path})
    assert "error" not in r
    assert "protocol_hierarchy" in r
    os.unlink(pcap_path)


@pytest.mark.asyncio
async def test_pcap_extract_missing_file(mcp_server):
    r = await call(mcp_server, "pcap_extract", {"pcap_path": "/nonexistent.pcap"})
    assert "error" in r


@pytest.mark.asyncio
async def test_tshark_query_runs(mcp_server):
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
        pcap_path = f.name
    import subprocess
    subprocess.run(
        ["tshark", "-i", "lo", "-w", pcap_path, "-a", "duration:1"],
        capture_output=True
    )
    r = await call(mcp_server, "tshark_query", {
        "pcap_path": pcap_path,
        "display_filter": "",
        "max_lines": 10
    })
    assert "error" not in r or r.get("return_code") is not None
    os.unlink(pcap_path)


@pytest.mark.asyncio
async def test_read_file_text(mcp_server, tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("hello pytest")
    r = await call(mcp_server, "read_file", {"path": str(f)})
    assert r.get("content") == "hello pytest"
    assert r.get("type") == "text"


@pytest.mark.asyncio
async def test_read_file_elf_binary(mcp_server):
    from config import ARTIFACTS_DIR
    elf_path = os.path.join(ARTIFACTS_DIR, "pytest_payload.elf")
    if not os.path.exists(elf_path):
        pytest.skip("ELF payload not generated yet")
    r = await call(mcp_server, "read_file", {"path": elf_path})
    assert "ELF" in r.get("type", "")
    assert "hex_preview" in r


@pytest.mark.asyncio
async def test_read_file_path_restriction(mcp_server):
    r = await call(mcp_server, "read_file", {"path": "/etc/shadow"})
    assert "error" in r
    assert "hint" in r


@pytest.mark.asyncio
async def test_list_artifacts(mcp_server):
    r = await call(mcp_server, "list_artifacts", {})
    assert "artifacts" in r
    assert isinstance(r["artifacts"], list)
    assert "count" in r


@pytest.mark.asyncio
async def test_server_health_all_tools_installed(mcp_server):
    r = await call(mcp_server, "server_health", {})
    assert r.get("overall_status") == "healthy", \
        f"Missing tools: {r.get('missing', [])}"
    assert r.get("missing") == []


@pytest.mark.asyncio
async def test_check_binary_installed(mcp_server):
    r = await call(mcp_server, "check_binary", {"name": "nmap"})
    assert r.get("installed") is True
    assert r.get("path") == "/usr/bin/nmap"


@pytest.mark.asyncio
async def test_check_binary_missing(mcp_server):
    r = await call(mcp_server, "check_binary", {"name": "nonexistent_xyz"})
    assert r.get("installed") is False
    assert r.get("path") is None
