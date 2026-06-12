"""Tests for Tier 1 features: credential vault, finding normalization."""
import os
import pytest
from tests.conftest import call
from scope import clear_scope


@pytest.fixture(autouse=True)
def lab_mode():
    clear_scope()
    yield
    clear_scope()


# ── Credential Vault ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_creds_store_and_list(mcp_server):
    r = await call(mcp_server, "creds_store", {
        "host": "10.0.0.1", "username": "admin", "password": "secret",
        "service": "ssh", "port": 22, "source_tool": "hydra"
    })
    assert r.get("stored") is True
    assert r.get("id") is not None

    r2 = await call(mcp_server, "creds_list", {"host": "10.0.0.1"})
    assert isinstance(r2, list)
    assert any(c["username"] == "admin" and c["password"] == "secret" for c in r2)


@pytest.mark.asyncio
async def test_creds_use_found(mcp_server):
    await call(mcp_server, "creds_store", {
        "host": "10.0.0.2", "username": "root", "password": "toor",
        "service": "ssh"
    })
    r = await call(mcp_server, "creds_use", {"host": "10.0.0.2", "service": "ssh"})
    assert r.get("found") is True
    assert r.get("password") == "toor"


@pytest.mark.asyncio
async def test_creds_use_not_found(mcp_server):
    r = await call(mcp_server, "creds_use", {"host": "99.99.99.99"})
    assert r.get("found") is False
    assert "hint" in r


@pytest.mark.asyncio
async def test_creds_delete(mcp_server):
    r = await call(mcp_server, "creds_store", {
        "host": "10.0.0.3", "username": "del_me", "password": "pass123"
    })
    cred_id = r.get("id")
    r2 = await call(mcp_server, "creds_delete", {"cred_id": cred_id})
    assert r2.get("deleted") is True


# ── Finding Normalization ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_findings_returns_structure(mcp_server, job_mgr):
    # Create a job with known nmap-style output
    jid = await job_mgr.create_job("nmap_port_scan", ["echo", ""], 5)
    import asyncio; await asyncio.sleep(0.3)
    job = await job_mgr.get_job(jid)
    if job.get("output_file"):
        with open(job["output_file"], "w") as f:
            f.write("22/tcp open ssh OpenSSH 9.6\n80/tcp open http Apache 2.4\n")
    r = await call(mcp_server, "get_findings", {"job_id": jid, "min_severity": "info"})
    assert "total" in r
    assert "findings" in r
    assert isinstance(r["findings"], list)


def test_extract_findings_nmap():
    from findings import extract_findings
    output = "22/tcp open ssh OpenSSH 9.6\n80/tcp open http Apache 2.4.49"
    findings = extract_findings("nmap_port_scan", output, "10.0.0.1")
    assert len(findings) == 2
    assert all(f["tool"] == "nmap" for f in findings)
    assert all(f["host"] == "10.0.0.1" for f in findings)
    assert all(f["severity"] == "info" for f in findings)


def test_extract_findings_hydra():
    from findings import extract_findings
    output = "[22][ssh] host: 10.0.0.1   login: admin   password: secret"
    findings = extract_findings("hydra", output, "10.0.0.1")
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert "admin:secret" in findings[0]["evidence"]


def test_extract_findings_sqlmap():
    from findings import extract_findings
    output = "[INFO] Parameter: id (GET) appears to be 'Boolean-based blind' injectable"
    findings = extract_findings("sqlmap", output, "10.0.0.1")
    assert len(findings) >= 1
    assert findings[0]["severity"] == "critical"


def test_extract_findings_empty_output():
    from findings import extract_findings
    findings = extract_findings("nmap_port_scan", "", "10.0.0.1")
    assert findings == []


def test_suggest_next_ssh_and_web():
    from suggest import suggest_next
    output = "22/tcp open ssh\n80/tcp open http\n445/tcp open microsoft-ds"
    suggestions = suggest_next("nmap_port_scan", output, "10.0.0.1")
    tools = [s["tool"] for s in suggestions]
    assert "hydra_bruteforce" in tools
    assert "nikto_scan" in tools
    assert "enum4linux_scan" in tools


def test_suggest_next_hydra_found_creds():
    from suggest import suggest_next
    output = "[22][ssh] host: 10.0.0.1   login: admin   password: secret"
    suggestions = suggest_next("hydra", output, "10.0.0.1")
    tools = [s["tool"] for s in suggestions]
    assert "creds_store" in tools
    assert "ssh_enum_privesc" in tools
