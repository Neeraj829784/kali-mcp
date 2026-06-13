"""Tests for engagement DB, cred vault, health checks, parsers, and scope."""
import os
import pytest
from scope import clear_scope, add_scope, check_scope, set_scope, remove_scope


# ── Scope ─────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def reset_scope():
    clear_scope()
    yield
    clear_scope()


def test_scope_empty_allows_any():
    """Empty scope = lab mode — no ValueError raised."""
    check_scope("192.168.1.1")  # should not raise


def test_scope_allows_exact_ip():
    add_scope("10.0.0.1")
    check_scope("10.0.0.1")  # should not raise


def test_scope_blocks_out_of_scope():
    add_scope("10.0.0.1")
    with pytest.raises(ValueError):
        check_scope("10.0.0.2")


def test_scope_cidr_match():
    add_scope("192.168.1.0/24")
    check_scope("192.168.1.100")  # in range


def test_scope_cidr_blocks_outside():
    add_scope("192.168.1.0/24")
    with pytest.raises(ValueError):
        check_scope("192.168.2.1")


def test_scope_wildcard_subdomain():
    add_scope("*.example.com")
    check_scope("sub.example.com")


def test_scope_remove():
    add_scope("10.0.0.1")
    remove_scope("10.0.0.1")
    clear_scope()
    check_scope("10.0.0.1")  # should not raise after scope is empty again


def test_scope_url_extraction():
    add_scope("example.com")
    check_scope("http://example.com/path?q=1")


# ── Parsers ───────────────────────────────────────────────────────────────────

def test_parse_nuclei_jsonl_valid():
    from parsers import parse_nuclei_jsonl
    line = '{"template-id":"test","info":{"name":"XSS","severity":"high"},"host":"http://x.com","matched-at":"http://x.com/p"}'
    result = parse_nuclei_jsonl(line)
    assert result["total"] == 1
    assert result["findings"][0]["severity"] == "high"
    assert result["findings"][0]["name"] == "XSS"


def test_parse_nuclei_jsonl_empty():
    from parsers import parse_nuclei_jsonl
    result = parse_nuclei_jsonl("")
    assert result["total"] == 0


def test_parse_nmap_xml_invalid():
    from parsers import parse_nmap_xml
    result = parse_nmap_xml("not xml")
    assert result.get("parse_error") is True


def test_parse_nmap_xml_no_hosts():
    from parsers import parse_nmap_xml
    xml = '<?xml version="1.0"?><nmaprun></nmaprun>'
    result = parse_nmap_xml(xml)
    assert result["total"] == 0
    assert result["hosts"] == []


# ── Cred vault ────────────────────────────────────────────────────────────────

def test_cred_vault_encrypt_decrypt_roundtrip():
    from cred_vault import _encrypt, _decrypt
    plaintext = "s3cr3t_p@ssword!"
    encrypted = _encrypt(plaintext)
    assert encrypted != plaintext
    assert _decrypt(encrypted) == plaintext


def test_cred_vault_empty_passthrough():
    from cred_vault import _encrypt, _decrypt
    assert _encrypt("") == ""
    assert _decrypt("") == ""


def test_cred_vault_get_all_returns_list():
    from cred_vault import get_all_credentials
    result = get_all_credentials(limit=5)
    assert isinstance(result, list)


# ── Health ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_server_health_returns_structure(mcp_server):
    from tests.conftest import call
    result = await call(mcp_server, "server_health", {})
    assert "overall_status" in result
    assert result["overall_status"] in ("healthy", "degraded")
    assert "categories" in result
    assert "python_deps" in result


@pytest.mark.asyncio
async def test_check_binary_nmap(mcp_server):
    from tests.conftest import call
    result = await call(mcp_server, "check_binary", {"name": "nmap"})
    assert "installed" in result
    assert isinstance(result["installed"], bool)


# ── Engagement DB ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_engagement_start_sets_active(mcp_server):
    from tests.conftest import call
    r = await call(mcp_server, "engagement_start", {
        "name": "test-eng-pytest", "scope": ["127.0.0.1"], "client": "TestClient"
    })
    assert r.get("status") == "started"
    assert r.get("engagement") == "test-eng-pytest"

    status = await call(mcp_server, "engagement_status", {})
    assert status.get("active") is True
    assert status["name"] == "test-eng-pytest"

    # Cleanup
    await call(mcp_server, "engagement_end", {})


@pytest.mark.asyncio
async def test_engagement_end_clears_active(mcp_server):
    from tests.conftest import call
    await call(mcp_server, "engagement_start", {
        "name": "test-eng-end-pytest", "scope": []
    })
    r = await call(mcp_server, "engagement_end", {})
    assert r.get("status") == "ended"

    status = await call(mcp_server, "engagement_status", {})
    assert status.get("active") is False
