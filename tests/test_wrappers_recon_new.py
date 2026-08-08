"""Mock-based tests for the new recon/discovery tool wrappers.

Offline via `fake_exec` — asserts command construction and flag handling for
dnsx, httpx (PD), asnmap, gau, katana, arjun, and linkfinder.
"""
import pytest
from tests.conftest import call
from scope import clear_scope


@pytest.fixture(autouse=True)
def lab_mode():
    clear_scope()
    yield
    clear_scope()


# ── dnsx ──────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dnsx_resolve_default(mcp_server, fake_exec):
    await call(mcp_server, "dnsx_resolve", {"targets": "a.example.com,b.example.com"})
    assert fake_exec.cmd_contains("dnsx", "-l", "a.example.com,b.example.com",
                                  "-a", "-silent", "-j", "-resp")


@pytest.mark.asyncio
async def test_dnsx_resolve_record_type(mcp_server, fake_exec):
    await call(mcp_server, "dnsx_resolve",
               {"targets": "example.com", "record_type": "cname", "show_response": False})
    assert fake_exec.cmd_contains("dnsx", "-cname")
    assert "-resp" not in fake_exec.last_cmd


@pytest.mark.asyncio
async def test_dnsx_bad_record_type_rejected(mcp_server, fake_exec):
    r = await call(mcp_server, "dnsx_resolve", {"targets": "example.com", "record_type": "zzz"})
    assert "record_type" in r.get("error", "") and not fake_exec.calls


# ── httpx (PD, invoked as httpx-toolkit) ───────────────────────────────────────

@pytest.mark.asyncio
async def test_httpx_probe_flags(mcp_server, fake_exec):
    await call(mcp_server, "httpx_probe",
               {"targets": "example.com", "ports": "80,443", "follow_redirects": True,
                "match_codes": "200,301"})
    assert fake_exec.cmd_contains("httpx-toolkit", "-u", "example.com", "-json",
                                  "-sc", "-title", "-td", "-fr", "-p", "80,443", "-mc", "200,301")


@pytest.mark.asyncio
async def test_httpx_probe_no_tech(mcp_server, fake_exec):
    await call(mcp_server, "httpx_probe", {"targets": "example.com", "tech_detect": False})
    assert "-td" not in fake_exec.last_cmd


# ── asnmap ──────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_asnmap_domain(mcp_server, fake_exec):
    await call(mcp_server, "asnmap_lookup", {"query": "example.com"})
    assert fake_exec.cmd_contains("asnmap", "-d", "example.com", "-json", "-silent")


@pytest.mark.asyncio
async def test_asnmap_asn(mcp_server, fake_exec):
    await call(mcp_server, "asnmap_lookup", {"query": "AS15169", "query_type": "asn"})
    assert fake_exec.cmd_contains("asnmap", "-a", "AS15169")


@pytest.mark.asyncio
async def test_asnmap_bad_type(mcp_server, fake_exec):
    r = await call(mcp_server, "asnmap_lookup", {"query": "x", "query_type": "bogus"})
    assert "query_type" in r.get("error", "") and not fake_exec.calls


# ── gau ──────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_gau_urls(mcp_server, fake_exec):
    await call(mcp_server, "gau_urls",
               {"domain": "example.com", "providers": "wayback,otx", "match_codes": "200"})
    assert fake_exec.cmd_contains("gau", "--subs", "--providers", "wayback,otx",
                                  "--mc", "200", "example.com")


@pytest.mark.asyncio
async def test_gau_no_subs(mcp_server, fake_exec):
    await call(mcp_server, "gau_urls", {"domain": "example.com", "include_subs": False})
    assert "--subs" not in fake_exec.last_cmd


# ── katana ──────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_katana_crawl(mcp_server, fake_exec):
    await call(mcp_server, "katana_crawl",
               {"url": "https://example.com", "depth": 2, "rate_limit": 50, "crawl_duration": "30s"})
    assert fake_exec.cmd_contains("katana", "-u", "https://example.com", "-d", "2",
                                  "-rl", "50", "-jsonl", "-jc", "-ct", "30s")


@pytest.mark.asyncio
async def test_katana_headless(mcp_server, fake_exec):
    await call(mcp_server, "katana_crawl", {"url": "https://example.com", "headless": True})
    assert fake_exec.cmd_contains("katana", "-hl")


# ── arjun ──────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_arjun_params(mcp_server, fake_exec):
    await call(mcp_server, "arjun_params",
               {"url": "https://example.com/api", "method": "POST", "stable": True,
                "headers": "Authorization: Bearer x", "delay": 1})
    assert fake_exec.cmd_contains("arjun", "-u", "https://example.com/api", "-m", "POST",
                                  "--stable", "--headers", "Authorization: Bearer x", "-d", "1")


@pytest.mark.asyncio
async def test_arjun_bad_method(mcp_server, fake_exec):
    r = await call(mcp_server, "arjun_params", {"url": "https://example.com", "method": "PATCH"})
    assert "method" in r.get("error", "") and not fake_exec.calls


# ── linkfinder ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_linkfinder_extract(mcp_server, fake_exec):
    await call(mcp_server, "linkfinder_extract",
               {"input_url": "https://example.com/app.js", "regex": "^/api/"})
    # invoked via a python interpreter + linkfinder.py, output to cli
    assert fake_exec.any_cmd_contains("linkfinder.py", "-i", "https://example.com/app.js",
                                      "-o", "cli", "-r", "^/api/")


@pytest.mark.asyncio
async def test_linkfinder_domain_mode(mcp_server, fake_exec):
    await call(mcp_server, "linkfinder_extract",
               {"input_url": "https://example.com", "domain_mode": True})
    assert fake_exec.cmd_contains("-d")
