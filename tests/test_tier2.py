"""Tests for Tier 2 features: cve_to_exploit, web_crawl, fast_port_scan, screenshot, scope tools."""
import pytest
from tests.conftest import call
from scope import clear_scope, set_scope, list_scope


@pytest.fixture(autouse=True)
def lab_mode():
    clear_scope()
    yield
    clear_scope()


# ── CVE-to-Exploit ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cve_to_exploit_finds_vsftpd(mcp_server):
    """vsftpd 2.3.4 has a backdoor — well-known, must be found."""
    r = await call(mcp_server, "cve_to_exploit", {
        "service": "vsftpd", "version": "2.3.4"
    })
    assert r.get("exploitdb_count", 0) > 0 or r.get("msf_count", 0) > 0, \
        "vsftpd 2.3.4 must have known exploits in searchsploit or msf"
    assert r.get("query") == "vsftpd 2.3.4"


@pytest.mark.asyncio
async def test_cve_to_exploit_banner_parsing(mcp_server):
    """Banner auto-parsing must extract service + version."""
    r = await call(mcp_server, "cve_to_exploit", {
        "service": "", "banner": "Apache httpd 2.4.49 (Ubuntu)"
    })
    assert r.get("service") == "Apache"
    assert r.get("version") == "2.4.49"
    assert r.get("exploitdb_count", 0) > 0


@pytest.mark.asyncio
async def test_cve_to_exploit_openssh_banner(mcp_server):
    r = await call(mcp_server, "cve_to_exploit", {
        "service": "", "banner": "OpenSSH 7.4 (protocol 2.0)"
    })
    assert r.get("service") == "OpenSSH"
    assert "7.4" in r.get("version", "")


@pytest.mark.asyncio
async def test_cve_to_exploit_no_service_error(mcp_server):
    r = await call(mcp_server, "cve_to_exploit", {"service": "", "banner": ""})
    assert "error" in r


# ── Web Crawler ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_web_crawl_visits_pages(mcp_server):
    r = await call(mcp_server, "web_crawl", {
        "url": "http://example.com/", "max_depth": 1, "max_pages": 5
    })
    assert r.get("pages_visited", 0) >= 1
    assert isinstance(r.get("forms"), list)
    assert isinstance(r.get("all_urls"), list)
    assert "http://example.com/" in r.get("all_urls", [])


@pytest.mark.asyncio
async def test_web_crawl_out_of_scope_blocked(mcp_server):
    set_scope(["example.com"])
    try:
        r = await call(mcp_server, "web_crawl", {
            "url": "http://notinscope.example.net/", "max_depth": 1
        })
        assert "error" in r
    except Exception as e:
        assert "scope" in str(e).lower()


# ── Scope Tools ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_scope_set_and_list(mcp_server):
    r = await call(mcp_server, "scope_set", {"targets": ["10.0.0.1", "192.168.1.0/24"]})
    scope = r.get("scope", [])
    assert "10.0.0.1" in scope
    assert "192.168.1.0/24" in scope
    clear_scope()


@pytest.mark.asyncio
async def test_scope_add_and_remove(mcp_server):
    clear_scope()
    await call(mcp_server, "scope_add", {"target": "172.16.0.1"})
    assert "172.16.0.1" in list_scope()
    r = await call(mcp_server, "scope_remove", {"target": "172.16.0.1"})
    assert r.get("removed") is True
    assert "172.16.0.1" not in list_scope()


@pytest.mark.asyncio
async def test_scope_clear(mcp_server):
    set_scope(["1.2.3.4", "5.6.7.8"])
    r = await call(mcp_server, "scope_clear", {})
    assert r.get("mode") == "lab (all targets allowed)"
    assert list_scope() == []


# ── Screenshot ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_screenshot_url_runs(mcp_server):
    """screenshot_url must complete without crashing — screenshot may or may not be created."""
    r = await call(mcp_server, "screenshot_url", {"url": "http://example.com/"})
    assert r.get("status") in ("completed", "failed")
    assert "screenshot_dir" in r
    assert isinstance(r.get("screenshots"), list)


@pytest.mark.asyncio
async def test_screenshot_urls_batch(mcp_server):
    r = await call(mcp_server, "screenshot_urls", {
        "urls": ["http://example.com/", "http://example.org/"],
        "threads": 2
    })
    assert r.get("status") in ("completed", "failed")
    assert isinstance(r.get("screenshots"), list)


# ── fast_port_scan ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.timeout(60)
async def test_fast_port_scan_localhost(mcp_server):
    """fast_port_scan must run masscan and return a result (even if no ports found)."""
    r = await call(mcp_server, "fast_port_scan", {
        "target": "127.0.0.1", "ports": "80,443,22",
        "rate": 100, "service_detection": False
    })
    # masscan needs root — may error, but must not crash
    assert isinstance(r, dict)
    assert "open_ports" in r or "error" in r
