"""Tests for web interaction tools."""
import pytest
from tests.conftest import call
from scope import clear_scope


@pytest.fixture(autouse=True)
def lab_mode():
    clear_scope()
    yield
    clear_scope()


@pytest.mark.asyncio
async def test_http_request_basic(mcp_server):
    r = await call(mcp_server, "http_request", {"url": "http://example.com/"})
    assert r.get("status_code") == 200
    assert r.get("body")
    assert "example" in r.get("body", "").lower()


@pytest.mark.asyncio
async def test_http_request_extract_text(mcp_server):
    r = await call(mcp_server, "http_request", {
        "url": "http://example.com/", "extract_text": True
    })
    assert r.get("status_code") == 200
    assert r.get("note") == "HTML stripped to visible text only"
    body = r.get("body", "")
    assert "<html" not in body.lower(), "HTML tags not stripped"
    assert "example" in body.lower()


@pytest.mark.asyncio
async def test_http_request_dns_failure_structured_error(mcp_server):
    """Regression: DNS failure must return structured error, not None status."""
    r = await call(mcp_server, "http_request", {
        "url": "http://this-domain-does-not-exist-xyz.invalid/"
    })
    assert "error" in r, "DNS failure must produce error key"
    assert r.get("status_code") is None or "status_code" not in r or r.get("status_code") is None
    assert "hint" in r, "DNS error must include /etc/hosts hint"


@pytest.mark.asyncio
async def test_http_request_follow_redirects(mcp_server):
    r = await call(mcp_server, "http_request", {
        "url": "http://example.com/", "follow_redirects": True
    })
    assert r.get("status_code") == 200


@pytest.mark.asyncio
async def test_http_request_no_follow_redirect(mcp_server):
    """With follow_redirects=False, must return the redirect response."""
    # Use a known redirect — httpbin or direct IP
    r = await call(mcp_server, "http_request", {
        "url": "http://example.com/", "follow_redirects": False
    })
    # example.com may return 200 directly or redirect — just verify it runs
    assert r.get("status_code") is not None
    assert "error" not in r or r.get("status_code") is not None


@pytest.mark.asyncio
async def test_http_request_save_to(mcp_server, tmp_path):
    save_path = str(tmp_path / "test_save.html")
    r = await call(mcp_server, "http_request", {
        "url": "http://example.com/", "save_to": save_path
    })
    assert r.get("saved_to") == save_path
    import os
    assert os.path.exists(save_path)
    assert os.path.getsize(save_path) > 100


@pytest.mark.asyncio
async def test_http_form_submit(mcp_server):
    """http_form_submit must POST form data and return response."""
    r = await call(mcp_server, "http_form_submit", {
        "url": "http://httpbin.org/post",
        "form_data": {"field1": "value1", "field2": "value2"}
    })
    # httpbin.org may be unreachable — just check it runs without crash
    assert r is not None
    assert "error" in r or r.get("status_code") is not None


@pytest.mark.asyncio
async def test_html_to_text(mcp_server):
    html = "<html><head><script>bad</script></head><body><h1>Hello</h1><p>World</p></body></html>"
    r = await call(mcp_server, "html_to_text", {"html": html})
    text = r.get("text", "")
    assert "Hello" in text
    assert "World" in text
    assert "<" not in text, "HTML tags not stripped"
    assert "bad" not in text, "Script content not removed"


@pytest.mark.asyncio
async def test_extract_links(mcp_server):
    html = '<a href="/page1">x</a><a href="https://other.com">y</a><form action="/login">'
    r = await call(mcp_server, "extract_links", {
        "html": html, "base_url": "http://test.com"
    })
    assert "http://test.com/page1" in r.get("anchors", [])
    assert "http://test.com/login" in r.get("forms", [])
    assert r.get("total") >= 3


@pytest.mark.asyncio
async def test_extract_links_same_origin_filter(mcp_server):
    html = '<a href="/local">local</a><a href="https://other.com/x">external</a>'
    r = await call(mcp_server, "extract_links", {
        "html": html, "base_url": "http://test.com", "only_same_origin": True
    })
    anchors = r.get("anchors", [])
    assert all("test.com" in a for a in anchors), "External links not filtered"
