"""Tests for Tier 2 active web verification: content checks + catch-all clustering."""
import pytest

import findings as F


# ── Pure content validators ──────────────────────────────────────────────────

def test_looks_like_git_head_ref():
    assert F._looks_like_git_head("ref: refs/heads/main\n")


def test_looks_like_git_head_hash():
    assert F._looks_like_git_head("a" * 40)
    assert F._looks_like_git_head("b" * 64)


def test_looks_like_git_head_rejects_html():
    assert not F._looks_like_git_head("<!DOCTYPE html><html>404</html>")
    assert not F._looks_like_git_head("")


def test_looks_like_env_true():
    assert F._looks_like_env("# comment\nDB_PASSWORD=secret\nAPI_KEY=abc123\n")


def test_looks_like_env_rejects_html_and_empty():
    assert not F._looks_like_env("<html><body>Not found</body></html>")
    assert not F._looks_like_env("")
    assert not F._looks_like_env("# only comments\n\n")


# ── Pure classification core ─────────────────────────────────────────────────

def test_classify_soft404_dropped():
    entries = [{"status": 200, "length": 1000, "content_verified": None}]
    baseline = (200, 1000)
    assert F.classify_web_verification(entries, baseline) == ["drop"]


def test_classify_distinct_confirmed():
    entries = [{"status": 200, "length": 5000, "content_verified": None}]
    baseline = (404, 200)
    assert F.classify_web_verification(entries, baseline) == ["confirm"]


def test_classify_content_verified_survives_everything():
    # matches baseline AND part of a cluster, but content proven -> confirm
    entries = [{"status": 200, "length": 200, "content_verified": True}]
    baseline = (200, 200)
    assert F.classify_web_verification(entries, baseline) == ["confirm"]


def test_classify_content_disproven_dropped():
    entries = [{"status": 200, "length": 9999, "content_verified": False}]
    assert F.classify_web_verification(entries, None) == ["drop"]


def test_classify_catch_all_cluster_dropped():
    # 10 distinct paths all return identical (200, ~1234 bytes) -> catch-all
    entries = [{"status": 200, "length": 1234, "content_verified": None} for _ in range(10)]
    actions = F.classify_web_verification(entries, None, cluster_threshold=8)
    assert actions == ["drop"] * 10


def test_classify_small_group_not_catch_all():
    entries = [{"status": 200, "length": 1234, "content_verified": None} for _ in range(3)]
    actions = F.classify_web_verification(entries, None, cluster_threshold=8)
    assert actions == ["confirm"] * 3


def test_classify_fetch_failure_kept():
    entries = [{"status": None, "length": 0, "content_verified": None}]
    assert F.classify_web_verification(entries, None) == ["keep"]


# ── End-to-end verify_web_findings with a fake httpx client (no network) ─────

class _FakeResp:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self.content = body.encode()
        self.text = body


class _FakeClient:
    """Maps URL suffixes to canned responses."""
    def __init__(self, routes, default):
        self._routes = routes
        self._default = default

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url):
        for suffix, resp in self._routes.items():
            if url.endswith(suffix):
                return resp
        return self._default


@pytest.mark.asyncio
async def test_verify_git_exposure_content_verified(monkeypatch):
    import httpx
    routes = {
        "/.git/HEAD": _FakeResp(200, "ref: refs/heads/main\n"),
        "/.git/": _FakeResp(200, "Index of /.git"),
    }
    default = _FakeResp(404, "not found page")  # baseline
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _FakeClient(routes, default))
    findings = [F._finding("h", "Found path /.git/ [200]", F.LOW,
                           "HTTP 200 at /.git/", "gobuster", confidence=F.CONF_LOW)]
    out = await F.verify_web_findings(findings, "http://h/")
    assert len(out) == 1
    assert out[0]["confidence"] == F.CONF_HIGH
    assert "content-verified" in out[0]["evidence"]


@pytest.mark.asyncio
async def test_verify_fake_git_dropped(monkeypatch):
    import httpx
    # /.git/HEAD returns HTML (a soft-200 catch-all), not a real ref -> dropped
    routes = {"/.git/HEAD": _FakeResp(200, "<html>404 styled page</html>")}
    default = _FakeResp(404, "nf")
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _FakeClient(routes, default))
    findings = [F._finding("h", "Found path /.git/ [200]", F.LOW,
                           "HTTP 200 at /.git/", "gobuster", confidence=F.CONF_LOW)]
    out = await F.verify_web_findings(findings, "http://h/")
    assert out == []  # disproven -> dropped


@pytest.mark.asyncio
async def test_verify_non_web_findings_untouched(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "AsyncClient",
                        lambda **kw: _FakeClient({}, _FakeResp(404, "nf")))
    findings = [F._finding("h", "SQL Injection", F.CRITICAL, "injectable", "sqlmap",
                           confidence=F.CONF_HIGH)]
    out = await F.verify_web_findings(findings, "http://h/")
    assert out == findings  # no web-path findings -> unchanged
