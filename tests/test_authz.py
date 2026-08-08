"""Tests for the access-control / IDOR differential engine (authz.py) — offline.

Pure header parsing, identity store, and classifier are tested directly; the
active differential is driven with a fake client so no network is touched.
"""
import pytest

import authz as A


# ── parse_headers ─────────────────────────────────────────────────────────────

def test_parse_headers_lines_cookies_bearer():
    h = A.parse_headers("X-Api: 1\nAccept: */*", cookies="session=abc; r=user", bearer="tok123")
    assert h["X-Api"] == "1" and h["Accept"] == "*/*"
    assert h["Cookie"] == "session=abc; r=user"
    assert h["Authorization"] == "Bearer tok123"


def test_parse_headers_empty():
    assert A.parse_headers() == {}


# ── IdentityStore ─────────────────────────────────────────────────────────────

def test_identity_store_add_get_remove():
    s = A.IdentityStore()
    s.add("userA", {"Cookie": "s=a"})
    assert s.get("userA") == {"Cookie": "s=a"}
    assert s.names() == ["userA"]
    # summary exposes only header KEYS, not values
    assert s.summary() == [{"name": "userA", "header_keys": ["Cookie"]}]
    assert s.remove("userA") is True
    assert s.get("userA") is None and s.remove("userA") is False


# ── classify_authz (pure) ─────────────────────────────────────────────────────

def test_classify_vulnerable_same_resource():
    v, _ = A.classify_authz({"status": 200, "length": 1000}, {"status": 200, "length": 1010})
    assert v == "vulnerable"


def test_classify_enforced_403():
    v, _ = A.classify_authz({"status": 200, "length": 1000}, {"status": 403, "length": 50})
    assert v == "enforced"


def test_classify_enforced_login_redirect():
    v, _ = A.classify_authz({"status": 200, "length": 1000}, {"status": 302, "length": 0})
    assert v == "enforced"


def test_classify_enforced_404():
    v, _ = A.classify_authz({"status": 200, "length": 1000}, {"status": 404, "length": 20})
    assert v == "enforced"


def test_classify_inconclusive_owner_not_200():
    v, _ = A.classify_authz({"status": 404, "length": 0}, {"status": 200, "length": 1000})
    assert v == "inconclusive"


def test_classify_inconclusive_200_different_size():
    v, _ = A.classify_authz({"status": 200, "length": 1000}, {"status": 200, "length": 50})
    assert v == "inconclusive"


# ── run_access_control_test with a fake client ──────────────────────────────

class _Resp:
    def __init__(self, status, body=b""):
        self.status_code = status
        self.content = body if isinstance(body, bytes) else body.encode()


class _FakeClient:
    """Owner + any credentialed identity get the resource; anon is redirected."""
    async def request(self, method, url, headers=None, content=None):
        if headers:  # has some auth material
            return _Resp(200, b"x" * 1000)
        return _Resp(302)  # anonymous -> login redirect


@pytest.mark.asyncio
async def test_run_access_control_detects_idor():
    owner = {"Cookie": "s=owner"}
    tests = [("userB", {"Cookie": "s=bob"}), ("anonymous", {})]
    out = await A.run_access_control_test(_FakeClient(), "GET",
                                          "https://app/api/invoice?id=1", owner, tests)
    assert out["vulnerable"] is True
    verdicts = {r["identity"]: r["verdict"] for r in out["results"]}
    assert verdicts["userB"] == "vulnerable"      # bob saw owner's invoice -> IDOR
    assert verdicts["anonymous"] == "enforced"    # anon redirected to login


class _StrictClient:
    """Only the owner cookie works; everyone else is denied 403."""
    async def request(self, method, url, headers=None, content=None):
        if (headers or {}).get("Cookie") == "s=owner":
            return _Resp(200, b"x" * 1000)
        return _Resp(403, b"denied")


@pytest.mark.asyncio
async def test_run_access_control_properly_enforced():
    out = await A.run_access_control_test(
        _StrictClient(), "GET", "https://app/api/invoice?id=1",
        {"Cookie": "s=owner"}, [("userB", {"Cookie": "s=bob"})])
    assert out["vulnerable"] is False
    assert out["results"][0]["verdict"] == "enforced"
