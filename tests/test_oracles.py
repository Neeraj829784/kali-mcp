"""Tests for the verification-oracle layer (oracles.py) — fully offline.

Pure decision cores are tested directly; active oracles are driven with a fake
httpx-like client so no network is touched.
"""
import pytest

import oracles as O


# ── Pure: CORS ────────────────────────────────────────────────────────────────

def test_cors_reflect_with_credentials_confirmed():
    verdict, proof = O.classify_cors("https://evil.example", "https://evil.example", "true")
    assert verdict == "confirm" and "credentials" in proof.lower()


def test_cors_reflect_without_credentials_confirmed():
    verdict, _ = O.classify_cors("https://evil.example", "https://evil.example", None)
    assert verdict == "confirm"


def test_cors_null_origin_confirmed():
    verdict, _ = O.classify_cors("https://evil.example", "null", "true")
    assert verdict == "confirm"


def test_cors_wildcard_dropped():
    verdict, _ = O.classify_cors("https://evil.example", "*", "true")
    assert verdict == "drop"


def test_cors_no_header_dropped():
    verdict, _ = O.classify_cors("https://evil.example", None, None)
    assert verdict == "drop"


def test_cors_unrelated_origin_dropped():
    verdict, _ = O.classify_cors("https://evil.example", "https://trusted.com", "true")
    assert verdict == "drop"


# ── Pure: open redirect ─────────────────────────────────────────────────────

def test_open_redirect_absolute_confirmed():
    verdict, _ = O.classify_open_redirect("redir-abc.example", "https://redir-abc.example/")
    assert verdict == "confirm"


def test_open_redirect_scheme_relative_confirmed():
    verdict, _ = O.classify_open_redirect("redir-abc.example", "//redir-abc.example/x")
    assert verdict == "confirm"


def test_open_redirect_userinfo_bypass_confirmed():
    verdict, _ = O.classify_open_redirect("redir-abc.example", "https://legit.com@redir-abc.example/")
    assert verdict == "confirm"


def test_open_redirect_internal_dropped():
    verdict, _ = O.classify_open_redirect("redir-abc.example", "/dashboard")
    assert verdict == "drop"


def test_open_redirect_no_location_dropped():
    verdict, _ = O.classify_open_redirect("redir-abc.example", "")
    assert verdict == "drop"


# ── Pure: param swap ─────────────────────────────────────────────────────────

def test_swap_param_replaces_existing():
    out = O.swap_param("https://x/y?next=/home&a=1", "next", "https://evil/")
    assert "next=https%3A%2F%2Fevil%2F" in out and "a=1" in out


def test_swap_param_adds_redirect_when_none():
    out = O.swap_param("https://x/y", "", "https://evil/")
    assert "redirect=https%3A%2F%2Fevil%2F" in out


# ── Active oracles with a fake client (no network) ───────────────────────────

class _Resp:
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text


class _VulnCorsClient:
    """Reflects whatever Origin it receives, with credentials — vulnerable."""
    async def get(self, url, headers=None):
        origin = (headers or {}).get("Origin", "")
        return _Resp(200, {"access-control-allow-origin": origin,
                           "access-control-allow-credentials": "true"})


class _SafeCorsClient:
    async def get(self, url, headers=None):
        return _Resp(200, {})  # no ACAO


class _VulnRedirectClient:
    """Echoes the injected redirect target into Location — vulnerable."""
    async def get(self, url, headers=None):
        from urllib.parse import urlsplit, parse_qs
        q = parse_qs(urlsplit(url).query)
        target = (q.get("redirect") or q.get("next") or [""])[0]
        return _Resp(302, {"location": target})


class _SafeRedirectClient:
    async def get(self, url, headers=None):
        return _Resp(302, {"location": "/dashboard"})


class _GitClient:
    def __init__(self, body, status=200):
        self._body, self._status = body, status
    async def get(self, url, headers=None):
        return _Resp(self._status, {}, self._body)


@pytest.mark.asyncio
async def test_oracle_cors_vulnerable_confirmed():
    r = await O.oracle_cors(_VulnCorsClient(), "https://api.example.com/data")
    assert r["confirmed"] is True and r["vuln_class"] == "cors"
    assert "credentials" in r["proof"].lower()


@pytest.mark.asyncio
async def test_oracle_cors_safe_dropped():
    r = await O.oracle_cors(_SafeCorsClient(), "https://api.example.com/data")
    assert r["confirmed"] is False


@pytest.mark.asyncio
async def test_oracle_open_redirect_vulnerable_confirmed():
    r = await O.oracle_open_redirect(_VulnRedirectClient(), "https://x/go?redirect=/home", "redirect")
    assert r["confirmed"] is True and r["response"]["status"] == 302


@pytest.mark.asyncio
async def test_oracle_open_redirect_safe_dropped():
    r = await O.oracle_open_redirect(_SafeRedirectClient(), "https://x/go?redirect=/home", "redirect")
    assert r["confirmed"] is False


@pytest.mark.asyncio
async def test_oracle_git_exposure_confirmed():
    r = await O.oracle_git_exposure(_GitClient("ref: refs/heads/main\n"), "https://x")
    assert r["confirmed"] is True


@pytest.mark.asyncio
async def test_oracle_git_exposure_fake_dropped():
    r = await O.oracle_git_exposure(_GitClient("<html>404</html>"), "https://x")
    assert r["confirmed"] is False


@pytest.mark.asyncio
async def test_oracle_env_exposure_confirmed():
    r = await O.oracle_env_exposure(_GitClient("DB_PASSWORD=secret\nAPI_KEY=abc\n"), "https://x")
    assert r["confirmed"] is True


@pytest.mark.asyncio
async def test_oracle_env_exposure_fake_dropped():
    r = await O.oracle_env_exposure(_GitClient("<html>not found</html>"), "https://x")
    assert r["confirmed"] is False


def test_registry_has_all_classes():
    assert set(O.ORACLES) == {"cors", "open_redirect", "git_exposure", "env_exposure"}


# ── Blind SSRF one-shot oracle (fake OOB manager + recording client) ─────────

class _FakeOOB:
    def __init__(self, interactions):
        self._inter = interactions
        self.started = self.stopped = False

    async def start(self, count=1, **kw):
        self.started = True
        return {"session_id": "s1", "domain": "abc123.oast.live"}

    async def poll(self, session_id, correlation=""):
        return {"interactions": self._inter, "interaction_count": len(self._inter),
                "protocols": ["http"] if self._inter else []}

    async def stop(self, session_id):
        self.stopped = True
        return {"stopped": True}


class _FakeErrOOB:
    async def start(self, count=1, **kw):
        return {"error": "no domain", "return_code": -1}


class _RecordClient:
    def __init__(self):
        self.url = None

    async def get(self, url, headers=None):
        self.url = url
        from types import SimpleNamespace
        return SimpleNamespace(status_code=200, headers={}, text="")


async def _nosleep(_):
    return None


@pytest.mark.asyncio
async def test_verify_blind_ssrf_confirmed():
    oob = _FakeOOB([{"protocol": "http", "unique_id": "abc123"}])
    client = _RecordClient()
    r = await O.verify_blind_ssrf(oob, client, "https://t/fetch?url=x", param="url",
                                  wait=0, sleeper=_nosleep)
    assert r["confirmed"] is True and r["vuln_class"] == "blind_ssrf"
    # canary was injected into the 'url' param of the triggered request
    assert "oast.live" in client.url and "url=" in client.url
    assert oob.started and oob.stopped


@pytest.mark.asyncio
async def test_verify_blind_ssrf_not_confirmed():
    oob = _FakeOOB([])
    r = await O.verify_blind_ssrf(oob, _RecordClient(), "https://t/fetch?url=x",
                                  wait=0, sleeper=_nosleep)
    assert r["confirmed"] is False and "not proven" in r["proof"]


@pytest.mark.asyncio
async def test_verify_blind_ssrf_session_error():
    r = await O.verify_blind_ssrf(_FakeErrOOB(), _RecordClient(), "https://t/x",
                                  wait=0, sleeper=_nosleep)
    assert r["confirmed"] is None and "error" in r
