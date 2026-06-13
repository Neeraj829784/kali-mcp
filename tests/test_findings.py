"""Tests for finding confidence, dedup, corroboration, nikto filtering, soft-404."""
import pytest

import findings as F


# ── Task 1: confidence assignment ─────────────────────────────────────────────

def test_sqlmap_finding_high_confidence():
    out = "Parameter: id (GET)\n[*] the parameter 'id' is injectable"
    fs = F.extract_findings("sqlmap", out, "1.2.3.4")
    assert fs and fs[0]["confidence"] == F.CONF_HIGH


def test_nmap_open_port_high_confidence():
    out = "22/tcp open ssh OpenSSH 8.2"
    fs = F.extract_findings("nmap_port_scan", out, "1.2.3.4")
    assert fs and fs[0]["confidence"] == F.CONF_HIGH


def test_gobuster_finding_low_confidence():
    out = "/admin (Status: 200)"
    fs = F.extract_findings("gobuster_dir", out, "1.2.3.4")
    assert fs and fs[0]["confidence"] == F.CONF_LOW


def test_nuclei_finding_medium_confidence():
    out = '{"host":"1.2.3.4","info":{"name":"X","severity":"medium"},"matched-at":"http://x/"}'
    fs = F.extract_findings("nuclei", out, "1.2.3.4")
    assert fs and fs[0]["confidence"] == F.CONF_MEDIUM


# ── Task 2 + 5: dedup + cross-tool corroboration ──────────────────────────────

def test_dedup_merges_same_finding():
    a = F._finding("h", "Open port 80/http", F.INFO, "e1", "nmap", port=80, confidence=F.CONF_HIGH)
    b = F._finding("h", "Open port 80/http", F.INFO, "e2longer", "nuclei", port=80, confidence=F.CONF_MEDIUM)
    out = F.dedup_findings([a, b])
    assert len(out) == 1
    assert set(out[0]["tools"]) == {"nmap", "nuclei"}
    assert out[0]["evidence"] == "e2longer"  # longest evidence kept


def test_dedup_corroboration_boosts_confidence():
    a = F._finding("h", "SQLi in id", F.HIGH, "e", "nuclei", confidence=F.CONF_MEDIUM)
    b = F._finding("h", "SQLi in id", F.HIGH, "e", "sqlmap", confidence=F.CONF_MEDIUM)
    out = F.dedup_findings([a, b])
    assert len(out) == 1
    # two distinct tools -> medium bumped to high
    assert out[0]["confidence"] == F.CONF_HIGH


def test_dedup_normalizes_status_codes():
    a = F._finding("h", "Found path /admin [200]", F.LOW, "e", "gobuster")
    b = F._finding("h", "Found path /admin [301]", F.LOW, "e", "gobuster")
    out = F.dedup_findings([a, b])
    assert len(out) == 1


def test_dedup_keeps_highest_severity():
    a = F._finding("h", "thing", F.LOW, "e", "t1")
    b = F._finding("h", "thing", F.CRITICAL, "e", "t2")
    out = F.dedup_findings([a, b])
    assert out[0]["severity"] == F.CRITICAL


# ── Task 4: nikto noise filtering ─────────────────────────────────────────────

def test_nikto_drops_noise_lines():
    out = "\n".join([
        "+ Server: Apache/2.4.41",
        "+ X-Frame-Options header is not present.",
        "+ Cookie session created without the httponly flag",
        "+ /admin/: Admin login page with possible SQL injection",
    ])
    fs = F.extract_findings("nikto", out, "h")
    titles = " ".join(f["title"].lower() for f in fs)
    assert "server:" not in titles
    assert "x-frame-options" not in titles
    # the SQL injection line is kept (high-signal)
    assert any("sql injection" in f["title"].lower() for f in fs)


def test_nikto_keeps_high_signal_even_if_noise_keyword():
    out = "+ Server: leaks version AND allows SQL injection via header"
    fs = F.extract_findings("nikto", out, "h")
    assert len(fs) == 1
    assert fs[0]["severity"] == F.HIGH


# ── Task 3: soft-404 detection (mocked httpx) ─────────────────────────────────

class _Resp:
    def __init__(self, status, body):
        self.status_code = status
        self.content = body


class _FakeClient:
    """Returns 200 with identical body for every request -> pure wildcard server."""
    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url):
        return _Resp(200, b"same body everywhere")


class _RealishClient:
    """Wildcard baseline is 200/'x', but /real returns distinct content."""
    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url):
        if url.endswith("/real"):
            return _Resp(200, b"REAL PAGE " + b"content " * 40)  # ~330 bytes, well over tolerance
        return _Resp(200, b"x")


@pytest.mark.asyncio
async def test_soft404_drops_wildcard_paths(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
    fs = [F._finding("h", "Found path /admin [200]", F.LOW, "HTTP 200 at /admin", "gobuster")]
    out = await F.verify_web_findings(fs, "http://h/")
    assert out == []  # wildcard -> dropped


@pytest.mark.asyncio
async def test_verify_confirms_distinct_path(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", _RealishClient)
    fs = [F._finding("h", "Found path /real [200]", F.LOW, "HTTP 200 at /real", "gobuster")]
    out = await F.verify_web_findings(fs, "http://h/")
    assert len(out) == 1
    assert out[0]["confidence"] == F.CONF_HIGH


@pytest.mark.asyncio
async def test_verify_passes_through_non_web(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
    fs = [F._finding("h", "Open port 22/ssh", F.INFO, "ssh", "nmap", port=22)]
    out = await F.verify_web_findings(fs, "http://h/")
    assert len(out) == 1
    assert out[0]["tool"] == "nmap"


# ── Task 3: fail-open behaviour on network errors ─────────────────────────────

class _FailingClient:
    """Raises on every request — simulates total network failure."""
    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url):
        import httpx
        raise httpx.ConnectError("boom")


class _BaselineFailsThenOK:
    """Baseline request raises; subsequent path requests succeed distinctly."""
    def __init__(self, *a, **k):
        self._first = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url):
        import httpx
        if self._first:
            self._first = False
            raise httpx.ConnectError("baseline down")
        return _Resp(200, b"X" * 500)


@pytest.mark.asyncio
async def test_verify_returns_unchanged_on_total_network_failure(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", _FailingClient)
    fs = [F._finding("h", "Found path /admin [200]", F.LOW, "HTTP 200 at /admin", "gobuster")]
    out = await F.verify_web_findings(fs, "http://h/")
    # client constructed ok but every get raises -> findings preserved unchanged
    assert out == fs


@pytest.mark.asyncio
async def test_verify_keeps_finding_when_baseline_request_fails(monkeypatch):
    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", _BaselineFailsThenOK)
    fs = [F._finding("h", "Found path /real [200]", F.LOW, "HTTP 200 at /real", "gobuster")]
    out = await F.verify_web_findings(fs, "http://h/")
    # no baseline -> cannot call it soft-404 -> distinct response confirmed
    assert len(out) == 1
    assert out[0]["confidence"] == F.CONF_HIGH


@pytest.mark.asyncio
async def test_verify_empty_inputs_passthrough(monkeypatch):
    assert await F.verify_web_findings([], "http://h/") == []
    fs = [F._finding("h", "x", F.LOW, "e", "gobuster")]
    assert await F.verify_web_findings(fs, "") == fs
