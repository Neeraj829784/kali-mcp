"""Tests for the out-of-band (interactsh) engine (oob.py) — fully offline.

Pure parsers are tested directly; the session manager is driven with an injected
fake `spawn` (and a canned interactions file) so no interactsh binary or network
is needed.
"""
import os
import tempfile

import pytest

import oob as O


# ── Pure: extract_domain ─────────────────────────────────────────────────────

def test_extract_domain_from_ansi_startup():
    startup = (
        "\x1b[34mINF\x1b[0m Listing 1 payload for OOB Testing\n"
        "\x1b[34mINF\x1b[0m d9ritn968vi6pg33evj0jjh6yn8cq7jpr.oast.live\n"
    )
    assert O.extract_domain(startup) == "d9ritn968vi6pg33evj0jjh6yn8cq7jpr.oast.live"


def test_extract_domain_none():
    assert O.extract_domain("no domain here") == ""
    assert O.extract_domain("") == ""


# ── Pure: parse_interactions ─────────────────────────────────────────────────

_DNS = ('{"protocol":"dns","unique-id":"abc123","full-id":"abc123","q-type":"A",'
        '"remote-address":"1.2.3.4","timestamp":"t1"}')
_HTTP = ('{"protocol":"http","unique-id":"abc123","full-id":"abc123",'
         '"remote-address":"5.6.7.8","timestamp":"t2"}')
_OTHER = ('{"protocol":"dns","unique-id":"zzz999","full-id":"zzz999",'
          '"remote-address":"9.9.9.9","timestamp":"t3"}')


def test_parse_interactions_basic():
    got = O.parse_interactions(_DNS + "\n" + _HTTP)
    assert len(got) == 2
    assert got[0]["protocol"] == "dns" and got[0]["q_type"] == "A"
    assert got[1]["protocol"] == "http" and got[1]["remote_address"] == "5.6.7.8"


def test_parse_interactions_correlation_filter():
    got = O.parse_interactions("\n".join([_DNS, _HTTP, _OTHER]), correlation="abc123")
    assert len(got) == 2 and all(i["unique_id"] == "abc123" for i in got)


def test_parse_interactions_ignores_noise():
    noisy = "banner line\n" + _DNS + "\nnot json\n{}\n"
    got = O.parse_interactions(noisy)
    assert len(got) == 1  # only the valid interaction with a protocol


# ── Session manager with an injected fake spawn (no binary/network) ──────────

async def _fake_spawn_with_hit(sid, count, server, data_dir):
    """Simulate interactsh: mint a domain and pre-write a received HTTP callback."""
    out = os.path.join(tempfile.gettempdir(), f"oobtest_{sid}.jsonl")
    with open(out, "w") as f:
        f.write(_DNS + "\n" + _HTTP + "\n")  # unique-id abc123
    return {"domain": "abc123.oast.live", "out_file": out,
            "startup_file": out, "pid": None, "proc": None}


async def _fake_spawn_no_domain(sid, count, server, data_dir):
    return {"domain": "", "out_file": "", "startup_file": "", "pid": None, "proc": None}


@pytest.mark.asyncio
async def test_session_start_poll_stop_flow():
    m = O.OOBManager()
    started = await m.start(count=1, spawn=_fake_spawn_with_hit)
    assert "session_id" in started and started["domain"] == "abc123.oast.live"
    sid = started["session_id"]

    polled = await m.poll(sid)
    assert polled["confirmed"] is True
    assert polled["interaction_count"] == 2
    assert set(polled["protocols"]) == {"dns", "http"}

    stopped = await m.stop(sid)
    assert stopped["stopped"] is True
    # session removed; polling again errors
    assert "error" in await m.poll(sid)


@pytest.mark.asyncio
async def test_session_start_no_domain_errors():
    m = O.OOBManager()
    r = await m.start(count=1, spawn=_fake_spawn_no_domain)
    assert "error" in r and not m.list_sessions()


@pytest.mark.asyncio
async def test_poll_unknown_session():
    m = O.OOBManager()
    assert "error" in await m.poll("nope")


@pytest.mark.asyncio
async def test_list_sessions():
    m = O.OOBManager()
    await m.start(count=1, spawn=_fake_spawn_with_hit)
    assert len(m.list_sessions()) == 1
