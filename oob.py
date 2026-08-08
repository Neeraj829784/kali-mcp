"""Out-of-band (OOB) interaction engine — backs verification of *blind* bugs.

Uses interactsh-client to mint a unique canary domain. You embed that domain in
a payload (blind SSRF/XSS/RCE, etc.); if the target's server ever contacts it
(DNS or HTTP), interactsh records the interaction — undeniable proof the blind
vulnerability fired.

interactsh-client is a long-running poller, so this manages it as a background
session: `start` mints a domain and launches the client, `poll` reads any
received interactions, `stop` tears it down.

The pure parsing helpers (extract_domain, parse_interactions) have no I/O and are
unit-tested directly; the session manager takes an injectable `spawn` so its
logic can be tested without the binary or network.
"""
import asyncio
import json
import os
import re
import signal
import tempfile
import uuid

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
# interactsh default servers: oast.pro/live/site/online/fun/me (+ legacy interact.sh)
_DOMAIN_RE = re.compile(
    r"[a-z0-9]{20,}\.(?:oast\.(?:pro|live|site|online|fun|me)|interact\.sh)", re.I
)


def extract_domain(text: str) -> str:
    """Pull the interactsh payload domain out of the client's startup output."""
    m = _DOMAIN_RE.search(_ANSI.sub("", text or ""))
    return m.group(0) if m else ""


def parse_interactions(raw: str, correlation: str = "") -> list[dict]:
    """Parse interactsh JSONL output into structured interactions.

    correlation: if given, keep only interactions whose id contains it (used to
    match a specific canary). Returns a list of
    {protocol, unique_id, full_id, q_type, remote_address, timestamp}.
    """
    out: list[dict] = []
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        if "protocol" not in d:
            continue
        uid = d.get("unique-id", "") or d.get("full-id", "")
        full = d.get("full-id", "")
        if correlation and correlation not in (full + uid):
            continue
        out.append({
            "protocol": d.get("protocol", ""),
            "unique_id": uid,
            "full_id": full,
            "q_type": d.get("q-type", ""),
            "remote_address": d.get("remote-address", ""),
            "timestamp": d.get("timestamp", ""),
        })
    return out


class OOBManager:
    """Manages background interactsh-client sessions."""

    def __init__(self) -> None:
        self._sessions: dict[str, dict] = {}

    async def start(self, count: int = 1, server: str = "",
                    data_dir: str | None = None, spawn=None) -> dict:
        spawn = spawn or self._spawn
        sid = uuid.uuid4().hex[:12]
        info = await spawn(sid, count, server, data_dir or tempfile.gettempdir())
        if not info.get("domain"):
            await self._terminate(info)
            return {"error": "could not obtain an interactsh payload domain "
                             "(is interactsh-client installed and the network reachable?)",
                    "return_code": -1}
        self._sessions[sid] = info
        domain = info["domain"]
        return {
            "session_id": sid,
            "domain": domain,
            "canary_url": f"http://{domain}",
            "hint": "Embed this domain/URL in a payload (blind SSRF/XSS/RCE, etc.), "
                    "then call oob_poll(session_id). A received callback proves the bug.",
        }

    async def _spawn(self, sid: str, count: int, server: str, data_dir: str) -> dict:
        out_file = os.path.join(data_dir, f"interactsh_{sid}.jsonl")
        startup_file = os.path.join(data_dir, f"interactsh_{sid}.out")
        open(out_file, "w").close()
        sf = open(startup_file, "wb")
        cmd = ["interactsh-client", "-json", "-o", out_file, "-n", str(count),
               "-pi", "5", "-disable-update-check"]
        if server:
            cmd += ["-s", server]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=sf, stderr=asyncio.subprocess.STDOUT, preexec_fn=os.setsid,
        )
        domain = ""
        for _ in range(24):  # up to ~12s for registration
            await asyncio.sleep(0.5)
            try:
                with open(startup_file, "r", errors="replace") as f:
                    domain = extract_domain(f.read())
            except Exception:
                domain = ""
            if domain:
                break
        try:
            sf.close()
        except Exception:
            pass
        return {"domain": domain, "out_file": out_file,
                "startup_file": startup_file, "pid": proc.pid, "proc": proc}

    async def poll(self, session_id: str, correlation: str = "") -> dict:
        s = self._sessions.get(session_id)
        if not s:
            return {"error": f"unknown session '{session_id}'", "return_code": -1}
        try:
            with open(s["out_file"], "r", errors="replace") as f:
                raw = f.read()
        except Exception:
            raw = ""
        corr = correlation or s.get("domain", "").split(".")[0]
        inter = parse_interactions(raw, corr)
        protocols = sorted({i["protocol"] for i in inter})
        return {
            "session_id": session_id,
            "domain": s.get("domain", ""),
            "confirmed": len(inter) > 0,
            "interaction_count": len(inter),
            "protocols": protocols,
            "interactions": inter[:50],
        }

    async def stop(self, session_id: str) -> dict:
        s = self._sessions.pop(session_id, None)
        if not s:
            return {"error": f"unknown session '{session_id}'", "return_code": -1}
        await self._terminate(s)
        return {"session_id": session_id, "stopped": True}

    async def _terminate(self, s: dict) -> None:
        pid = s.get("pid")
        try:
            if pid:
                os.killpg(os.getpgid(pid), signal.SIGTERM)
        except Exception:
            pass
        for key in ("out_file", "startup_file"):
            path = s.get(key, "")
            if path:
                try:
                    os.unlink(path)
                except Exception:
                    pass

    def list_sessions(self) -> list[dict]:
        return [{"session_id": sid, "domain": s.get("domain", "")}
                for sid, s in self._sessions.items()]


# Module-level singleton used by the MCP tools.
OOB = OOBManager()
