"""Verification oracles — turn scanner/LLM *leads* into *proven bugs*.

Each oracle actively re-tests one vulnerability class over HTTP and returns a
machine-checked verdict plus a proof pack (the request/response evidence a human
or a bug-bounty triager can re-verify in seconds). Only oracle-confirmed
findings should be treated as real.

Design mirrors findings.verify_web_findings: a PURE decision core (no I/O, fully
unit-testable) is separated from the ACTIVE oracle (which performs the HTTP
request through an injected client, so tests can drive it with a fake client and
never touch the network).
"""
import asyncio
import secrets
from urllib.parse import urlparse, urlencode, parse_qsl, urlsplit, urlunsplit, urljoin

# Reuse the content validators already proven out in the findings pipeline.
from findings import _looks_like_git_head, _looks_like_env


# ── Pure decision cores (no network) ─────────────────────────────────────────

def classify_cors(sent_origin: str, acao: str | None, acac: str | None) -> tuple[str, str]:
    """Decide whether a CORS response proves an insecure cross-origin policy.

    Returns (verdict, proof) where verdict is 'confirm' or 'drop'.
    Vulnerable when the server reflects our attacker Origin (or 'null') back in
    Access-Control-Allow-Origin. Impact is highest when Allow-Credentials: true
    is also set. A bare '*' is NOT credentialed cross-origin access, so it is
    not treated as a confirmed bug here.
    """
    if not acao:
        return "drop", "no Access-Control-Allow-Origin header returned"
    acao = acao.strip()
    acac_true = (acac or "").strip().lower() == "true"
    if acao == "*":
        return "drop", "Access-Control-Allow-Origin is '*' (no credentialed cross-origin access)"
    if acao == sent_origin or acao.lower() == "null":
        if acac_true:
            return "confirm", f"reflects attacker Origin '{acao}' AND Access-Control-Allow-Credentials: true"
        return "confirm", f"reflects attacker Origin '{acao}' (without credentials)"
    return "drop", f"Access-Control-Allow-Origin '{acao}' does not reflect the attacker origin"


def classify_open_redirect(canary_host: str, location: str) -> tuple[str, str]:
    """Decide whether a redirect actually points at attacker-controlled host.

    Returns (verdict, proof). Handles absolute (https://evil), scheme-relative
    (//evil), and userinfo (https://legit@evil) forms.
    """
    if not location:
        return "drop", "no redirect issued (no Location header)"
    loc = location.strip()
    test = ("http:" + loc) if loc.startswith("//") else loc
    parsed = urlparse(test)
    host = parsed.netloc.split("@")[-1].split(":")[0].lower()
    if host == canary_host.lower():
        return "confirm", f"redirects to attacker-controlled host via 'Location: {loc}'"
    return "drop", f"redirect 'Location: {loc}' does not point to the attacker host"


def swap_param(url: str, param: str, value: str) -> str:
    """Return url with `param` set to `value` (adds a 'redirect' param if none given)."""
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param or "redirect"] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


# ── Active oracles (take an injected httpx-like client) ──────────────────────

async def oracle_cors(client, url: str, param: str = "") -> dict:
    canary = f"https://evil-{secrets.token_hex(6)}.example"
    resp = await client.get(url, headers={"Origin": canary})
    acao = resp.headers.get("access-control-allow-origin")
    acac = resp.headers.get("access-control-allow-credentials")
    verdict, proof = classify_cors(canary, acao, acac)
    return {
        "vuln_class": "cors",
        "url": url,
        "confirmed": verdict == "confirm",
        "proof": proof,
        "request": {"method": "GET", "url": url, "headers": {"Origin": canary}},
        "response": {"status": resp.status_code,
                     "access-control-allow-origin": acao,
                     "access-control-allow-credentials": acac},
    }


async def oracle_open_redirect(client, url: str, param: str = "") -> dict:
    canary_host = f"redir-{secrets.token_hex(6)}.example"
    test_url = swap_param(url, param, f"https://{canary_host}/")
    resp = await client.get(test_url)  # client is configured follow_redirects=False
    loc = resp.headers.get("location", "")
    verdict, proof = classify_open_redirect(canary_host, loc)
    return {
        "vuln_class": "open_redirect",
        "url": test_url,
        "confirmed": verdict == "confirm",
        "proof": proof,
        "request": {"method": "GET", "url": test_url},
        "response": {"status": resp.status_code, "location": loc},
    }


async def oracle_git_exposure(client, url: str, param: str = "") -> dict:
    base = url if url.endswith("/") else url + "/"
    target = urljoin(base, ".git/HEAD")
    resp = await client.get(target)
    confirmed = resp.status_code == 200 and _looks_like_git_head(getattr(resp, "text", ""))
    return {
        "vuln_class": "git_exposure",
        "url": target,
        "confirmed": bool(confirmed),
        "proof": ("exposed .git/HEAD is a real git ref" if confirmed
                  else "no valid .git/HEAD (not a real exposed repo)"),
        "response": {"status": resp.status_code},
    }


async def oracle_env_exposure(client, url: str, param: str = "") -> dict:
    base = url if url.endswith("/") else url + "/"
    target = urljoin(base, ".env")
    resp = await client.get(target)
    confirmed = resp.status_code == 200 and _looks_like_env(getattr(resp, "text", ""))
    return {
        "vuln_class": "env_exposure",
        "url": target,
        "confirmed": bool(confirmed),
        "proof": ("exposed .env contains KEY=value secrets" if confirmed
                  else "no valid .env file (not real secrets)"),
        "response": {"status": resp.status_code},
    }


# Registry: vuln class -> active oracle. Extend this to add more proof-checks.
ORACLES = {
    "cors": oracle_cors,
    "open_redirect": oracle_open_redirect,
    "git_exposure": oracle_git_exposure,
    "env_exposure": oracle_env_exposure,
}


# ── Out-of-band oracle (blind SSRF) ──────────────────────────────────────────

async def verify_blind_ssrf(oob_manager, client, url: str, param: str = "url",
                            wait: float = 9.0, sleeper=None) -> dict:
    """One-shot blind-SSRF proof: mint a canary, request `url` with the canary
    injected into `param`, wait, then report whether the target's server called
    back. `oob_manager`, `client`, and `sleeper` are injected so this is testable
    without the interactsh binary or a real network.
    """
    sleeper = sleeper or asyncio.sleep
    started = await oob_manager.start(count=1)
    if "error" in started or not started.get("domain"):
        return {"vuln_class": "blind_ssrf", "url": url, "confirmed": None,
                "error": started.get("error", "could not start OOB session")}
    sid, domain = started["session_id"], started["domain"]
    marker = secrets.token_hex(4)
    canary = f"http://{domain}/{marker}"
    injected = swap_param(url, param or "url", canary)

    trigger_ok, trigger_err = True, ""
    try:
        await client.get(injected)
    except Exception as e:  # target unreachable / errored — still poll, may have fired
        trigger_ok, trigger_err = False, str(e)

    await sleeper(wait)
    polled = await oob_manager.poll(sid)
    await oob_manager.stop(sid)

    inter = polled.get("interactions", [])
    confirmed = bool(inter)
    return {
        "vuln_class": "blind_ssrf",
        "url": url,
        "injected_url": injected,
        "canary": canary,
        "confirmed": confirmed,
        "proof": (
            f"target server contacted the canary {domain} — "
            f"{polled.get('interaction_count', 0)} interaction(s) {polled.get('protocols')}"
            if confirmed else
            "no callback received — not proven (target may filter egress, or the "
            "canary needs a different injection point/parameter)"
        ),
        "interactions": inter[:20],
        "request": {"method": "GET", "url": injected},
        "trigger_ok": trigger_ok,
        "trigger_error": trigger_err,
    }
