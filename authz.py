"""Access-control / IDOR differential engine.

The only reliable way to detect broken access control and IDOR is to compare
what *different identities* can do. This module replays the SAME request as the
owner, as other identities, and as anonymous, then compares the responses:

* if a non-owner identity receives the owner's protected resource  -> vulnerable
* if it is denied (401/403), redirected to login, or 404'd          -> enforced
* anything ambiguous                                                -> inconclusive (verify manually)

Pure decision logic (classify_authz) is separated from network I/O
(run_access_control_test takes an injected client) so it is unit-testable offline.
It also harvests ID-bearing URLs from a crawl and bulk-tests them (run_idor_sweep).
"""
import asyncio
import re
from urllib.parse import urlsplit, parse_qsl

_REDIRECTS = {301, 302, 303, 307, 308}


def parse_headers(headers: str = "", cookies: str = "", bearer: str = "") -> dict:
    """Build a headers dict from convenient inputs.

    headers: newline-separated 'Key: Value' lines
    cookies: a raw Cookie header value (e.g. 'session=abc; role=user')
    bearer:  a bearer token -> 'Authorization: Bearer <token>'
    """
    h: dict[str, str] = {}
    for line in (headers or "").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        h[k.strip()] = v.strip()
    if cookies.strip():
        h["Cookie"] = cookies.strip()
    if bearer.strip():
        h["Authorization"] = f"Bearer {bearer.strip()}"
    return h


class IdentityStore:
    """In-memory registry of named test identities (auth material).

    Kept in memory (not persisted) so session tokens/cookies never touch disk.
    """

    def __init__(self) -> None:
        self._d: dict[str, dict] = {}

    def add(self, name: str, headers: dict) -> None:
        self._d[name] = dict(headers)

    def get(self, name: str) -> dict | None:
        return self._d.get(name)

    def remove(self, name: str) -> bool:
        return self._d.pop(name, None) is not None

    def names(self) -> list[str]:
        return sorted(self._d)

    def summary(self) -> list[dict]:
        # Only expose header KEYS, never the secret values.
        return [{"name": n, "header_keys": sorted(self._d[n])} for n in sorted(self._d)]


# Module-level singleton used by the MCP tools.
IDENTITIES = IdentityStore()


def classify_authz(baseline: dict, other: dict, length_tolerance: int = 64) -> tuple[str, str]:
    """Decide whether `other` (a non-owner identity) improperly accessed the
    owner's resource. baseline/other are {status, length}. Returns
    (verdict, reason) with verdict in 'vulnerable' | 'enforced' | 'inconclusive'.
    """
    b_status, b_len = baseline.get("status"), baseline.get("length", 0)
    o_status, o_len = other.get("status"), other.get("length", 0)

    if b_status != 200:
        return "inconclusive", f"owner did not get HTTP 200 (got {b_status}); nothing protected to compare"
    if o_status in (401, 403):
        return "enforced", f"access denied to this identity (HTTP {o_status})"
    if o_status in _REDIRECTS:
        return "enforced", f"redirected (HTTP {o_status}) — likely to a login page"
    if o_status == 404:
        return "enforced", "resource not found for this identity"
    if o_status == 200 and abs(o_len - b_len) <= length_tolerance:
        return "vulnerable", (f"this identity received the owner's resource "
                              f"(HTTP 200, {o_len} bytes ≈ owner {b_len})")
    if o_status == 200:
        return "inconclusive", (f"HTTP 200 but response size differs ({o_len} vs owner "
                                f"{b_len}) — verify the content manually")
    return "inconclusive", f"HTTP {o_status} — verify manually"


async def run_access_control_test(client, method: str, url: str, owner_headers: dict,
                                  test_identities: list[tuple[str, dict]],
                                  body: str = "", length_tolerance: int = 64) -> dict:
    """Replay `method url` as the owner (baseline) then as each test identity;
    classify each. `client` is an injected httpx-like client (async .request).
    """
    async def fetch(headers: dict) -> dict:
        resp = await client.request(method.upper(), url, headers=headers or {},
                                    content=(body or None))
        return {"status": resp.status_code, "length": len(resp.content)}

    baseline = await fetch(owner_headers)
    results: list[dict] = []
    for name, headers in test_identities:
        other = await fetch(headers)
        verdict, reason = classify_authz(baseline, other, length_tolerance)
        results.append({"identity": name, "status": other["status"],
                        "length": other["length"], "verdict": verdict, "reason": reason})
    return {
        "method": method.upper(),
        "url": url,
        "owner_status": baseline["status"],
        "owner_length": baseline["length"],
        "results": results,
        "vulnerable": any(r["verdict"] == "vulnerable" for r in results),
    }


# ── Automatic IDOR sweep: harvest ID-bearing URLs, then bulk-test ────────────

# Query-param names that typically reference a specific object.
_ID_PARAM_RE = re.compile(
    r"^(id|uid|u|user|userid|user_id|account|acct|customer|invoice|order|order_id|"
    r"doc|document|file|fileid|file_id|num|no|number|pid|gid|oid|obj|object|ref|"
    r"key|profile|msg|message|ticket|item|record|report)$", re.I)
_NUMERIC_SEG = re.compile(r"^\d+$")
_UUID_SEG = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
# Paths that likely change state — skipped unless explicitly allowed (GET on these
# can still trigger actions in badly-built apps).
_DANGER_RE = re.compile(
    r"(delete|remove|destroy|drop|pay|payment|transfer|withdraw|logout|update|edit|"
    r"create|/new\b|/add\b|reset|disable|enable|revoke|grant|approve|cancel)", re.I)


def is_state_changing(url: str) -> bool:
    """True if the URL looks like it performs a state-changing action."""
    return bool(_DANGER_RE.search(url or ""))


def _endpoint_template(parts) -> tuple:
    """Normalize a URL to an endpoint template so we test each distinct endpoint
    once (e.g. /invoice?id=1 and /invoice?id=2 collapse to one)."""
    segs = []
    for seg in parts.path.split("/"):
        segs.append("{id}" if (_NUMERIC_SEG.match(seg) or _UUID_SEG.match(seg)) else seg)
    pkeys = ",".join(sorted(k for k, _ in parse_qsl(parts.query)))
    return (parts.netloc, "/".join(segs), pkeys)


def find_idor_candidates(urls, allow_dangerous: bool = False) -> list[str]:
    """From a list of URLs, return those that reference a specific object (an
    id-like query param, or a numeric/uuid path segment), deduped per endpoint.
    State-changing endpoints are skipped unless allow_dangerous is True.
    """
    seen: set = set()
    out: list[str] = []
    for u in urls:
        u = (u or "").strip()
        if not u.lower().startswith("http"):
            continue
        parts = urlsplit(u)
        has_id = any(v and _ID_PARAM_RE.match(k) for k, v in
                     parse_qsl(parts.query, keep_blank_values=True))
        if not has_id:
            has_id = any(_NUMERIC_SEG.match(s) or _UUID_SEG.match(s)
                         for s in parts.path.split("/"))
        if not has_id:
            continue
        if not allow_dangerous and is_state_changing(u):
            continue
        key = _endpoint_template(parts)
        if key in seen:
            continue
        seen.add(key)
        out.append(u)
    return out


async def run_idor_sweep(client, urls, owner_headers, test_identities, max_urls: int = 50,
                         length_tolerance: int = 64, allow_dangerous: bool = False,
                         delay: float = 0.0, sleeper=None) -> dict:
    """Harvest ID-bearing URLs and bulk-test each (read-only GET) for IDOR/BAC."""
    sleeper = sleeper or asyncio.sleep
    candidates = find_idor_candidates(urls, allow_dangerous)[:max_urls]
    results: list[dict] = []
    for url in candidates:
        r = await run_access_control_test(client, "GET", url, owner_headers,
                                          test_identities, length_tolerance=length_tolerance)
        results.append(r)
        if delay:
            await sleeper(delay)
    vulnerable = [r for r in results if r["vulnerable"]]
    return {
        "candidates_found": len(candidates),
        "tested": len(results),
        "vulnerable_count": len(vulnerable),
        "vulnerable": [
            {"url": r["url"],
             "leaked_to": [x["identity"] for x in r["results"] if x["verdict"] == "vulnerable"]}
            for r in vulnerable
        ],
        "results": results,
    }
