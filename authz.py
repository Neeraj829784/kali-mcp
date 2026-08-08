"""Access-control / IDOR differential engine.

The only reliable way to detect broken access control and IDOR is to compare
what *different identities* can do. This module replays the SAME request as the
owner, as other identities, and as anonymous, then compares the responses:

* if a non-owner identity receives the owner's protected resource  -> vulnerable
* if it is denied (401/403), redirected to login, or 404'd          -> enforced
* anything ambiguous                                                -> inconclusive (verify manually)

Pure decision logic (classify_authz) is separated from network I/O
(run_access_control_test takes an injected client) so it is unit-testable offline.
"""

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
