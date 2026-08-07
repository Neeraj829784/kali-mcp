"""
Scope allowlist — all tool targets must pass check_scope() before execution.
Add authorized targets to SCOPE_FILE (one per line: IPs, CIDRs, domains).

FIX: Added threading.Lock around _cache reads/writes to prevent TOCTOU race
     under concurrent tool calls (scan_host fires many tools in parallel).
"""
import ipaddress
import os
import threading

from config import SCOPE_FILE

_cache: list[str] | None = None
_lock = threading.Lock()   # guards all _cache access


def _load_scope() -> list[str]:
    global _cache
    with _lock:
        if _cache is not None:
            return _cache
        if not os.path.exists(SCOPE_FILE):
            _cache = []
            return _cache
        with open(SCOPE_FILE) as f:
            _cache = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        return _cache


def _invalidate() -> None:
    global _cache
    with _lock:
        _cache = None


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _in_cidr(target: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(target) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _extract_host(target: str) -> str:
    """Pull a bare hostname/IP out of a URL or host:port string."""
    host = target
    if "://" in target:
        host = target.split("://", 1)[1].split("/")[0].split(":")[0]
    return host


def _matches(host: str, entry: str) -> bool:
    """True if `host` matches a scope entry (exact, CIDR, or '*.domain' wildcard)."""
    if entry == host:
        return True
    if "/" in entry and _is_ip(host) and _in_cidr(host, entry):
        return True
    # Wildcard entry like '*.example.com': match any subdomain AND the apex.
    if entry.startswith("*."):
        suffix = entry[1:]          # '.example.com' — subdomain match
        apex = entry[2:]            # 'example.com'  — apex match
        if host.endswith(suffix) or host == apex:
            return True
    return False


# Out-of-scope denylist (in-memory). Set by the program scope engine
# (program_scope.py) when a program is activated. Entries here are ALWAYS
# rejected — even in lab mode — so an explicitly excluded target can never be
# scanned regardless of the allowlist.
_denylist: list[str] = []


def set_denylist(entries: list[str]) -> None:
    """Replace the out-of-scope denylist."""
    global _denylist
    with _lock:
        _denylist = [e.strip() for e in entries if e and e.strip()]


def clear_denylist() -> None:
    global _denylist
    with _lock:
        _denylist = []


def list_denylist() -> list[str]:
    with _lock:
        return list(_denylist)


def check_scope(target: str) -> None:
    """
    Raise ValueError if target is not in scope.
    Target can be IP, domain, or URL (hostname extracted).
    Scope file empty = all targets allowed (dev/lab mode).
    An out-of-scope denylist (set via set_denylist) is enforced even in lab mode.
    Thread-safe: safe to call from concurrent asyncio tasks.
    """
    # Argument-injection guard: a target beginning with '-' could be parsed as a
    # command-line flag by the downstream tool (e.g. '-oN/tmp/x'). Reject it here
    # so the guard runs for EVERY tool that scope-checks its target — even in lab
    # mode (empty scope), which returns early below.
    if isinstance(target, str) and target.startswith("-"):
        raise ValueError(
            f"Refusing target that starts with '-' (possible argument injection): {target!r}"
        )

    host = _extract_host(target)

    # Out-of-scope denylist takes precedence over everything, including lab mode.
    for entry in list_denylist():
        if _matches(host, entry):
            raise ValueError(
                f"Target '{host}' is explicitly OUT OF SCOPE for the active program "
                f"(matched deny rule '{entry}'). Refusing to proceed."
            )

    scope = _load_scope()
    if not scope:
        return  # no scope file = unrestricted (lab mode)

    for entry in scope:
        if _matches(host, entry):
            return

    raise ValueError(
        f"Target '{host}' is not in scope. "
        f"Add it to {SCOPE_FILE} to authorize. "
        f"Current scope: {scope}"
    )


def add_scope(entry: str) -> None:
    with open(SCOPE_FILE, "a") as f:
        f.write(entry.strip() + "\n")
    _invalidate()


def set_scope(entries: list[str]) -> None:
    """Replace entire scope with a new list."""
    with open(SCOPE_FILE, "w") as f:
        for e in entries:
            f.write(e.strip() + "\n")
    _invalidate()


def remove_scope(entry: str) -> bool:
    current = _load_scope()
    new = [e for e in current if e != entry.strip()]
    if len(new) == len(current):
        return False
    with open(SCOPE_FILE, "w") as f:
        for e in new:
            f.write(e + "\n")
    _invalidate()
    return True


def clear_scope() -> None:
    """Remove scope file — reverts to lab mode (all targets allowed)."""
    if os.path.exists(SCOPE_FILE):
        os.unlink(SCOPE_FILE)
    _invalidate()


def list_scope() -> list[str]:
    return _load_scope()
