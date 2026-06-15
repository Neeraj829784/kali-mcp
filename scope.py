"""
Scope allowlist — all tool targets must pass check_scope() before execution.
Add authorized targets to SCOPE_FILE (one per line: IPs, CIDRs, domains).

FIX: Added threading.Lock around _cache reads/writes to prevent TOCTOU race
     under concurrent tool calls (scan_host fires many tools in parallel).
"""
import ipaddress
import os
import threading

SCOPE_FILE = os.path.join(os.path.dirname(__file__), "scope.txt")

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


def check_scope(target: str) -> None:
    """
    Raise ValueError if target is not in scope.
    Target can be IP, domain, or URL (hostname extracted).
    Scope file empty = all targets allowed (dev/lab mode).
    Thread-safe: safe to call from concurrent asyncio tasks.
    """
    scope = _load_scope()
    if not scope:
        return  # no scope file = unrestricted (lab mode)

    # Extract hostname from URL
    host = target
    if "://" in target:
        host = target.split("://", 1)[1].split("/")[0].split(":")[0]

    for entry in scope:
        if entry == host:
            return
        if "/" in entry and _is_ip(host) and _in_cidr(host, entry):
            return
        # Subdomain match: *.example.com
        if entry.startswith("*.") and host.endswith(entry[1:]):
            return
        if host == entry.lstrip("*."):
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
