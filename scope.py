"""
Scope allowlist — all tool targets must pass check_scope() before execution.
Add authorized targets to SCOPE_FILE (one per line: IPs, CIDRs, domains).
"""
import ipaddress
import os
import re

SCOPE_FILE = os.path.join(os.path.dirname(__file__), "scope.txt")


def _load_scope() -> list[str]:
    if not os.path.exists(SCOPE_FILE):
        return []
    with open(SCOPE_FILE) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


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


def set_scope(entries: list[str]) -> None:
    """Replace entire scope with a new list."""
    with open(SCOPE_FILE, "w") as f:
        for e in entries:
            f.write(e.strip() + "\n")


def remove_scope(entry: str) -> bool:
    current = _load_scope()
    new = [e for e in current if e != entry.strip()]
    if len(new) == len(current):
        return False
    with open(SCOPE_FILE, "w") as f:
        for e in new:
            f.write(e + "\n")
    return True


def clear_scope() -> None:
    """Remove scope file — reverts to lab mode (all targets allowed)."""
    if os.path.exists(SCOPE_FILE):
        os.unlink(SCOPE_FILE)


def list_scope() -> list[str]:
    return _load_scope()
