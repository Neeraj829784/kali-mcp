"""
Attack-chain engine — correlates individual findings into named attack chains.

The value of a pentest report is rarely a single critical bug; it's the story of
how several smaller issues combine into real impact (e.g. info disclosure leaks a
credential, which unlocks an admin panel, which allows RCE). This module turns a
flat list of findings into those compound-impact narratives.

Pure functions, no I/O, no tool calls — fully unit-testable offline.

FIX: Replaced pure keyword substring matching with confidence-weighted signals.
     Each signal now considers the finding's confidence level and source tool,
     not just text content. This eliminates false chains from low-confidence
     Nikto noise (e.g. "password field" triggering the creds signal) and
     ensures Hydra/SQLMap confirmed credentials always trigger correctly.
"""
from __future__ import annotations

# Severity ordering (kept local so this module has no hard dependency on findings.py)
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_RANK_SEV = {v: k for k, v in _SEV_RANK.items()}
_CONF_RANK = {"low": 0, "medium": 1, "high": 2}

# Tools whose findings are authoritative for specific signal types
_CRED_TOOLS = {"hydra", "sqlmap", "cred_vault"}
_SQLI_TOOLS = {"sqlmap"}
_EXPLOIT_TOOLS = {"searchsploit", "metasploit", "cve_to_exploit"}


def _text(f: dict) -> str:
    """Lowercased haystack of a finding's searchable fields."""
    return " ".join(str(f.get(k, "")) for k in ("title", "evidence", "service", "tool")).lower()


def _conf(f: dict) -> int:
    """Return numeric confidence rank for a finding."""
    return _CONF_RANK.get(str(f.get("confidence", "medium")).lower(), 1)


def _max_sev(findings: list[dict]) -> str:
    if not findings:
        return "info"
    return _RANK_SEV[max(_SEV_RANK.get(f.get("severity", "info"), 0) for f in findings)]


def _escalate(base_sev: str, levels: int = 1) -> str:
    """Raise a severity by N levels, capped at critical."""
    rank = min(_SEV_RANK.get(base_sev, 0) + levels, _SEV_RANK["critical"])
    return _RANK_SEV[rank]


# ── Confidence-weighted signal detectors ─────────────────────────────────────
# Rules:
#   - Authoritative tool match  → always fires regardless of confidence
#   - Keyword match + high conf → fires (scanner actively confirmed)
#   - Keyword match + med conf  → fires (template matched)
#   - Keyword match + low conf  → does NOT fire (Nikto noise, gobuster paths etc.)
#
# This prevents "password field detected" (low-conf Nikto) from triggering
# credential chains while still catching all Hydra/SQLMap confirmed finds.

def _cred_signal(findings: list[dict]) -> list[dict]:
    """Credential findings: authoritative tools OR high/med confidence text match."""
    result = []
    for f in findings:
        tool = str(f.get("tool", "")).lower()
        txt = _text(f)
        is_authoritative = tool in _CRED_TOOLS
        is_keyword = any(k in txt for k in ("valid credential", "credentials found",
                                             "password found", "login successful"))
        if is_authoritative or (is_keyword and _conf(f) >= _CONF_RANK["medium"]):
            result.append(f)
    return result


def _sqli_signal(findings: list[dict]) -> list[dict]:
    """SQL injection: authoritative tool OR high-confidence text match only."""
    result = []
    for f in findings:
        tool = str(f.get("tool", "")).lower()
        txt = _text(f)
        is_authoritative = tool in _SQLI_TOOLS
        is_keyword = any(k in txt for k in ("sql injection", "sqli", "injectable"))
        if is_authoritative or (is_keyword and _conf(f) >= _CONF_RANK["high"]):
            result.append(f)
    return result


def _exploit_signal(findings: list[dict]) -> list[dict]:
    """Exploit available: authoritative tool OR medium+ confidence text match."""
    result = []
    for f in findings:
        tool = str(f.get("tool", "")).lower()
        txt = _text(f)
        is_authoritative = tool in _EXPLOIT_TOOLS
        is_keyword = any(k in txt for k in ("cve-", "exploit", "searchsploit"))
        if is_authoritative or (is_keyword and _conf(f) >= _CONF_RANK["medium"]):
            result.append(f)
    return result


def _keyword_signal(findings: list[dict], *needles: str,
                    min_conf: str = "medium") -> list[dict]:
    """Generic keyword signal with configurable minimum confidence threshold."""
    min_rank = _CONF_RANK.get(min_conf, 1)
    return [
        f for f in findings
        if any(n in _text(f) for n in needles) and _conf(f) >= min_rank
    ]


def _signals(findings: list[dict]) -> dict[str, list[dict]]:
    return {
        "sqli":             _sqli_signal(findings),
        "creds":            _cred_signal(findings),
        "ssh_open":         [f for f in findings
                             if f.get("port") == 22 or "ssh" in _text(f)],
        "admin_panel":      _keyword_signal(findings,
                                "/admin", "/wp-admin", "/phpmyadmin",
                                "admin panel", min_conf="low"),
        "info_disclosure":  _keyword_signal(findings,
                                ".git", ".env", "backup", "config",
                                "phpinfo", "directory listing", "index of",
                                min_conf="medium"),
        "smb_vuln":         _keyword_signal(findings,
                                "ms17-010", "eternalblue", "smb-vuln",
                                min_conf="low"),
        "exploit_available": _exploit_signal(findings),
        "file_upload":      _keyword_signal(findings,
                                "upload", "file upload",
                                min_conf="medium"),
        "lfi":              _keyword_signal(findings,
                                "lfi", "local file inclusion",
                                "path traversal", "directory traversal",
                                min_conf="medium"),
        "open_port":        [f for f in findings
                             if "open port" in _text(f)
                             and _conf(f) >= _CONF_RANK["high"]],
    }


# ── Chain templates ─────────────────────────────────────────────────────────

_CHAIN_TEMPLATES = [
    {
        "name": "SQL Injection → Credential Theft → System Access",
        "requires": ["sqli", "ssh_open"],
        "narrative": (
            "A SQL injection vulnerability allows extraction of the application's "
            "user/credential tables. Reused or cracked credentials can then be used "
            "against the exposed SSH service to gain interactive system access — "
            "turning a single web flaw into full host compromise."
        ),
        "escalate": 1,
    },
    {
        "name": "Exposed Sensitive File → Credential Leak → Authenticated Access",
        "requires": ["info_disclosure", "admin_panel"],
        "narrative": (
            "Sensitive files (e.g. .git, .env, backups) are exposed and disclose "
            "secrets or credentials. These unlock the discovered admin/login interface, "
            "giving an attacker authenticated access without brute force."
        ),
        "escalate": 2,
    },
    {
        "name": "Admin Panel + Weak Credentials → Privileged Access",
        "requires": ["admin_panel", "creds"],
        "narrative": (
            "An administrative interface is reachable and valid credentials were "
            "recovered. Together these grant privileged application access, often a "
            "stepping stone to code execution via plugin/upload features."
        ),
        "escalate": 1,
    },
    {
        "name": "Recovered Credentials → Lateral Movement → Privilege Escalation",
        "requires": ["creds", "ssh_open"],
        "narrative": (
            "Recovered credentials authenticate to the exposed SSH service. Once on "
            "the host, local privilege-escalation vectors (SUID, sudo, cron, kernel) "
            "can be enumerated to reach root and pivot further into the network."
        ),
        "escalate": 1,
    },
    {
        "name": "Unauthenticated SMB RCE (EternalBlue class)",
        "requires": ["smb_vuln"],
        "narrative": (
            "The host is vulnerable to a critical SMB flaw (e.g. MS17-010 / EternalBlue) "
            "that permits unauthenticated remote code execution as SYSTEM — full "
            "compromise with no credentials required."
        ),
        "escalate": 0,
    },
    {
        "name": "File Upload → Remote Code Execution",
        "requires": ["admin_panel", "file_upload"],
        "narrative": (
            "An authenticated upload feature accepts attacker-controlled files. Combined "
            "with predictable storage paths, a web shell can be planted and executed, "
            "yielding remote code execution on the web server."
        ),
        "escalate": 2,
    },
    {
        "name": "Outdated Service + Public Exploit → Compromise",
        "requires": ["open_port", "exploit_available"],
        "narrative": (
            "An exposed service runs a version with a known public exploit. The "
            "combination of network reachability and an available exploit makes "
            "compromise straightforward and likely."
        ),
        "escalate": 1,
    },
]


def build_attack_chains(findings: list[dict]) -> list[dict]:
    """Correlate findings into named attack chains.

    Returns a list of chain dicts, each with:
      - name:        the chain's name
      - severity:    escalated combined severity (compound impact)
      - narrative:   human-readable story of how the chain works
      - steps:       ordered contributing findings (title + host + tool)
      - hosts:       affected hosts
      - finding_count
    Only chains whose required signals are ALL present are returned, sorted by
    severity (critical first).
    """
    if not findings:
        return []

    sig = _signals(findings)
    chains = []
    for tpl in _CHAIN_TEMPLATES:
        if not all(sig.get(req) for req in tpl["requires"]):
            continue
        contributing: list[dict] = []
        seen: set[tuple] = set()
        for req in tpl["requires"]:
            for f in sig[req]:
                key = (f.get("host", ""), f.get("title", ""), f.get("tool", ""))
                if key not in seen:
                    seen.add(key)
                    contributing.append(f)
        base = _max_sev(contributing)
        severity = _escalate(base, tpl["escalate"])
        hosts = sorted({f.get("host", "") for f in contributing if f.get("host")})
        chains.append({
            "name": tpl["name"],
            "severity": severity,
            "narrative": tpl["narrative"],
            "steps": [
                {
                    "title": f.get("title", ""),
                    "host": f.get("host", ""),
                    "tool": f.get("tool", ""),
                    "severity": f.get("severity", "info"),
                    "confidence": f.get("confidence", "medium"),
                }
                for f in contributing
            ],
            "hosts": hosts,
            "finding_count": len(contributing),
        })

    chains.sort(key=lambda c: _SEV_RANK.get(c["severity"], 0), reverse=True)
    return chains
