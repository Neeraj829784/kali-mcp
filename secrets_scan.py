"""Detect secrets / API keys leaked in text (typically JavaScript files).

Pure `scan_secrets` (no I/O) is unit-tested; the MCP tool fetches JS URLs and
runs it over their bodies. Matches are redacted so the tool output never dumps a
full live credential.
"""
import re

_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Access Key",
     re.compile(r"(?i)aws.{0,20}?(?:secret|key).{0,20}?['\"]([A-Za-z0-9/+]{40})['\"]")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}")),
    ("GitHub Token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,255}")),
    ("Stripe Live Secret Key", re.compile(r"sk_live_[0-9A-Za-z]{24,}")),
    ("Stripe Live Publishable Key", re.compile(r"pk_live_[0-9A-Za-z]{24,}")),
    ("Google OAuth Client Secret", re.compile(r"GOCSPX-[0-9A-Za-z\-_]{20,}")),
    ("Private Key Block",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("Generic secret assignment",
     re.compile(r"(?i)(?:api[_-]?key|apikey|secret|token|passwd|password)"
                r"['\"]?\s*[:=]\s*['\"]([^'\"\s]{8,64})['\"]")),
]


def _redact(s: str) -> str:
    s = s.strip()
    if len(s) <= 8:
        return (s[:1] + "***") if s else "***"
    return f"{s[:4]}...{s[-4:]}"


def scan_secrets(text: str, source: str = "") -> list[dict]:
    """Return a list of {type, match_redacted, source} for secrets found in text."""
    found: list[dict] = []
    seen: set = set()
    for name, rx in _PATTERNS:
        for m in rx.finditer(text or ""):
            val = m.group(0)
            key = (name, val)
            if key in seen:
                continue
            seen.add(key)
            found.append({"type": name, "match_redacted": _redact(val), "source": source})
    return found
