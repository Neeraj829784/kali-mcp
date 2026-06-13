"""Remediation guidance lookup — maps finding patterns to actionable fix text.

Pure functions, no I/O. Called by the report generator to attach remediation
advice to each finding automatically.
"""
from __future__ import annotations

# Each entry: (pattern_keywords, short_title, detail)
_REMEDIATIONS: list[tuple[tuple[str, ...], str, str]] = [
    (("sql injection", "sqli", "injectable"),
     "Parameterised Queries / ORM",
     "Replace string-concatenated queries with parameterised statements or an ORM. "
     "Apply allowlist input validation. Disable detailed SQL error messages in production."),

    (("valid credential", "credentials found", "password:"),
     "Rotate Credentials + Enforce MFA",
     "Immediately rotate all discovered credentials. Enable MFA on exposed services. "
     "Audit password policy and enforce minimum complexity. Remove hardcoded secrets from code."),

    (("xss", "cross-site scripting"),
     "Output Encoding + CSP",
     "Encode all user-supplied data before rendering in HTML/JS contexts. "
     "Implement a strict Content-Security-Policy header. Use a template engine with auto-escaping."),

    (("ms17-010", "eternalblue", "smb-vuln"),
     "Patch SMB + Disable Legacy Protocols",
     "Apply MS17-010 security updates immediately. Disable SMBv1. "
     "Restrict SMB (445/139) to required internal hosts via firewall. Enable Windows Firewall."),

    ((".git", ".env", "backup", "directory listing", "index of"),
     "Remove Exposed Files + Restrict Directory Listing",
     "Remove .git, .env, backup, and config files from the web root. "
     "Disable directory listing in the web server config. "
     "Audit the deployment pipeline to prevent sensitive files being published."),

    (("file upload", "upload"),
     "Restrict File Upload",
     "Validate file type server-side via magic bytes (not extension/MIME header). "
     "Store uploads outside the web root. Rename files on save. "
     "Scan uploaded content with antivirus. Disable script execution in upload directories."),

    (("lfi", "path traversal", "directory traversal", "local file inclusion"),
     "Canonicalise + Allowlist File Paths",
     "Resolve all user-supplied paths with realpath() and verify they fall within "
     "an allowlisted base directory. Reject requests containing '../', '%2e%2e', or null bytes."),

    (("open port", "service"),
     "Reduce Attack Surface",
     "Disable or firewall off services not required for the application's function. "
     "Run services as low-privilege users. Keep software up-to-date."),

    (("phpinfo",),
     "Disable phpinfo()",
     "Remove or restrict access to phpinfo() pages. They disclose server paths, "
     "PHP version, loaded modules, and environment variables useful to attackers."),

    (("default credential", "default password", "admin:admin", "admin:password"),
     "Change Default Credentials",
     "Change all default vendor credentials immediately after deployment. "
     "Add default-credential checks to the deployment checklist."),

    (("ssl", "tls", "certificate", "https"),
     "Enforce TLS + HSTS",
     "Configure TLS 1.2+ only; disable TLS 1.0/1.1 and SSLv3. "
     "Set HSTS with a long max-age. Obtain a valid certificate from a trusted CA."),

    (("cors",),
     "Restrict CORS Policy",
     "Set Access-Control-Allow-Origin to a specific trusted origin, not '*'. "
     "Do not reflect the Origin header blindly. Combine with CSRF tokens for state-changing requests."),
]

_DEFAULT_REMEDIATION = (
    "Investigate and Remediate",
    "Review the finding in context, assess exploitability, and apply the principle of "
    "least privilege. Consult the relevant vendor advisory or CVE entry for specific patches.",
)


def get_remediation(finding: dict) -> tuple[str, str]:
    """Return (short_title, detail) for the closest matching remediation.

    Matches against the finding's title, evidence, service, and tool fields.
    Returns the default guidance if nothing specific matches.
    """
    haystack = " ".join(
        str(finding.get(k, "")) for k in ("title", "evidence", "service", "tool")
    ).lower()

    for keywords, short, detail in _REMEDIATIONS:
        if any(kw in haystack for kw in keywords):
            return short, detail

    return _DEFAULT_REMEDIATION
