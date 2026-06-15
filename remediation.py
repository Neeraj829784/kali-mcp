"""Remediation guidance lookup — maps finding patterns to actionable fix text.

Pure functions, no I/O (CVE lookup uses a local table, no network calls).
Called by the report generator to attach remediation advice to each finding.

FIX: Added CVE-specific remediation table covering the 25 most common CVEs seen
     in pentests. CVE IDs are extracted from the finding title/evidence before
     falling back to keyword pattern matching, so Log4Shell findings get
     "Update Log4j to 2.17.1" instead of the generic "reduce attack surface".
"""
from __future__ import annotations
import re

# ── CVE-specific remediation ─────────────────────────────────────────────────
# Covers the CVEs most frequently encountered in real-world pentests.
# Format: CVE-ID → (short_title, detailed_fix)

_CVE_REMEDIATIONS: dict[str, tuple[str, str]] = {
    # Log4Shell
    "CVE-2021-44228": (
        "Update Log4j — Log4Shell (CVE-2021-44228)",
        "Upgrade Apache Log4j2 to 2.17.1+ (Java 8) or 2.12.4+ (Java 7). "
        "As a short-term mitigation set log4j2.formatMsgNoLookups=true or remove "
        "the JndiLookup class from the classpath. Block outbound LDAP/RMI at the firewall."
    ),
    "CVE-2021-45046": (
        "Update Log4j — Incomplete Fix (CVE-2021-45046)",
        "Upgrade to Log4j2 2.17.1+. The 2.15.0 patch was incomplete. "
        "Disable JNDI lookups entirely via log4j2.formatMsgNoLookups=true."
    ),
    # EternalBlue / MS17-010
    "CVE-2017-0144": (
        "Patch EternalBlue SMB (MS17-010 / CVE-2017-0144)",
        "Apply Microsoft security bulletin MS17-010 immediately. "
        "Disable SMBv1 via 'Set-SmbServerConfiguration -EnableSMB1Protocol $false'. "
        "Block ports 445/139 at the network perimeter."
    ),
    # BlueKeep
    "CVE-2019-0708": (
        "Patch BlueKeep RDP (CVE-2019-0708)",
        "Apply the Microsoft patch from KB4499175. Disable Remote Desktop if not needed. "
        "Enable Network Level Authentication (NLA). Restrict RDP (3389) to trusted IPs."
    ),
    # PrintNightmare
    "CVE-2021-34527": (
        "Patch PrintNightmare (CVE-2021-34527)",
        "Apply KB5004945 or later. Disable the Print Spooler service on domain controllers "
        "and non-printing servers. Restrict Point and Print driver installation."
    ),
    # Shellshock
    "CVE-2014-6271": (
        "Update Bash — Shellshock (CVE-2014-6271)",
        "Upgrade bash to a patched version (bash 4.3 patch 25+). "
        "Disable CGI scripts that invoke bash. Use a WAF to block malicious function definitions."
    ),
    # Heartbleed
    "CVE-2014-0160": (
        "Update OpenSSL — Heartbleed (CVE-2014-0160)",
        "Upgrade OpenSSL to 1.0.1g or later. Revoke and reissue all TLS certificates. "
        "Rotate session keys and passwords that may have been exposed."
    ),
    # Apache Struts (Equifax)
    "CVE-2017-5638": (
        "Update Apache Struts (CVE-2017-5638)",
        "Upgrade to Struts 2.3.32 or 2.5.10.1+. "
        "Disable multipart parsing if not required. Deploy a WAF rule blocking malicious Content-Type headers."
    ),
    # Apache Log4j DoS
    "CVE-2021-45105": (
        "Update Log4j — DoS (CVE-2021-45105)",
        "Upgrade to Log4j2 2.17.0+ (or 2.12.3+ for Java 7). "
        "This CVE enables infinite recursion DoS via self-referential lookups."
    ),
    # Spring4Shell
    "CVE-2022-22965": (
        "Update Spring Framework — Spring4Shell (CVE-2022-22965)",
        "Upgrade Spring Framework to 5.3.18+ or 5.2.20+. "
        "Upgrade Spring Boot to 2.6.6+ or 2.5.12+. "
        "As a workaround, use a DataBinder.setDisallowedFields allowlist."
    ),
    # ProxyLogon
    "CVE-2021-26855": (
        "Patch Exchange ProxyLogon (CVE-2021-26855)",
        "Apply Microsoft's Exchange security update (March 2021 CUs). "
        "Run the EOMT (Exchange On-premises Mitigation Tool). "
        "Check for web shells in Exchange directories immediately."
    ),
    # Confluence RCE
    "CVE-2022-26134": (
        "Update Atlassian Confluence — OGNL RCE (CVE-2022-26134)",
        "Upgrade to Confluence 7.4.17, 7.13.7, 7.14.3, 7.15.2, 7.16.4, 7.17.4, or 7.18.1+. "
        "Block external access to Confluence until patched. "
        "Check for indicators of compromise: unusual processes spawned by Confluence."
    ),
    # Citrix Bleed
    "CVE-2023-4966": (
        "Update Citrix NetScaler — Citrix Bleed (CVE-2023-4966)",
        "Upgrade to NetScaler ADC/Gateway 14.1-8.50+, 13.1-49.15+, or 13.0-92.19+. "
        "Kill all active sessions after patching. Rotate credentials for accounts "
        "that authenticated through the affected appliance."
    ),
    # MOVEit Transfer
    "CVE-2023-34362": (
        "Patch MOVEit Transfer SQL Injection (CVE-2023-34362)",
        "Apply Progress Software's emergency patch (May 2023). "
        "Disable HTTP/S access until patched. Review activity logs for "
        "unauthorized access, especially the human2.aspx webshell indicator."
    ),
    # Fortinet FortiOS
    "CVE-2023-27997": (
        "Update Fortinet FortiOS — SSL-VPN Heap Overflow (CVE-2023-27997)",
        "Upgrade to FortiOS 6.0.17, 6.2.15, 6.4.13, 7.0.12, or 7.2.5+. "
        "Disable SSL-VPN if not required, or restrict to trusted source IPs."
    ),
    # OpenSSH regreSSHion
    "CVE-2024-6387": (
        "Update OpenSSH — regreSSHion Race Condition (CVE-2024-6387)",
        "Upgrade OpenSSH to 9.8p1+. As a mitigation set LoginGraceTime=0 in sshd_config "
        "(disables unauthenticated connections timing window). Restrict SSH access via firewall."
    ),
    # VMware vCenter
    "CVE-2021-21985": (
        "Update VMware vCenter (CVE-2021-21985)",
        "Apply VMware Security Advisory VMSA-2021-0010. "
        "Restrict vCenter access to management networks only. "
        "Disable the Virtual SAN Health Check plugin if not in use."
    ),
    # Sudo Baron Samedit
    "CVE-2021-3156": (
        "Update sudo — Baron Samedit (CVE-2021-3156)",
        "Upgrade sudo to 1.9.5p2+. This heap overflow allows any local user to gain "
        "root privileges. Patch immediately on all Linux/Unix systems."
    ),
    # Dirty Pipe
    "CVE-2022-0847": (
        "Update Linux kernel — Dirty Pipe (CVE-2022-0847)",
        "Upgrade the Linux kernel to 5.16.11+, 5.15.25+, or 5.10.102+. "
        "This allows unprivileged users to overwrite read-only files including /etc/passwd."
    ),
    # PwnKit
    "CVE-2021-4034": (
        "Update polkit — PwnKit (CVE-2021-4034)",
        "Apply the polkit patch released January 2022 (polkit 0.120+). "
        "Any local user can exploit this to gain full root. "
        "Workaround: chmod 0755 /usr/bin/pkexec"
    ),
    # Apache HTTP Server RCE
    "CVE-2021-41773": (
        "Update Apache HTTP Server — Path Traversal/RCE (CVE-2021-41773)",
        "Upgrade to Apache HTTP Server 2.4.50+. "
        "Disable mod_cgi if not required. This path traversal allows RCE when "
        "mod_cgi is enabled and the target directory has require all granted."
    ),
    "CVE-2021-42013": (
        "Update Apache HTTP Server — Path Traversal bypass (CVE-2021-42013)",
        "Upgrade to Apache HTTP Server 2.4.51+. The 2.4.50 fix was incomplete. "
        "Disable mod_cgi. Block traversal sequences at the WAF."
    ),
    # GitLab RCE
    "CVE-2021-22205": (
        "Update GitLab — ExifTool RCE (CVE-2021-22205)",
        "Upgrade GitLab to 13.10.3, 13.9.6, or 13.8.8+. "
        "This allows unauthenticated RCE via malicious image file uploads processed by ExifTool."
    ),
    # Zimbra
    "CVE-2022-41352": (
        "Update Zimbra — SSRF/RCE (CVE-2022-41352)",
        "Apply Zimbra patch ZCS 9.0.0 P27 or 8.8.15 P34+. "
        "Block access to the Zimbra admin interface from untrusted networks."
    ),
    # F5 BIG-IP
    "CVE-2022-1388": (
        "Update F5 BIG-IP — Authentication Bypass (CVE-2022-1388)",
        "Upgrade BIG-IP to 17.0.0, 16.1.2.2, 15.1.5.1, 14.1.4.6, or 13.1.5+. "
        "Block iControl REST access to the management interface from untrusted networks."
    ),
}

# Regex to extract CVE IDs from any text
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# ── Keyword-based remediation table ──────────────────────────────────────────
# Fallback when no CVE ID is found. Order matters — first match wins.

_REMEDIATIONS: list[tuple[tuple[str, ...], str, str]] = [
    (("sql injection", "sqli", "injectable"),
     "Parameterised Queries / ORM",
     "Replace string-concatenated queries with parameterised statements or an ORM. "
     "Apply allowlist input validation. Disable detailed SQL error messages in production."),

    (("valid credential", "credentials found", "password found", "login successful"),
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

    (("suid", "sudo nopasswd", "capabilities", "privesc"),
     "Harden Privilege Escalation Vectors",
     "Audit SUID/SGID binaries and remove unnecessary ones. Review sudo rules — "
     "never grant NOPASSWD unless essential. Remove dangerous capabilities (cap_setuid, cap_net_raw). "
     "Apply the principle of least privilege to all service accounts."),

    (("smb", "netbios", "null session"),
     "Harden SMB / Restrict NetBIOS",
     "Disable SMBv1. Require SMB signing. Disable null session access. "
     "Restrict SMB to required internal hosts via firewall rules."),
]

_DEFAULT_REMEDIATION = (
    "Investigate and Remediate",
    "Review the finding in context, assess exploitability, and apply the principle of "
    "least privilege. Consult the relevant vendor advisory or CVE entry for specific patches.",
)


def get_remediation(finding: dict) -> tuple[str, str]:
    """Return (short_title, detail) for the closest matching remediation.

    Priority order:
    1. CVE ID found in title/evidence → CVE-specific fix
    2. Keyword pattern match → category fix
    3. Default fallback
    """
    haystack = " ".join(
        str(finding.get(k, "")) for k in ("title", "evidence", "service", "tool")
    )

    # 1. CVE-specific lookup (case-insensitive)
    for cve_id in _CVE_RE.findall(haystack):
        match = _CVE_REMEDIATIONS.get(cve_id.upper())
        if match:
            return match

    haystack_lower = haystack.lower()

    # 2. Keyword pattern match
    for keywords, short, detail in _REMEDIATIONS:
        if any(kw in haystack_lower for kw in keywords):
            return short, detail

    return _DEFAULT_REMEDIATION
