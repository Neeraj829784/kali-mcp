import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
JOBS_DB_PATH = os.path.join(BASE_DIR, "jobs.db")
ARTIFACTS_DIR = os.path.join(BASE_DIR, "artifacts")
AUDIT_LOG_PATH = os.path.join(BASE_DIR, "audit.log")
SCOPE_FILE = os.path.join(BASE_DIR, "scope.txt")

# Program Scope & Policy engine store (see program_scope.py). Holds named
# bug-bounty/pentest programs, their in/out-of-scope rules, rules-of-engagement
# policies, and approval grants. Git-ignored — may contain real target scope.
PROGRAMS_DB_PATH = os.path.join(BASE_DIR, "programs.db")

# TOFU known-hosts store for SSH host-key pinning (see tools/exploitation/ssh_tools.py).
# First connection to a host pins its key here; a later key change is rejected as
# a possible MITM. Git-ignored — never commit.
SSH_KNOWN_HOSTS = os.path.join(BASE_DIR, "known_hosts")

# Centralized TLS certificate verification for the built-in HTTP helpers
# (finding verification, crawlers, http_request). Pentest targets frequently
# use self-signed / expired certs, so this defaults to OFF for usability.
# Set KALI_MCP_TLS_VERIFY=1 (or true/yes) to enforce certificate validation.
TLS_VERIFY: bool = os.environ.get("KALI_MCP_TLS_VERIFY", "0").lower() in ("1", "true", "yes")

# Ensure artifacts directory exists with restricted permissions
os.makedirs(ARTIFACTS_DIR, exist_ok=True)
os.chmod(ARTIFACTS_DIR, 0o700)

# Webhook — set KALI_MCP_WEBHOOK_URL env var to receive critical finding alerts.
# Supports any HTTP endpoint that accepts JSON POST (Slack, Discord, Teams, custom).
# Leave empty to disable notifications.
WEBHOOK_URL: str = os.environ.get("KALI_MCP_WEBHOOK_URL", "")
WEBHOOK_MIN_SEVERITY: str = os.environ.get("KALI_MCP_WEBHOOK_MIN_SEVERITY", "critical")

# Maximum number of external tool subprocesses allowed to run concurrently
# across the whole server. Per-tool RATE_LIMITS cap requests/sec, but NOT the
# number of simultaneously-running processes — a few parallel deep scans
# (scan_host/scan_web fan-out) could otherwise exhaust CPU/file descriptors.
# This global semaphore bounds that. Override with KALI_MCP_MAX_CONCURRENT_TOOLS.
try:
    MAX_CONCURRENT_TOOLS: int = max(1, int(os.environ.get("KALI_MCP_MAX_CONCURRENT_TOOLS", "8")))
except ValueError:
    MAX_CONCURRENT_TOOLS = 8

# Per-tool timeouts in seconds
TOOL_TIMEOUTS = {
    "nmap_host_discovery": 120,
    "nmap_port_scan": 1800,  # 30 min for large ranges
    "nmap_service_detection": 900,
    "nmap_os_detection": 600,
    "nmap_vuln_scan": 1200,
    "nmap_aggressive_scan": 1200,
    "subfinder": 300,
    "theharvester": 300,
    "amass": 600,
    "nikto": 600,
    "gobuster_dir": 600,
    "gobuster_dns": 300,
    "gobuster_vhost": 300,
    "enum4linux": 300,
    "ffuf": 600,
    "nuclei": 900,
    "wpscan": 600,
    "sqlmap": 2400,  # 40 min
    "hydra": 1800,
    "msf_run_module": 600,
    "default": 120,
}

# Per-tool rate limits (requests/sec, 0 = no limit)
RATE_LIMITS = {
    "nuclei": 150,
    "ffuf": 40,
    "gobuster_dir": 10,
    "gobuster_dns": 10,
    "gobuster_vhost": 10,
    "nikto": 0,
    "hydra": 16,
    "sqlmap": 0,
    # masscan rate is packets-per-second, not requests/sec — handled separately
    # in workflow.py via MASSCAN_RATE. Kept here for documentation/override.
    "masscan": 5000,
}

# masscan PPS defaults — configurable per intensity level
MASSCAN_RATE = {
    "light":  1000,   # stealthy — suitable for VPN/remote targets
    "normal": 5000,   # default — balanced speed vs reliability
    "deep":   10000,  # fast — LAN/local targets only
}

# Seclists fallback wordlists
WORDLISTS = {
    "dirb_common": (
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
    ),
    "dns_subdomains": (
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/wordlists/dirb/common.txt",
    ),
}


def find_wordlist(key: str) -> str:
    for path in WORDLISTS.get(key, []):
        if os.path.exists(path):
            return path
    raise FileNotFoundError(f"No wordlist found for '{key}'. Install seclists: apt install seclists")
