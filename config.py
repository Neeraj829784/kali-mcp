import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
JOBS_DB_PATH = os.path.join(BASE_DIR, "jobs.db")
ARTIFACTS_DIR = os.path.join(BASE_DIR, "artifacts")
AUDIT_LOG_PATH = os.path.join(BASE_DIR, "audit.log")
SCOPE_FILE = os.path.join(BASE_DIR, "scope.txt")

# Ensure artifacts directory exists with restricted permissions
os.makedirs(ARTIFACTS_DIR, exist_ok=True)
os.chmod(ARTIFACTS_DIR, 0o700)

# Webhook — set KALI_MCP_WEBHOOK_URL env var to receive critical finding alerts.
# Supports any HTTP endpoint that accepts JSON POST (Slack, Discord, Teams, custom).
# Leave empty to disable notifications.
WEBHOOK_URL: str = os.environ.get("KALI_MCP_WEBHOOK_URL", "")
WEBHOOK_MIN_SEVERITY: str = os.environ.get("KALI_MCP_WEBHOOK_MIN_SEVERITY", "critical")

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
