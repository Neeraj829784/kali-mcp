# kali-mcp

**AI-assisted penetration testing MCP server for Kali Linux.**

Transforms 28+ Kali security tools into structured, AI-consumable MCP tool calls with built-in safety controls, engagement management, credential vaulting, automated finding extraction, and parallel workflow execution.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Tool Catalog](#tool-catalog)
  - [Reconnaissance](#reconnaissance)
  - [Scanning](#scanning)
  - [Vulnerability Assessment](#vulnerability-assessment)
  - [Exploitation](#exploitation)
  - [Web Testing](#web-testing)
  - [Reporting & Analysis](#reporting--analysis)
  - [Engagement Management](#engagement-management)
- [Workflows](#workflows)
- [Security Model](#security-model)
- [Configuration](#configuration)
- [Testing](#testing)
- [Systemd Service](#systemd-service)
- [Claude Desktop Integration](#claude-desktop-integration)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **28+ MCP Tools** — Wraps nmap, gobuster, nikto, nuclei, sqlmap, hydra, metasploit, wpscan, amass, subfinder, theHarvester, enum4linux, ffuf, searchsploit, gowitness, tshark, and more
- **Scope Enforcement** — Allowlist-based target authorization prevents accidental unauthorized scanning
- **Async Job Queue** — Long-running scans run in background with process group management, cancellation support, and partial output reads
- **Engagement Model** — Named engagements group scope, jobs, findings, and credentials for professional pentest organization
- **Credential Vault** — Fernet-encrypted SQLite storage for discovered credentials, thread-safe with env-var key support
- **Confidence-Scored Findings** — Every finding carries a `confidence` level (high/medium/low) separate from severity. Tool-confirmed findings (sqlmap injectable, hydra valid creds, nmap open port) = high; template matches = medium; pattern guesses (nikto, gobuster) = low
- **Finding Deduplication + Cross-Tool Corroboration** — Identical findings from multiple tools are merged into one; when 2+ distinct tools agree, confidence is boosted automatically
- **Soft-404 / Wildcard Detection** — Gobuster/ffuf path findings are actively re-verified; wildcard server responses are dropped as false positives; confirmed distinct paths are promoted to high confidence
- **Nikto Noise Filtering** — Low-value header/info lines are filtered out; only actionable findings (XSS, SQLi, RCE, injection) are kept
- **Attack Chain Engine** — Correlates small individual findings into compound-impact narratives (e.g. "SQL Injection → Credential Theft → System Access"). Automatically escalates combined severity beyond individual finding severity
- **Professional Report Generator** — `generate_pentest_report` produces a client-ready Markdown report from vuln findings (not raw scan output): executive summary, attack chains section, findings grouped by severity with evidence + remediation guidance + confidence, scan coverage appendix. Supports `min_severity`, `min_confidence`, and `save_to` file output
- **Remediation Guidance** — Automatic remediation lookup for 12 vulnerability classes (SQLi, XSS, SMB vulns, file upload, path traversal, credential issues, TLS, CORS, and more)
- **Auto-Suggest Next Steps** — Chain-of-thought recommendations based on tool findings (e.g., "SSH port found → suggest hydra brute force")
- **Parallel Workflows** — `scan_host` and `scan_web` fire multiple tools simultaneously, reducing total recon time by 70%+
- **CVE-to-Exploit Chain** — Given a service version, finds matching exploits in searchsploit and Metasploit automatically
- **Audit Logging** — Every tool call is logged with timestamp for compliance and review
- **Health Checks** — Preflight verification of all tool binaries, Python dependencies, and wordlists
- **PCAP Analysis** — Protocol extraction, credential discovery, and arbitrary tshark queries on captured traffic
- **Screenshot Recon** — Visual triage of discovered endpoints using gowitness
- **File Inspection** — Safe file reading with magic byte detection, hex/base64 output, and path restrictions

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     MCP Client (Claude)                      │
└──────────────────────────────┬──────────────────────────────┘
                               │ stdio transport
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                    FastMCP Server (server.py)                │
├────────────┬────────────┬────────────┬──────────────────────┤
│  Job Mgr   │   Scope    │   Creds    │   Engagement Mgr     │
│  (async)   │  (allow)   │   Vault    │   (named scopes)     │
├────────────┴────────────┴────────────┴──────────────────────┤
│                    Tool Modules Layer                        │
├────────────┬────────────┬────────────┬──────────────────────┤
│ Recon      │ Scanning   │ Vuln       │ Exploitation         │
│ nmap       │ gobuster   │ nuclei     │ sqlmap               │
│ subfinder  │ nikto      │ wpscan     │ hydra                │
│ amass      │ ffuf       │ searchsploit│ metasploit          │
│ dig/whois  │ enum4linux │ cve_exploit│ ssh_tools            │
│ harvester  │ smbclient  │            │ netcat               │
├────────────┼────────────┼────────────┼──────────────────────┤
│ Web        │ Reporting  │ Utils      │                      │
│ http_req   │ reports    │ health     │                      │
│ crawler    │ pcap_parse │ findings   │                      │
│ screenshot │            │ suggest    │                      │
└────────────┴────────────┴────────────┴──────────────────────┘
       │              │              │
       ▼              ▼              ▼
  [Subprocess]   [SQLite DBs]   [Artifacts Dir]
  nmap, nuclei   jobs.db        scan outputs
  gobuster, etc  vault.db       screenshots
                 engagements.db pcap files
```

---

## Requirements

### System Dependencies

| Tool | Install Command | Purpose |
|------|----------------|---------|
| nmap | `apt install nmap` | Port scanning & service detection |
| gobuster | `apt install gobuster` | Directory & subdomain brute-force |
| nikto | `apt install nikto` | Web server vulnerability scanning |
| nuclei | `apt install nuclei` | Template-based vulnerability scanning |
| sqlmap | `apt install sqlmap` | SQL injection detection & exploitation |
| hydra | `apt install hydra` | Password brute-force |
| ffuf | `apt install ffuf` | Web fuzzer |
| subfinder | `apt install subfinder` | Passive subdomain enumeration |
| amass | `apt install amass` | In-depth subdomain enumeration |
| theHarvester | `apt install theharvester` | OSINT gathering |
| wpscan | `apt install wpscan` | WordPress vulnerability scanning |
| enum4linux | `apt install enum4linux` | SMB/NetBIOS enumeration |
| smbclient | `apt install smbclient` | SMB share listing |
| searchsploit | `apt install exploitdb` | Exploit database search |
| metasploit | `apt install metasploit-framework` | Exploit framework |
| netcat/ncat | `apt install netcat-openbsd` | Port checking & banner grabbing |
| whois | `apt install whois` | WHOIS lookups |
| dnsutils | `apt install dnsutils` | DNS queries (dig) |
| tshark | `apt install tshark` | PCAP analysis |
| gowitness | `go install github.com/sensepost/gowitness@latest` | Web screenshots |
| masscan | `apt install masscan` | Fast port scanning (optional) |

### Wordlists

```bash
apt install seclists
```

Provides: `dirb/common.txt`, `seclists/Discovery/Web-Content/common.txt`, `seclists/Discovery/DNS/subdomains-top1million-5000.txt`, `rockyou.txt`

### Python 3.11+

```bash
python3 --version  # Must be 3.11 or higher
```

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Neeraj829784/kali-mcp.git
cd kali-mcp
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

Or with optional dev dependencies:

```bash
pip install -e ".[dev]"
```

### 4. Verify Installation

```bash
python3 -c "from server import mcp; print('MCP server ready')"
```

### 5. Run Health Check

```bash
python3 server.py  # Server starts — use MCP client to call server_health tool
```

Or manually check binaries:

```bash
python3 -c "
import shutil
tools = ['nmap', 'gobuster', 'nikto', 'nuclei', 'sqlmap', 'hydra', 'ffuf', 'subfinder', 'amass', 'theHarvester', 'wpscan', 'enum4linux', 'smbclient', 'searchsploit', 'whois', 'dig', 'tshark']
for t in tools:
    status = '✓' if shutil.which(t) else '✗'
    print(f'{status} {t}')
"
```

---

## Quick Start

### Connect to Claude Desktop

The `claude_desktop_config.json` file is pre-configured. Point Claude Desktop to it:

```json
{
  "mcpServers": {
    "kali-mcp": {
      "command": "/path/to/kali-mcp/venv/bin/python",
      "args": ["/path/to/kali-mcp/server.py"]
    }
  }
}
```

### Basic Usage Flow

```
1. Start an engagement:
   → engagement_start(name="ClientX-WebApp-2026", scope=["192.168.1.0/24", "example.com"])

2. Run a parallel host scan:
   → scan_host(target="192.168.1.10", intensity="normal")

3. Check findings:
   → analyze_findings(host="192.168.1.10", min_severity="high")

4. Follow suggestions:
   → The system auto-suggests next steps based on what was found

5. Generate a report:
   → generate_report(job_ids=["abc123", "def456"], title="ClientX Assessment")

6. End the engagement:
   → engagement_end()
```

---

## Tool Catalog

### Reconnaissance

| Tool | Description |
|------|-------------|
| `nmap_host_discovery(targets)` | Ping scan to discover live hosts (-sn) |
| `nmap_port_scan(targets, ports, scan_type, timing)` | Port scan with SYN/TCP/UDP options |
| `nmap_service_detection(targets, ports, version_intensity)` | Detect service versions (-sV) |
| `nmap_os_detection(targets)` | OS fingerprinting (-O) |
| `nmap_vuln_scan(targets, ports, scripts)` | NSE vulnerability scripts |
| `nmap_aggressive_scan(targets, ports)` | Full aggressive scan (-A) |
| `subfinder_enumerate(domain, all_sources, threads)` | Passive subdomain enumeration |
| `amass_enum(domain, passive, brute_force)` | OWASP Amass subdomain discovery |
| `theharvester_search(domain, source, limit)` | OSINT: emails, subdomains, IPs |
| `whois_lookup(target)` | WHOIS registration data |
| `dig_lookup(domain, record_type, dns_server)` | DNS record queries |
| `dig_zone_transfer(domain, nameserver)` | DNS zone transfer attempt (AXFR) |

### Scanning

| Tool | Description |
|------|-------------|
| `gobuster_dir(url, wordlist, extensions)` | Directory/file brute-force |
| `gobuster_dns(domain, wordlist)` | DNS subdomain brute-force |
| `gobuster_vhost(url, wordlist)` | Virtual host discovery |
| `nikto_scan(target, port, ssl)` | Web server vulnerability scan |
| `ffuf_fuzz(url, wordlist, keyword, method)` | Web endpoint fuzzer |
| `enum4linux_scan(target, username, password)` | SMB/NetBIOS enumeration |
| `smbclient_list_shares(target, username, password)` | List SMB shares |
| `fast_port_scan(target, ports, rate)` | masscan + nmap two-phase scan |

### Vulnerability Assessment

| Tool | Description |
|------|-------------|
| `nuclei_scan(target, templates, severity, tags)` | Template-based vuln scanning |
| `nuclei_update_templates()` | Update Nuclei template database |
| `wpscan_scan(url, enumerate, api_token)` | WordPress vulnerability scan |
| `searchsploit_search(query, cve, exact)` | Exploit-DB local search |
| `searchsploit_get_path(edb_id)` | Get exploit file path by EDB-ID |
| `cve_to_exploit(service, version, banner)` | Find exploits for a service version |
| `scan_and_exploit_chain(target, ports)` | Full scan → detect → exploit chain |

### Exploitation

| Tool | Description |
|------|-------------|
| `sqlmap_scan(url, data, level, risk, dbms)` | SQL injection detection & exploitation |
| `hydra_bruteforce(target, service, username, passlist)` | Password brute-force |
| `msf_search(query)` | Search Metasploit modules |
| `msf_run_module(module, options, payload)` | Run a Metasploit module non-interactively |
| `msfvenom_generate(payload, lhost, lport, format)` | Generate payloads |
| `ssh_exec(host, username, password/key_file, command)` | Execute commands via SSH |
| `ssh_enum_privesc(host, username, password/key_file)` | Enumerate privilege escalation vectors |
| `nc_port_check(host, ports)` | Quick port open/closed check |
| `nc_banner_grab(host, port, send_data)` | Grab service banners |

### Web Testing

| Tool | Description |
|------|-------------|
| `http_request(url, method, headers, cookies, data)` | Arbitrary HTTP requests with full response |
| `html_to_text(html)` | Strip HTML tags, extract visible text |
| `extract_links(html, base_url)` | Extract anchors, forms, scripts, images from HTML |
| `http_form_submit(url, form_data, method)` | Submit HTML forms (simulates browser POST) |
| `web_crawl(url, max_depth, max_pages)` | Organic web crawler for endpoint discovery |
| `screenshot_url(url)` | Take screenshot of a single URL |
| `screenshot_urls(urls, threads)` | Batch screenshots of multiple URLs |

### Reporting & Analysis

| Tool | Description |
|------|-------------|
| `generate_report(job_ids, title, format)` | Markdown or JSON report from job results |
| `list_completed_jobs(tool_filter)` | List finished jobs, optionally filtered |
| `parse_nmap_output(job_id)` | Structured nmap XML parsing |
| `parse_nuclei_output(findings_file)` | Structured Nuclei JSONL parsing |
| `pcap_extract(pcap_path)` | Extract credentials & data from PCAP files |
| `pcap_protocols(pcap_path)` | Protocol hierarchy & conversations in PCAP |
| `tshark_query(pcap_path, display_filter, fields)` | Arbitrary tshark queries on PCAP |
| `read_file(path, max_bytes, as_hex, as_base64)` | Safe file reading with magic byte detection |
| `list_artifacts()` | List all files in the artifacts directory |

### Engagement Management

| Tool | Description |
|------|-------------|
| `engagement_start(name, scope, client, notes)` | Start a named engagement with authorized targets |
| `engagement_status()` | Show active engagement and findings summary |
| `engagement_findings(min_severity, host, limit)` | Get all findings for current engagement |
| `engagement_end()` | Close engagement and clear scope |
| `engagement_list()` | List all engagements (past and active) |
| `creds_store(host, username, password, hash, service)` | Store discovered credentials |
| `creds_list(host, service)` | List stored credentials with filters |
| `creds_use(host, service)` | Get best credential for a host/service |
| `creds_delete(cred_id)` | Delete a credential from vault |
| `get_findings(job_id, host, min_severity)` | Extract normalized findings from job output |
| `analyze_findings(host, min_severity, max_items)` | AI-assisted triage with attack paths & quick wins |
| `server_health()` | Preflight check of all binaries, deps, and wordlists |
| `check_binary(name)` | Check if a specific binary is installed |

---

## Workflows

### Parallel Host Scan (`scan_host`)

Fires multiple tools simultaneously based on detected services:

```
scan_host(target="192.168.1.10", intensity="normal")

Phase 1: nmap port scan (must complete first)
Phase 2 (parallel based on findings):
  └─ Web detected → nikto + gobuster + nuclei simultaneously
  └─ SMB detected → enum4linux + nmap vuln scan simultaneously
  └─ SSH detected → service version detection
```

**Intensity levels:**
- `light` — Top 100 ports, T5 timing, no follow-up scans (~1 min)
- `normal` — Ports 1-10000, T4 timing, targeted scans (~5 min)
- `deep` — Full port range 1-65535, T3 timing, comprehensive scans (~30 min)

### Parallel Web Scan (`scan_web`)

```
scan_web(url="http://example.com", depth="normal")

Runs simultaneously: nikto, gobuster, nuclei, web crawler
Returns consolidated findings from all scanners
```

### MCP Prompts (Reusable Workflow Templates)

Three built-in prompts that generate step-by-step instructions for the AI:

- `recon_domain(domain)` — Full reconnaissance: whois → DNS → subfinder → theharvester → amass → report
- `web_pentest(url)` — Web app testing: nmap → nikto → gobuster → ffuf → nuclei → wpscan → sqlmap → report
- `smb_enum(target)` — SMB enumeration: nmap → smbclient → enum4linux → vuln scan → report

---

## Security Model

### Scope Enforcement

All tools check `scope.txt` before execution:

- **Empty scope file** → Lab mode (all targets allowed)
- **Populated scope file** → Restricted mode (only listed IPs/CIDRs/domains allowed)
- Wildcard support: `*.example.com` matches all subdomains
- CIDR support: `192.168.1.0/24` matches all IPs in range

### File Access Restrictions

The `read_file` tool only allows access to:
- `artifacts/` directory
- `/tmp` and `/var/tmp`
- `/usr/share/wordlists` and `/usr/share/seclists`

Blocked patterns: `id_rsa`, `.pem`, `.key`, `shadow`, `.ssh/`, `.env`, `.bash_history`, `credentials`, `.aws/`

### Audit Logging

Every tool call is logged to `audit.log`:

```
2026-06-12 14:32:10,123 scope_add target=192.168.1.0/24
2026-06-12 14:32:15,456 get_job_status job_id=a1b2c3d4
2026-06-12 14:33:00,789 cancel_job job_id=e5f6g7h8
```

### Credential Vault

- SQLite database with no encryption at rest
- Store only what you need for the engagement
- Clear with `creds_delete()` when done
- Vault is excluded from git by default (add `-f` to override)

---

## Configuration

Edit `config.py` to customize:

```python
# Timeouts per tool (seconds)
TOOL_TIMEOUTS = {
    "nmap_port_scan": 1800,    # 30 min for large ranges
    "sqlmap": 2400,            # 40 min for deep injection testing
    "default": 120,            # 2 min default
}

# Rate limits (requests/sec, 0 = no limit)
RATE_LIMITS = {
    "nuclei": 150,
    "ffuf": 40,
    "gobuster_dir": 10,
    "hydra": 16,
}

# Wordlist fallback paths
WORDLISTS = {
    "dirb_common": (
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    ),
    "dns_subdomains": (
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    ),
}
```

---

## Testing

```bash
# Run fast tests (excludes slow and live tests)
pytest

# Run all tests including slow ones
pytest -m slow

# Run tests requiring a live target (HTB/DVWA)
pytest -m live

# Run with coverage
pytest --cov=. --cov-report=term-missing
```

Test categories:
- `test_core.py` — Core modules (job manager, scope, findings)
- `test_tier1.py` — Tier 1 tool tests (fast, no network)
- `test_tier2.py` — Tier 2 tool tests (moderate, network)
- `test_tier3.py` — Tier 3 tool tests (slow, full scans)
- `test_tools_*.py` — Per-category tool tests

---

## Systemd Service

For running as a persistent service:

```bash
# Edit paths in kali-mcp.service if needed
sudo cp kali-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable kali-mcp
sudo systemctl start kali-mcp
sudo systemctl status kali-mcp
```

Service configuration:
- Runs as user `neeraj`
- Working directory: `/home/neeraj/kali-mcp`
- Auto-restarts on failure with 5s delay
- Logs to journal (`journalctl -u kali-mcp -f`)

---

## Claude Desktop Integration

The `claude_desktop_config.json` file is pre-configured for Claude Desktop MCP integration:

```json
{
  "mcpServers": {
    "kali-mcp": {
      "command": "/home/neeraj/kali-mcp/venv/bin/python",
      "args": ["/home/neeraj/kali-mcp/server.py"],
      "env": {}
    }
  }
}
```

Update the paths to match your installation, then restart Claude Desktop.

---

## Project Structure

```
kali-mcp/
├── server.py              # FastMCP server entry point (28+ tools)
├── config.py              # Timeouts, rate limits, wordlist paths
├── job_manager.py         # Async job queue with SQLite backend
├── scope.py               # Target allowlist enforcement
├── cred_vault.py          # Credential storage & retrieval
├── findings.py            # Finding extraction & normalization
├── suggest.py             # Auto-suggest next steps
├── triage.py              # AI-assisted finding analysis
├── engagement.py          # Named engagement management
├── workflow.py            # Parallel scan workflows
├── parsers.py             # Structured output parsers (nmap XML, nuclei JSONL)
├── health.py              # Binary & dependency health checks
├── pyproject.toml         # Python project config
├── requirements.txt       # Python dependencies
├── pytest.ini             # Test configuration
├── kali-mcp.service       # Systemd service file
├── claude_desktop_config.json  # MCP client configuration
├── tools/
│   ├── base.py            # ToolExecutor (subprocess runner with process groups)
│   ├── file_tools.py      # File inspection with path restrictions
│   ├── reconnaissance/    # nmap, subfinder, amass, theharvester, whois, dig
│   ├── scanning/          # gobuster, nikto, ffuf, enum4linux, smbclient, fast_port_scan
│   ├── vulnerability/     # nuclei, wpscan, searchsploit, cve_to_exploit
│   ├── exploitation/      # sqlmap, hydra, metasploit, ssh_tools, netcat
│   ├── web/               # http_request, web_crawler, screenshot
│   └── reporting/         # report_generator, pcap_parser
├── tests/                 # pytest test suite
├── artifacts/             # Scan outputs, screenshots, payloads (git-ignored)
├── *.db                   # SQLite databases (git-ignored by default)
└── audit.log              # Tool call audit trail (git-ignored)
```

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-tool`
3. Add your tool in `tools/<category>/` following the `_register(mcp, job_mgr)` pattern
4. Write tests in `tests/`
5. Update this README with the new tool
6. Submit a pull request

### Adding a New Tool

```python
# tools/category/new_tool.py
from config import TOOL_TIMEOUTS
from scope import check_scope

def _register(mcp, job_mgr):
    @mcp.tool()
    async def new_tool_name(target: str) -> dict:
        """Description of what this tool does."""
        check_scope(target)
        cmd = ["new-tool-binary", target]
        return await job_mgr.run_and_wait("new_tool_name", cmd, TOOL_TIMEOUTS.get("default", 120))
```

Then register it in `server.py`:

```python
from tools.category import new_tool
# Add to the module list:
for module in [..., new_tool, ...]:
    module._register(mcp, job_mgr)
```

---

## License

MIT License — see [LICENSE](LICENSE) for full terms.

**Authorized use only.** This tool is designed exclusively for systems you own or have explicit written authorization to test. Unauthorized use is illegal under the CFAA, Computer Misuse Act, and equivalent laws. You accept full responsibility for all use.

The scope enforcement system is a safety aid, not a substitute for proper written authorization.

---

## Author

**Neeraj Vasupalli** — [GitHub](https://github.com/Neeraj829784)

Built for AI-assisted penetration testing with Kali Linux and MCP protocol integration.
