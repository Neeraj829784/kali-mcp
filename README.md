<div align="center">

# kali-mcp

**AI-powered penetration testing platform for Kali Linux**

[![Tests](https://github.com/Neeraj829784/kali-mcp/actions/workflows/test.yml/badge.svg)](https://github.com/Neeraj829784/kali-mcp/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

*81 MCP tools · 21 finding extractors · 25 CVE-specific remediations · 7 attack chain templates · 145 tests*

</div>

---

kali-mcp turns your AI assistant into a hands-on penetration testing partner. It wraps 30+ Kali Linux security tools into structured MCP tool calls — every scan result is automatically parsed into findings, deduplicated across tools, tagged to your engagement, and correlated into attack chains. The AI gets structured data, not raw text.

```
You: "Scan 10.10.10.5 for vulnerabilities"

AI:  → scan_host(target="10.10.10.5", intensity="normal")
     → Finds open ports 22, 80, 445
     → Runs nikto + gobuster + nuclei + enum4linux in parallel
     → Extracts 14 findings, boosts confidence on corroborated ones
     → Identifies chain: "Exposed .git + Admin Panel → Credential Leak"
     → Suggests: hydra on SSH, sqlmap on login form
     → All findings tagged to your engagement automatically
```

---

## Table of Contents

- [How It Works](#how-it-works)
- [What Makes It Different](#what-makes-it-different)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Tool Reference](#tool-reference)
- [Workflows](#workflows)
- [Finding Pipeline](#finding-pipeline)
- [Attack Chain Engine](#attack-chain-engine)
- [Engagement System](#engagement-system)
- [Security Model](#security-model)
- [Configuration](#configuration)
- [Webhook Notifications](#webhook-notifications)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Deployment](#deployment)
- [Contributing](#contributing)
- [License](#license)

---

## How It Works

```
┌─────────────────────────────────────────────┐
│          AI Client (Claude, Kiro, etc.)      │
└─────────────────┬───────────────────────────┘
                  │  MCP stdio transport
                  ▼
┌─────────────────────────────────────────────┐
│           FastMCP Server (server.py)         │
│                                             │
│  ┌──────────┐  ┌─────────┐  ┌───────────┐  │
│  │ Job Mgr  │  │  Scope  │  │Engagement │  │
│  │ (async)  │  │ (allow) │  │ Manager   │  │
│  │ retry    │  │ thread  │  │ aiosqlite │  │
│  │ backoff  │  │  safe   │  │           │  │
│  └──────────┘  └─────────┘  └───────────┘  │
│                                             │
│  ┌──────────┐  ┌─────────┐  ┌───────────┐  │
│  │ Findings │  │ Chains  │  │Remediation│  │
│  │ 21 tools │  │ 7 temps │  │ 25 CVEs   │  │
│  │ dedup +  │  │ conf-   │  │ keyword   │  │
│  │ corrobor │  │ weighted│  │ fallback  │  │
│  └──────────┘  └─────────┘  └───────────┘  │
└─────────────────────────────────────────────┘
         │              │             │
         ▼              ▼             ▼
   [Subprocess]   [SQLite DBs]  [Artifacts]
   nmap, nuclei   jobs.db       scan outputs
   gobuster, etc  vault.db      screenshots
                  engage.db     pcap files
```

**The execution flow for every tool call:**

1. Scope check — target validated against allowlist (thread-safe, CIDR/wildcard support)
2. Input validation — nmap targets validated against allowlist regex before subprocess
3. Rate gate — per-tool async lock enforces configured requests/sec
4. Subprocess — runs in its own session (setsid), process group killed on timeout/cancel
5. Retry — transient failures (timeout, crash) retry up to 2× with exponential backoff
6. Extraction — raw output parsed by per-tool extractor into structured finding dicts
7. Verification — web path findings actively re-checked against soft-404 baseline
8. Deduplication — same finding from multiple tools merged, confidence boosted
9. Tagging — findings written to engagement DB (fast path, single indexed query)
10. Webhook — high/critical findings fire HTTP notification (Slack/Discord/custom)

---

## What Makes It Different

**vs. running tools manually**

Every tool result is immediately structured. No regex on raw output. No copy-pasting between tools. No forgetting what you found 3 scans ago. The AI sees findings, not terminal dumps.

**vs. other pentest MCP servers**

Most MCP pentest tools wrap tool execution and return raw stdout. kali-mcp goes further:

| Feature | Raw wrapper | kali-mcp |
|---|---|---|
| Structured findings | ❌ | ✅ 21 extractors |
| False positive filtering | ❌ | ✅ Soft-404 + nikto noise |
| Cross-tool corroboration | ❌ | ✅ Confidence boost |
| Attack chain narratives | ❌ | ✅ 7 templates, confidence-weighted |
| CVE-specific remediation | ❌ | ✅ 25 CVEs, specific patch versions |
| Engagement lifecycle | ❌ | ✅ Full DB-backed workflow |
| Retry on failure | ❌ | ✅ 2× with backoff |
| Rate limiting | ❌ | ✅ Per-tool async lock |
| Input validation | ❌ | ✅ Allowlist regex |
| Encrypted credential vault | ❌ | ✅ Fernet AES-128 |

**vs. commercial platforms**

No subscription, no cloud, no data leaves your machine. Runs entirely on your Kali box. The LLM is the UI — no dashboards to learn, no UI to click through.

---

## Requirements

### Python

```
Python 3.11+
```

### System Tools

Install all at once on Kali:

```bash
sudo apt install -y nmap gobuster nikto ffuf hydra sqlmap \
  subfinder amass theharvester wpscan enum4linux smbclient \
  searchsploit netcat-openbsd whois dnsutils tshark \
  metasploit-framework masscan seclists

# gowitness (screenshots) — go required
go install github.com/sensepost/gowitness@latest
```

Minimum required (everything else degrades gracefully):

```bash
sudo apt install -y nmap gobuster nikto nuclei ffuf hydra sqlmap
```

### Python Dependencies

```
mcp[cli]>=1.27.2    aiosqlite>=0.22.1   httpx>=0.28.1
paramiko>=5.0.0     cryptography        anyio>=4.13.0
```

---

## Installation

```bash
# 1. Clone
git clone https://github.com/Neeraj829784/kali-mcp.git
cd kali-mcp

# 2. Virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install
pip install -e ".[dev]"

# 4. Verify
python3 -c "from server import mcp; print('Ready')"
```

**One-command installer (Kali/Debian/Ubuntu):**

```bash
curl -fsSL https://raw.githubusercontent.com/Neeraj829784/kali-mcp/main/install.sh | sudo bash
```

---

## Quick Start

### 1. Connect to your AI client

**Claude Desktop** — edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

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

**Kiro / other MCP clients** — point to `server.py` with the venv Python.

### 2. Run a preflight check

```
→ server_health()
```

Verifies all binaries, Python deps, and wordlists before your first scan.

### 3. Start an engagement

```
→ engagement_start(
    name="ClientX-WebApp-2026",
    scope=["10.10.10.0/24", "example.com"],
    client="ClientX Ltd"
  )
```

All subsequent tool calls automatically check scope and tag findings.

### 4. Scan

```
→ scan_host(target="10.10.10.5", intensity="normal")
→ scan_web(url="http://10.10.10.5", depth="normal")
```

### 5. Triage

```
→ analyze_findings(min_severity="medium")
→ analyze_attack_chains()
```

### 6. Report

```
→ generate_pentest_report(format="html", save_to="artifacts/report.html")
```

### 7. Close

```
→ engagement_end()
```

---

## Tool Reference

### Reconnaissance (12 tools)

| Tool | What it does |
|---|---|
| `nmap_host_discovery(targets)` | Ping scan — live host discovery |
| `nmap_port_scan(targets, ports, scan_type, timing, wait)` | TCP/SYN/UDP port scan — returns job_id or blocks with `wait=True` |
| `nmap_service_detection(targets, ports, version_intensity)` | Service version detection `-sV` |
| `nmap_os_detection(targets)` | OS fingerprinting `-O`, auto-sudo if not root |
| `nmap_vuln_scan(targets, ports, scripts)` | NSE vulnerability scripts |
| `nmap_aggressive_scan(targets, ports)` | Full `-A` scan: OS + version + scripts + traceroute |
| `nmap_xml_scan(targets, ports, scan_type, timing, service_detection)` | Structured XML output — returns parsed host/port/service dicts |
| `subfinder_enumerate(domain, all_sources, threads)` | Passive subdomain enumeration |
| `amass_enum(domain, passive, brute_force, timeout_mins)` | OWASP Amass deep subdomain discovery |
| `theharvester_search(domain, source, limit, dns_resolve)` | OSINT: emails, subdomains, IPs |
| `whois_lookup(target)` | WHOIS registration data |
| `dig_lookup(domain, record_type, dns_server, short)` | DNS record queries |
| `dig_zone_transfer(domain, nameserver)` | DNS zone transfer attempt (AXFR) |

> All nmap tools validate target tokens against an allowlist regex — `--script=evil` and `/etc/passwd` style injection is blocked before subprocess execution.

### Scanning (8 tools)

| Tool | What it does |
|---|---|
| `gobuster_dir(url, wordlist, extensions, threads, exclude_codes, follow_redirect)` | Directory/file brute-force |
| `gobuster_dns(domain, wordlist, show_ips, threads)` | DNS subdomain brute-force |
| `gobuster_vhost(url, wordlist, append_domain, threads)` | Virtual host discovery |
| `nikto_scan(target, port, ssl, max_time, timeout)` | Web server vulnerability scan |
| `ffuf_fuzz(url, wordlist, keyword, match_codes, filter_codes, threads, data, method, headers, auto_calibrate)` | Web endpoint fuzzer |
| `enum4linux_scan(target, username, password)` | Full SMB/NetBIOS enumeration |
| `smbclient_list_shares(target, username, password, port)` | List accessible SMB shares |
| `fast_port_scan(target, ports, rate, service_detection)` | masscan discovery + targeted nmap `-sV` |

### Vulnerability Assessment (6 tools)

| Tool | What it does |
|---|---|
| `nuclei_scan(target, templates, severity, tags, rate_limit, concurrency, auto_scan)` | Template-based vulnerability scanning |
| `nuclei_update_templates()` | Pull latest Nuclei template database |
| `wpscan_scan(url, enumerate, api_token, detection_mode, random_user_agent)` | WordPress vulnerability scan |
| `searchsploit_search(query, cve, exact, title_only, exclude)` | Local Exploit-DB search |
| `searchsploit_get_path(edb_id)` | Get exploit file path by EDB-ID |
| `cve_to_exploit(service, version, banner, os_type)` | Given a service version → find searchsploit + MSF exploits |
| `scan_and_exploit_chain(target, ports)` | Full chain: port scan → version detect → CVE lookup per service |

### Exploitation (9 tools)

| Tool | What it does |
|---|---|
| `sqlmap_scan(url, data, level, risk, dbms, technique, enumerate_dbs, enumerate_tables, dump, database, table, cookie, random_agent)` | SQL injection detection and exploitation |
| `hydra_bruteforce(target, service, username, userlist, password, passlist, port, tasks, stop_on_first)` | Multi-protocol password brute-force |
| `msf_search(query)` | Search Metasploit module database |
| `msf_run_module(module, options, payload)` | Run a Metasploit module non-interactively via resource file |
| `msfvenom_generate(payload, lhost, lport, format, filename)` | Generate payloads — saved `chmod 600` to artifacts/ |
| `ssh_exec(host, username, password, key_file, command, port, timeout)` | Execute commands via SSH (paramiko, no sshpass) |
| `ssh_enum_privesc(host, username, password, key_file, port)` | Enumerate SUID/sudo/capabilities/cron privesc vectors |
| `nc_port_check(host, ports)` | Quick TCP port open/closed check |
| `nc_banner_grab(host, port, send_data, timeout)` | Grab raw service banners |

### Web Testing (7 tools)

| Tool | What it does |
|---|---|
| `http_request(url, method, headers, cookies, data, follow_redirects, timeout, save_to, extract_text)` | Full HTTP request — status, headers, body, redirect chain, timing |
| `html_to_text(html)` | Strip tags, return visible text |
| `extract_links(html, base_url, only_same_origin)` | Extract anchors, forms, scripts, images from HTML |
| `http_form_submit(url, form_data, method, headers, cookies, follow_redirects)` | Submit HTML forms |
| `web_crawl(url, max_depth, max_pages, include_external, timeout)` | Organic crawler — discovers endpoints wordlists miss |
| `screenshot_url(url, timeout)` | Single URL screenshot via gowitness |
| `screenshot_urls(urls, threads, timeout)` | Batch screenshots for visual triage |

### Analysis & Reporting (9 tools)

| Tool | What it does |
|---|---|
| `generate_pentest_report(title, min_severity, min_confidence, host, save_to, format, confirmed_only)` | Professional report: exec summary + attack chains + findings + CVE remediation. Markdown or standalone HTML |
| `generate_report(job_ids, title, format)` | Quick report from specific job IDs |
| `list_completed_jobs(tool_filter)` | List finished jobs, optionally filtered |
| `parse_nmap_output(job_id)` | Structured nmap XML parsing |
| `parse_nuclei_output(findings_file)` | Structured Nuclei JSONL parsing |
| `pcap_extract(pcap_path)` | Extract credentials and key data from PCAP |
| `pcap_protocols(pcap_path)` | Protocol hierarchy and conversation list |
| `tshark_query(pcap_path, display_filter, fields, max_lines)` | Arbitrary tshark filter queries |
| `read_file(path, max_bytes, offset, as_hex, as_base64)` | Safe file reading with magic byte detection |
| `list_artifacts()` | List all files in artifacts directory |

### Engagement & Triage (16 tools)

| Tool | What it does |
|---|---|
| `engagement_start(name, scope, client, notes)` | Start engagement — sets scope automatically |
| `engagement_status()` | Active engagement + findings summary |
| `engagement_findings(min_severity, host, limit)` | All findings for current engagement |
| `engagement_end()` | Close engagement, clear scope |
| `engagement_list()` | All engagements, past and active |
| `list_unconfirmed_findings(host, min_severity)` | Findings awaiting validation |
| `update_finding_status(finding_id, status)` | Mark `confirmed` / `false_positive` / `unconfirmed` |
| `analyze_findings(host, min_severity, min_confidence, max_items)` | AI triage: attack paths, quick wins, next steps |
| `analyze_attack_chains(host, min_severity, min_confidence)` | Correlate findings into compound attack chains |
| `get_findings(job_id, host, min_severity, min_confidence)` | Extract normalized findings from a job |
| `creds_store(host, username, password, hash, service, port, source_tool, notes)` | Store credentials — encrypted at rest (Fernet) |
| `creds_list(host, service)` | List credentials with decrypted passwords |
| `creds_use(host, service)` | Best credential for a host/service |
| `creds_delete(cred_id)` | Remove credential from vault |
| `server_health()` | Preflight: binaries, Python deps, wordlists |
| `check_binary(name)` | Check if a specific binary is installed |

### Scope Management (5 tools)

| Tool | What it does |
|---|---|
| `scope_list()` | Show current scope (empty = lab mode) |
| `scope_add(target)` | Add IP, CIDR, domain, or wildcard |
| `scope_set(targets)` | Replace entire scope |
| `scope_remove(target)` | Remove one target |
| `scope_clear()` | Reset to lab mode |

### Job Management (4 tools)

| Tool | What it does |
|---|---|
| `get_job_status(job_id)` | Status and result of an async job |
| `get_job_output(job_id, tail)` | Partial output from running/completed job |
| `list_jobs(limit)` | Recent jobs with statuses and retry counts |
| `cancel_job(job_id)` | Kill a running job and its process group |

---

## Workflows

### `scan_host` — Parallel Host Scan

Fires multiple tools simultaneously based on detected services. Reduces total recon time by 70%+ vs sequential scanning.

```
scan_host(target="10.10.10.5", intensity="normal")

Phase 1:  nmap port scan (completes first)
          ↓ detects open services
Phase 2:  [parallel]
          Web found  → nikto + gobuster + nuclei
          SMB found  → enum4linux + nmap smb vuln scripts
          SSH found  → service version banner
```

**Intensity levels:**

| Level | Ports | Timing | Phase 1 method | Time |
|---|---|---|---|---|
| `light` | top 100 | T5 | nmap | ~1 min |
| `normal` | 1-10000 | T4 | nmap | ~5 min |
| `deep` | 1-65535 | T3 | masscan → nmap | ~15 min |

> `deep` uses masscan at configurable PPS (1000/5000/10000 by intensity level) for fast port discovery, then targeted nmap `-sV` only on confirmed open ports. Falls back to nmap-only if masscan is not installed.

### `scan_web` — Parallel Web Scan

```
scan_web(url="http://10.10.10.5", depth="normal")

Runs simultaneously: nikto, gobuster, nuclei, web crawler
After crawl: gowitness screenshots of interesting URLs
Returns: consolidated findings from all scanners + screenshot paths
```

### MCP Prompts — Built-in Workflow Templates

Three reusable prompts that give the AI a complete step-by-step plan:

**`recon_domain(domain)`** — Full domain recon
```
whois → dig (A/NS/MX/TXT) → subfinder → theharvester → amass → report
```

**`web_pentest(url)`** — Web application pentest
```
nmap → nikto → gobuster → gobuster_vhost → ffuf → nuclei
→ wpscan (if WordPress) → sqlmap (if login forms) → report
```

**`smb_enum(target)`** — Windows/Samba enumeration
```
nmap (135/139/445) → smbclient (anonymous) → enum4linux → nmap smb vuln scripts
```

---

## Finding Pipeline

Every tool result flows through this pipeline before the AI ever sees it:

```
Raw output
    │
    ▼ Per-tool extractor (21 tools)
Structured finding: {host, port, service, title, severity, confidence, evidence, tool}
    │
    ▼ Soft-404 / wildcard verification (gobuster, ffuf paths only)
    │  → Random baseline request establishes wildcard fingerprint
    │  → Paths matching baseline dropped as false positives
    │  → Distinct responses promoted to high confidence
    │
    ▼ Deduplication keyed on (host, port, normalized_title)
    │  → Highest severity kept
    │  → Longest evidence kept
    │  → 2+ distinct tools agreeing → confidence bumped one level
    │
    ▼ Engagement tagging (async, single DB write)
    │
    ▼ Webhook notification (high/critical, fire-and-forget)
```

### Confidence Levels

| Level | Meaning | Examples |
|---|---|---|
| `high` | Tool actively confirmed | nmap open port, hydra valid creds, sqlmap injectable, MSF session opened |
| `medium` | Template/script matched | nuclei template, wpscan vuln, nmap NSE script |
| `low` | Pattern guess | gobuster path, nikto header finding, ffuf endpoint |

### Extractors by Tool

| Tool | What gets extracted |
|---|---|
| `nmap` | Open ports, service versions, NSE vuln findings |
| `nmap_os_detection` | OS name/version with confidence level |
| `nuclei` | JSONL findings with severity from template metadata |
| `nikto` | High-signal findings only (XSS, SQLi, RCE) — header noise filtered |
| `gobuster_dir/vhost` | Discovered paths with HTTP status |
| `gobuster_dns` | Discovered subdomains (strips IP brackets) |
| `sqlmap` | Injectable parameters, enumerated databases |
| `hydra` | Valid credentials with port/service |
| `searchsploit` | Matching exploits from local ExploitDB |
| `nuclei` | Template matches with severity |
| `wpscan` | Vulnerable plugins with CVSS score |
| `enum4linux` | SMB users, shares, null sessions |
| `theharvester` | Emails, subdomains with IPs |
| `subfinder / amass` | Discovered subdomains |
| `ssh_enum_privesc` | SUID binaries, sudo NOPASSWD, Linux capabilities |
| `msf_run_module` | **Meterpreter/shell sessions (CRITICAL)**, loot, `[+]` success lines |
| `ffuf` | Discovered endpoints from JSON or plain text output |

---

## Attack Chain Engine

The chain engine correlates individual findings into compound-impact narratives. 7 templates with confidence-weighted signals.

### How signals work

Each signal (e.g. `creds`, `sqli`, `ssh_open`) uses **authoritative tool matching** before keyword matching:

- **Authoritative tool** (hydra, sqlmap, cve_to_exploit) → signal always fires, regardless of confidence
- **Keyword match + medium+ confidence** → signal fires (scanner confirmed)
- **Keyword match + low confidence** → signal does NOT fire (Nikto noise ignored)

This prevents "password field detected by Nikto" from triggering a credential lateral movement chain in your client report.

### Chain Templates

| Chain | Signals Required | Escalation |
|---|---|---|
| SQL Injection → Credential Theft → System Access | `sqli` + `ssh_open` | +1 severity |
| Exposed Sensitive File → Authenticated Access | `info_disclosure` + `admin_panel` | +2 severity |
| Admin Panel + Weak Credentials → Privileged Access | `admin_panel` + `creds` | +1 severity |
| Recovered Credentials → Lateral Movement | `creds` + `ssh_open` | +1 severity |
| Unauthenticated SMB RCE (EternalBlue) | `smb_vuln` | +0 (already critical) |
| File Upload → Remote Code Execution | `admin_panel` + `file_upload` | +2 severity |
| Outdated Service + Public Exploit → Compromise | `open_port` + `exploit_available` | +1 severity |

Each chain includes a human-readable narrative explaining the compound impact — ready to paste into a client report.

---

## Engagement System

The engagement system provides a complete professional pentest workflow:

```python
# Start — sets scope automatically on all tools
engagement_start(name="ACME-WebApp-2026", scope=["10.10.10.0/24"])

# All scans run here — findings auto-tagged to engagement

# Triage — reads from engagement DB (O(1) query, not O(n) job rescan)
analyze_findings(min_severity="medium")

# Validate findings — optional zero-FP workflow
list_unconfirmed_findings()
update_finding_status(finding_id=42, status="confirmed")
update_finding_status(finding_id=43, status="false_positive")

# Report — confirmed_only=True for zero-FP client delivery
generate_pentest_report(
    format="html",
    confirmed_only=True,
    save_to="artifacts/ACME-report.html"
)

# Close
engagement_end()
```

### What the report includes

- Executive summary with host/finding counts and risk rating
- Attack chains section with compound-impact narratives
- Findings grouped by severity (critical → info)
- Per-finding: host, tool, evidence, CVE-specific remediation
- Scan coverage appendix: tools used, job count, timestamp

---

## Security Model

### Scope Enforcement

Every tool call validates the target before execution. The scope cache is protected by a `threading.Lock` — safe under parallel tool execution.

```
scope.txt (empty) = lab mode — all targets allowed
scope.txt (populated) = restricted mode

Supported formats:
  10.0.0.1          exact IP
  192.168.1.0/24    CIDR range
  example.com       exact domain
  *.example.com     wildcard subdomain
```

### Input Validation

All nmap tools run target tokens through an allowlist regex before building the subprocess command. Blocks:

```
--script=evil     → flag injection
/etc/passwd       → path traversal
10.0.0.1;id       → command injection
```

Allows: IPs, CIDRs (`x.x.x.x/n`), hostnames, ranges (`x-y`), wildcards.

### Credential Vault

```
Encryption:  Fernet (AES-128-CBC + HMAC)
Key source:  KALI_MCP_VAULT_KEY env var, or vault.key (0600)
Storage:     vault.db (git-ignored)
Thread safety: double-checked locking on key init
```

### File Access

All report save paths are validated against an allowlist:
- `artifacts/` (created `0700`)
- `/tmp`, `/var/tmp`

Path traversal (`../../../etc/passwd`) is blocked at `safe_save_path()`.

### Secrets in Git

The following are always git-ignored:

```
vault.key, vault.db, jobs.db, engagements.db
audit.log, scope.txt, artifacts/
```

### Audit Trail

Every tool call is written to `audit.log`:

```
2026-06-15 14:32:10 scope_add target=10.10.10.0/24
2026-06-15 14:32:15 get_job_status job_id=a1b2c3d4
```

---

## Configuration

All tunable parameters live in `config.py`:

```python
# Per-tool timeouts (seconds)
TOOL_TIMEOUTS = {
    "nmap_port_scan":      1800,  # 30 min for full port range
    "sqlmap":              2400,  # 40 min for deep injection
    "hydra":               1800,  # 30 min brute-force
    "nuclei":               900,
    "default":              120,
}

# Per-tool rate limits (req/sec, 0 = no limit)
RATE_LIMITS = {
    "nuclei":    150,
    "ffuf":       40,
    "gobuster_dir": 10,
    "hydra":      16,
    "masscan":  5000,   # pps, handled separately
}

# masscan packets-per-second by intensity
MASSCAN_RATE = {
    "light":   1000,   # stealthy — VPN/remote targets
    "normal":  5000,   # balanced default
    "deep":   10000,   # fast — LAN only
}
```

---

## Webhook Notifications

Get notified when a critical finding lands — Slack, Discord, or any HTTP endpoint.

```bash
# Enable in environment
export KALI_MCP_WEBHOOK_URL="https://hooks.slack.com/services/XXX/YYY/ZZZ"
export KALI_MCP_WEBHOOK_MIN_SEVERITY="high"   # default: critical
```

Auto-detects payload format:
- **Slack** — `text` + `attachments` with colour-coded severity
- **Discord** — `embeds` with hex colour codes
- **Generic** — flat JSON for Teams, custom endpoints

Fire-and-forget — never blocks the scan pipeline.

---

## Project Structure

```
kali-mcp/
├── server.py              # MCP server entry point — registers all 81 tools
├── config.py              # Timeouts, rate limits, masscan PPS, wordlists, webhook
├── job_manager.py         # Async job queue — retry, rate gate, finding extraction
├── scope.py               # Target allowlist (thread-safe cache)
├── engagement.py          # Named engagement lifecycle (aiosqlite)
├── findings.py            # 21 per-tool extractors + dedup + soft-404 verification
├── chains.py              # Attack chain engine — 7 templates, confidence-weighted
├── remediation.py         # CVE-specific + keyword remediation lookup (25 CVEs)
├── triage.py              # AI triage — fast path from engagement DB
├── workflow.py            # Parallel scan workflows (scan_host, scan_web)
├── suggest.py             # Auto-suggest next steps after tool completion
├── webhook.py             # Slack/Discord/generic finding notifications
├── cred_vault.py          # Fernet-encrypted credential storage
├── health.py              # Binary + dependency preflight checks
├── parsers.py             # Structured parsers (nmap XML, nuclei JSONL)
│
├── tools/
│   ├── base.py                    # ToolExecutor + rate gate + safe_save_path
│   ├── file_tools.py
│   ├── reconnaissance/
│   │   ├── nmap.py                # 7 nmap tools + _validate_targets()
│   │   ├── subfinder.py
│   │   ├── amass.py
│   │   ├── theharvester.py
│   │   ├── whois_tool.py
│   │   └── dig_tool.py
│   ├── scanning/
│   │   ├── gobuster.py
│   │   ├── nikto.py
│   │   ├── ffuf.py
│   │   ├── enum4linux.py
│   │   ├── smbclient_tool.py
│   │   └── fast_port_scan.py
│   ├── vulnerability/
│   │   ├── nuclei.py
│   │   ├── wpscan.py
│   │   ├── searchsploit.py
│   │   └── cve_to_exploit.py
│   ├── exploitation/
│   │   ├── sqlmap.py
│   │   ├── hydra.py
│   │   ├── metasploit.py          # RC file injection protection
│   │   ├── ssh_tools.py           # paramiko, WarningPolicy
│   │   └── netcat.py
│   ├── web/
│   │   ├── web_tools.py
│   │   ├── web_crawler.py
│   │   └── screenshot.py
│   └── reporting/
│       ├── report_generator.py    # HTML/Markdown report with CVE remediation
│       └── pcap_parser.py
│
├── tests/                         # 145 tests across 22 files
├── .github/workflows/test.yml     # CI — runs all non-integration tests on every PR
├── artifacts/                     # git-ignored scan outputs, screenshots, payloads
├── audit.log                      # git-ignored tool call log
├── kali-mcp.service               # systemd unit file
├── install.sh                     # One-command Kali/Debian/Ubuntu installer
└── pyproject.toml
```

---

## Testing

```bash
# Fast tests — runs in ~5 seconds
pytest

# With verbose output
pytest -v

# Specific area
pytest tests/test_chains.py
pytest tests/test_findings.py
pytest tests/test_suggest.py

# All tests including slow integration
pytest -m "slow or live"
```

**Test coverage by area:**

| File | What it covers |
|---|---|
| `test_core.py` | JobManager, ToolExecutor, scope |
| `test_findings.py` | All 21 extractors, dedup, soft-404 |
| `test_chains.py` | Chain templates, confidence-weighted signals |
| `test_suggest.py` | Auto-suggest logic — all 8 tool branches |
| `test_fixes_hp.py` | aiosqlite, triage fast path, rate limiting |
| `test_fixes_mp.py` | Retry, scope thread safety, CVE remediation, chains |
| `test_fixes_lp.py` | nmap XML, masscan, webhooks, screenshots |
| `test_fixes_missing.py` | OS/MSF extractors, masscan rate, input validation |
| `test_coverage_gaps.py` | Parsers, vault, engagement lifecycle, gobuster_dns |
| `test_report.py` | Report generation, HTML output, attack chains in reports |

---

## Deployment

### Systemd Service

```bash
sudo cp kali-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now kali-mcp
journalctl -u kali-mcp -f
```

The service file runs as `neeraj` with the project venv. Edit paths in `kali-mcp.service` if your username or install path differs.

### Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `KALI_MCP_VAULT_KEY` | (from `vault.key`) | Credential vault encryption key |
| `KALI_MCP_WEBHOOK_URL` | `""` | Webhook endpoint (empty = disabled) |
| `KALI_MCP_WEBHOOK_MIN_SEVERITY` | `critical` | Minimum severity to notify |

---

## Contributing

The pattern for adding a new tool is consistent across all 27 tool modules:

```python
# tools/category/my_tool.py
from config import TOOL_TIMEOUTS
from scope import check_scope

def _register(mcp, job_mgr):

    @mcp.tool()
    async def my_tool_name(target: str) -> dict:
        """One-line description for the AI."""
        check_scope(target)
        cmd = ["my-binary", target]
        return await job_mgr.run_and_wait(
            "my_tool_name", cmd, TOOL_TIMEOUTS.get("default", 120)
        )
```

Then in `server.py`:

```python
from tools.category import my_tool
# Add to the module registration list
```

If the tool produces findings, add an extractor to `findings.py` and register it in `_EXTRACTORS`. Write tests. Open a PR — CodeRabbit reviews every PR automatically.

---

## License

MIT — see [LICENSE](LICENSE).

**Authorized use only.** This tool is designed for systems you own or have explicit written authorization to test. Unauthorized scanning is illegal under the CFAA, Computer Misuse Act, and equivalent laws worldwide. The scope enforcement system is a safety aid, not a substitute for written authorization.

---

<div align="center">

Built by [Neeraj Vasupalli](https://github.com/Neeraj829784)

*81 tools · 21 extractors · 25 CVEs · 7 attack chains · 145 tests · 21 PRs*

</div>
