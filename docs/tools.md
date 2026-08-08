# Tool Reference

kali-mcp exposes **123 AI-callable tools**. You never call these directly — your
AI client does, on your behalf. This page is the complete reference so you know
what the AI *can* do and what each action returns.

Every tool that touches a target first checks it against your [scope](security.md),
and most scan results flow through the [Finding Pipeline](finding-pipeline.md)
automatically.

Tools are grouped by phase:

- [Parallel Workflows](#parallel-workflows)
- [Reconnaissance](#reconnaissance)
- [Scanning](#scanning)
- [Vulnerability Assessment](#vulnerability-assessment)
- [Exploitation](#exploitation)
- [Web Testing](#web-testing)
- [Analysis & Reporting](#analysis--reporting)
- [Engagement & Triage](#engagement--triage)
- [Program Scope](#program-scope)
- [Asset Inventory & Continuous Recon](#asset-inventory--continuous-recon)
- [Scope Management](#scope-management)
- [Job Management](#job-management)

---

## Parallel Workflows
One call that fires many tools at once. Full detail in [Workflows](workflows.md).

| Tool | What it does |
|---|---|
| `scan_host(target, intensity)` | Full parallel host scan — port scan, then web/SMB/SSH tools in parallel based on what's found |
| `scan_web(url, depth)` | Full parallel web scan — nikto + gobuster + nuclei + crawler + screenshots |
| `hunt_program(scope, max_assets, format, include_injection)` | **Autonomous single-program hunt**: discovers live hosts, runs the no-injection proof oracles (CORS/.git/.env), optionally (`include_injection`) harvests parameterized URLs and runs read-only injection oracles (open_redirect/LFI/XSS/SSTI). Returns a confirmed-findings-with-proof report (+`format='markdown'`) + coverage ledger + needs-human list |

---

## Reconnaissance

Discovering what exists: hosts, domains, subdomains, DNS records, and OSINT.

| Tool | What it does |
|---|---|
| `nmap_host_discovery(targets)` | Ping scan — finds live hosts, no port scan |
| `nmap_port_scan(targets, ports, scan_type, timing, wait)` | TCP/SYN/UDP port scan. Returns a `job_id`, or blocks with `wait=True` |
| `nmap_service_detection(targets, ports, version_intensity)` | Service version detection (`-sV`) |
| `nmap_os_detection(targets)` | OS fingerprinting (`-O`); auto-uses sudo if not root |
| `nmap_vuln_scan(targets, ports, scripts)` | NSE vulnerability scripts |
| `nmap_aggressive_scan(targets, ports)` | Full `-A` scan: OS + version + scripts + traceroute |
| `nmap_xml_scan(targets, ports, scan_type, timing, service_detection)` | Structured XML output → parsed host/port/service dicts |
| `subfinder_enumerate(domain, all_sources, threads)` | Passive subdomain enumeration |
| `amass_enum(domain, passive, brute_force, timeout_mins)` | OWASP Amass deep subdomain discovery |
| `theharvester_search(domain, source, limit, dns_resolve)` | OSINT: emails, subdomains, IPs |
| `whois_lookup(target)` | WHOIS registration data for a domain or IP |
| `dig_lookup(domain, record_type, dns_server, short)` | DNS record queries (A, MX, NS, TXT, ...) |
| `dig_zone_transfer(domain, nameserver)` | DNS zone transfer attempt (AXFR) |
| `dnsx_resolve(targets, record_type, show_response)` | Fast DNS resolution / record lookup (A/AAAA/CNAME/NS/TXT/PTR/MX) via dnsx |
| `httpx_probe(targets, ports, follow_redirects, match_codes, tech_detect)` | Probe live HTTP services — status, title, server, tech, CDN/WAF, IP (httpx) |
| `asnmap_lookup(query, query_type)` | Map an ASN / IP / domain / org → announced CIDR ranges |
| `gau_urls(domain, include_subs, providers, match_codes, threads, from_date, to_date)` | Passive URL discovery from Wayback / CommonCrawl / OTX / URLScan archives |

> **Injection-safe:** every nmap tool validates target tokens against an
> allowlist regex, so inputs like `--script=evil` or `/etc/passwd` are rejected
> before a subprocess ever runs. See [Security Model](security.md).

---

## Scanning

Enumerating a known host: directories, files, virtual hosts, SMB shares, and open ports at speed.

| Tool | What it does |
|---|---|
| `gobuster_dir(url, wordlist, extensions, threads, exclude_codes, follow_redirect)` | Directory/file brute-force |
| `gobuster_dns(domain, wordlist, show_ips, threads)` | DNS subdomain brute-force |
| `gobuster_vhost(url, wordlist, append_domain, threads)` | Virtual host discovery |
| `nikto_scan(target, port, ssl, max_time, timeout)` | Web server vulnerability scan |
| `ffuf_fuzz(url, wordlist, keyword, match_codes, filter_codes, threads, data, method, headers, auto_calibrate)` | Fast web fuzzer — put `FUZZ` in the URL, headers, or body |
| `enum4linux_scan(target, username, password)` | Full SMB/NetBIOS enumeration (users, shares, policy) |
| `smbclient_list_shares(target, username, password, port)` | List accessible SMB shares |
| `fast_port_scan(target, ports, rate, service_detection)` | masscan discovery + targeted nmap `-sV` (fast for large ranges) |

---

## Vulnerability Assessment

Finding known weaknesses and mapping versions to exploits.

| Tool | What it does |
|---|---|
| `nuclei_scan(target, templates, severity, tags, rate_limit, concurrency, auto_scan)` | Template-based vulnerability scanning |
| `nuclei_update_templates()` | Pull the latest Nuclei template database |
| `wpscan_scan(url, enumerate, api_token, detection_mode, random_user_agent, disable_tls_checks, throttle_ms)` | WordPress vulnerability scan |
| `searchsploit_search(query, exact, title_only, cve, exclude)` | Local Exploit-DB search |
| `searchsploit_get_path(edb_id)` | Get the exploit file path for an EDB-ID |
| `cve_to_exploit(service, version, banner, os_type)` | Given a service version → matching searchsploit + Metasploit exploits |
| `scan_and_exploit_chain(target, ports)` | Full chain: port scan → version detect → CVE lookup per service |
| `verify_vulnerability(vuln_class, url, param)` | Actively **prove** a lead is real (cors, open_redirect, git_exposure, env_exposure, lfi, reflected_xss, ssti) — returns a confirmed verdict + proof pack. Turns "leads" into "proven bugs" |
| `oob_start(payloads, server)` | Mint a unique interactsh canary domain for out-of-band testing of **blind** bugs (SSRF/XSS/RCE/SQLi/XXE) |
| `oob_poll(session_id)` | Check for received callbacks — `confirmed: true` is undeniable proof the blind bug fired |
| `oob_stop(session_id)` | Stop an OOB session and clean up its listener |
| `oob_list()` | List active OOB interaction sessions |
| `verify_blind_ssrf(url, param, wait_seconds)` | **One-shot** blind SSRF proof: injects a canary into `param`, requests `url`, and confirms if the target's server calls back |
| `identity_add(name, headers, cookies, bearer)` | Store a test account's auth material (cookies/bearer/headers) for access-control testing (in-memory only) |
| `identity_list()` | List stored test identities (header keys only — never secret values) |
| `identity_remove(name)` | Remove a stored test identity |
| `verify_access_control(url, owner_identity, test_identities, method, body, include_anonymous)` | **IDOR / broken-access-control** detector — replays the same request as owner vs other identities vs anonymous and flags when a non-owner gets the owner's resource |
| `sweep_idor(urls, owner_identity, test_identities, max_urls, include_anonymous, allow_dangerous, delay_ms)` | **Automatic IDOR sweep** — harvests ID-bearing URLs from a crawl (katana/gau) and bulk-tests each for access-control leaks. Read-only & skips state-changing endpoints by default |
| `race_test(url, count, method, body, identity)` | **Race-condition / double-spend** test — fires many identical requests at once; `likely_race: true` flags a candidate. State-changing — authorized targets only |
| `scan_js_secrets(urls, max_urls)` | Fetch JavaScript/URLs and scan for **leaked secrets/API keys** (AWS/Google/GitHub/Slack/Stripe/JWT/private keys); matches redacted |
| `scan_text_secrets(text)` | Scan a pasted blob of text for leaked secrets/API keys |

---

## Exploitation

Actively testing and, with authorization, exploiting weaknesses.

| Tool | What it does |
|---|---|
| `sqlmap_scan(url, data, level, risk, dbms, technique, enumerate_dbs, enumerate_tables, dump, database, table, cookie, random_agent)` | SQL injection detection and exploitation |
| `hydra_bruteforce(target, service, username, userlist, password, passlist, port, tasks, stop_on_first)` | Multi-protocol password brute-force |
| `msf_search(query)` | Search the Metasploit module database |
| `msf_run_module(module, options, payload)` | Run a Metasploit module non-interactively; sessions auto-closed |
| `msfvenom_generate(payload, lhost, lport, format, filename)` | Generate a payload — saved `chmod 600` under artifacts/ |
| `ssh_exec(host, username, password, key_file, command, port, timeout)` | Run a command over SSH (paramiko, no sshpass; TOFU host-key pinning) |
| `ssh_enum_privesc(host, username, password, key_file, port)` | Enumerate SUID/sudo/capabilities/cron privesc vectors |
| `nc_port_check(host, ports)` | Quick TCP open/closed check |
| `nc_banner_grab(host, port, timeout, send_data)` | Grab a raw service banner |

> **Exploitation tools are powerful.** Run them only against targets you are
> authorized to test. Scope enforcement and rules-of-engagement help
> ([Program Scope](program-scope.md)), but authorization is your responsibility.

---

## Web Testing

Interacting with web applications directly, without a full scanner.

| Tool | What it does |
|---|---|
| `http_request(url, method, headers, cookies, data, follow_redirects, timeout, save_to, extract_text)` | Full HTTP request — status, headers, body, redirect chain, timing |
| `html_to_text(html)` | Strip tags, return visible text |
| `extract_links(html, base_url, only_same_origin)` | Extract anchors, forms, scripts, images from HTML |
| `http_form_submit(url, form_data, method, headers, cookies, follow_redirects)` | Submit an HTML form |
| `web_crawl(url, max_depth, max_pages, include_external, timeout)` | Organic crawler — finds endpoints wordlists miss |
| `screenshot_url(url, timeout)` | Single-URL screenshot via gowitness |
| `screenshot_urls(urls, threads, timeout)` | Batch screenshots for visual triage |
| `katana_crawl(url, depth, js_crawl, concurrency, rate_limit, headless, crawl_duration)` | Next-gen crawler incl. JavaScript endpoint parsing (katana) |
| `arjun_params(url, method, threads, stable, headers, delay)` | Discover hidden HTTP parameters on an endpoint |
| `linkfinder_extract(input_url, domain_mode, regex, cookies, timeout)` | Extract endpoints/links from JavaScript files (LinkFinder) |

---

## Analysis & Reporting

Turning findings into decisions and deliverables.

| Tool | What it does |
|---|---|
| `analyze_findings(host, min_severity, min_confidence, max_items)` | AI triage: attack paths, quick wins, recommended next steps |
| `analyze_attack_chains(host, min_severity, min_confidence)` | Correlate findings into compound [attack chains](attack-chains.md) |
| `get_findings(job_id, host, min_severity, min_confidence)` | Extract normalized findings from a job |
| `generate_pentest_report(title, min_severity, min_confidence, host, save_to, format, confirmed_only)` | Full report: exec summary + chains + findings + remediation (Markdown or standalone HTML) |
| `generate_report(job_ids, title, format)` | Quick report from specific job IDs |
| `list_completed_jobs(tool_filter)` | List finished jobs, optionally filtered |
| `parse_nmap_output(job_id)` | Structured nmap XML parsing |
| `parse_nuclei_output(findings_file)` | Structured Nuclei JSONL parsing |
| `pcap_extract(pcap_path)` | Extract credentials/key data from a PCAP |
| `pcap_protocols(pcap_path)` | Protocol hierarchy + conversations in a PCAP |
| `tshark_query(pcap_path, display_filter, fields, max_lines)` | Arbitrary tshark filter queries |
| `read_file(path, max_bytes, offset, as_hex, as_base64)` | Safe file reading with magic-byte type detection |
| `list_artifacts()` | List everything in the artifacts directory |

---

## Engagement & Triage

Managing a professional test session end to end. See [Engagements](engagements.md).

| Tool | What it does |
|---|---|
| `engagement_start(name, scope, client, notes)` | Start an engagement — sets scope automatically |
| `engagement_status()` | Active engagement + findings summary |
| `engagement_findings(min_severity, host, limit)` | All findings for the current engagement |
| `engagement_end()` | Close the engagement, clear scope |
| `engagement_list()` | All engagements, past and active |
| `list_unconfirmed_findings(host, min_severity)` | Findings awaiting manual validation |
| `update_finding_status(finding_id, status)` | Mark `confirmed` / `false_positive` / `unconfirmed` |

### Credential Vault

Discovered credentials, encrypted at rest with Fernet. See [Security Model](security.md).

| Tool | What it does |
|---|---|
| `creds_store(host, username, password, hash, service, port, source_tool, notes)` | Store a credential (encrypted) |
| `creds_list(host, service)` | List credentials with decrypted secrets |
| `creds_use(host, service)` | Best credential to try for a host/service |
| `creds_delete(cred_id)` | Remove a credential |

### Health

| Tool | What it does |
|---|---|
| `server_health()` | Preflight: binaries, Python deps, wordlists |
| `check_binary(name)` | Check whether one binary is installed and where |

---

## Program Scope

Named authorization boundaries with in/out-of-scope rules. See [Program Scope & Policy](program-scope.md).

| Tool | What it does |
|---|---|
| `program_scope_start(name, in_scope, out_of_scope, client, rules, approvers)` | Create/activate a program; sets allowlist + denylist |
| `program_scope_status()` | Show the active program |
| `program_scope_list()` | List all programs |
| `program_scope_end()` | Close the program and clear scope |
| `program_scope_add_targets(targets)` | Add targets to in-scope |
| `program_scope_remove_targets(targets)` | Remove targets from in-scope |
| `program_scope_out_of_scope(targets)` | Add targets to the out-of-scope (deny) list |
| `program_scope_allow(target)` | Explicitly allow one target |
| `program_scope_deny(target)` | Explicitly deny one target (blocked even if in-scope) |

---

## Asset Inventory & Continuous Recon

A persistent, project-wide database of everything discovered, plus change
detection across recon cycles. See [Asset Inventory](asset-inventory.md) and
[Continuous Recon](continuous-recon.md).

| Tool | What it does |
|---|---|
| `asset_list_hosts(status, min_scan_count, limit)` | List known hosts |
| `asset_get_host(host_ip)` | Full detail for one host: services + vulnerabilities |
| `asset_list_services(host_ip, service_name, min_port, max_port)` | List discovered services |
| `asset_list_vulnerabilities(host_ip, min_severity, status, limit)` | List vulnerabilities, filterable |
| `asset_search(query)` | Search assets by IP, hostname, service, or CVE |
| `asset_mark_host(host_ip, status)` | Set a host status (new/scanned/confirmed/remediated/false_positive) |
| `asset_mark_vuln(vuln_id, status)` | Set a vulnerability status |
| `asset_list_runs(program, limit)` | List recorded scan runs (recon cycles) |
| `asset_diff_runs(prev_run_id, curr_run_id)` | Compare two runs — new/disappeared/changed assets |
| `asset_latest_changes(program)` | What changed between the two most recent runs |
| `recon_sweep(domain, program, tools, tool_budget)` | Passive recon sweep with change detection |

---

## Scope Management

Low-level scope controls. Most of the time you'll use [engagements](engagements.md)
or [programs](program-scope.md), which manage scope for you.

| Tool | What it does |
|---|---|
| `scope_list()` | Show current scope (empty = lab mode) |
| `scope_add(target)` | Add an IP, CIDR, domain, or wildcard |
| `scope_set(targets)` | Replace the entire scope |
| `scope_remove(target)` | Remove one target |
| `scope_clear()` | Reset to lab mode (all targets allowed) |

---

## Job Management

Long-running scans run asynchronously as jobs.

| Tool | What it does |
|---|---|
| `get_job_status(job_id)` | Status and result of an async job |
| `get_job_output(job_id, tail)` | Partial output from a running/completed job |
| `list_jobs(limit)` | Recent jobs with status and retry counts |
| `cancel_job(job_id)` | Kill a running job and its process group |

---

See also: [Workflows](workflows.md) for the high-level `scan_host` / `scan_web`
parallel workflows and the built-in MCP prompt templates.
