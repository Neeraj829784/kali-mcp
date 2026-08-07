# Workflows

A "workflow" is a single action that orchestrates many tools for you. Instead of
running nmap, then nikto, then gobuster, then nuclei one at a time, you call one
tool and kali-mcp fans them out in parallel and consolidates the results.

There are two built-in parallel workflows (`scan_host`, `scan_web`) and three
guided prompt templates. This page also shows how a first scan looks end to end.

## Your first scan

Talk to your AI client in plain language. Behind the scenes it calls tools:

```
You:  "Scan 10.10.10.5 for anything interesting."

AI:   → scan_host(target="10.10.10.5", intensity="normal")
      → Finds open ports 22, 80, 445
      → Runs nikto + gobuster + nuclei + enum4linux in parallel
      → Extracts 14 findings, boosts confidence on corroborated ones
      → Identifies a chain: "Exposed .git + Admin Panel → Credential Leak"
      → Suggests: hydra on SSH, sqlmap on the login form
```

You never memorize tool names or flags — you describe intent.

## `scan_host` — parallel host scan

Fires tools simultaneously based on which services are detected. Roughly 70%
faster than running them one after another.

```
scan_host(target="10.10.10.5", intensity="normal")

Phase 1:  nmap port scan (runs first)
              │  detects open services
              ▼
Phase 2:  [all in parallel]
          Web open  → nikto + gobuster + nuclei
          SMB open  → enum4linux + nmap SMB vuln scripts
          SSH open  → service-version banner grab
```

### Intensity levels

| Level | Ports | Timing | Phase-1 method | Rough time |
|---|---|---|---|---|
| `light` | top 100 | T5 | nmap | ~1 min |
| `normal` | 1–10000 | T4 | nmap | ~5 min |
| `deep` | 1–65535 | T3 | masscan → nmap | ~15 min |

> `deep` uses **masscan** for fast port discovery (at a configurable
> packets-per-second rate), then runs targeted nmap `-sV` only on the ports
> masscan found open. If masscan isn't installed, it falls back to nmap alone.

## `scan_web` — parallel web scan

```
scan_web(url="http://10.10.10.5", depth="normal")

Runs simultaneously:  nikto, gobuster, nuclei, and an organic web crawler
After crawling:       gowitness screenshots of interesting URLs
Returns:              consolidated findings from every scanner + screenshot paths
```

`depth` accepts `light`, `normal`, or `deep` (deep adds ffuf fuzzing and a wider crawl).

## MCP prompt templates

Prompts are ready-made, step-by-step plans the AI can follow. Your client
surfaces them as reusable commands.

**`recon_domain(domain)`** — full domain reconnaissance
```
whois → dig (A/NS/MX/TXT) → subfinder → theharvester → amass → report
```

**`web_pentest(url)`** — web application test
```
nmap → nikto → gobuster → gobuster_vhost → ffuf → nuclei
→ wpscan (if WordPress) → sqlmap (if login forms) → report
```

**`smb_enum(target)`** — Windows/Samba enumeration
```
nmap (135/139/445) → smbclient (anonymous) → enum4linux → nmap SMB vuln scripts
```

**`reporting_rules()`** — not a scan, but a set of rules the AI follows when
reporting, so it never inflates or invents findings. See
[False-Positive Reduction](false-positive-reduction.md).

## Where results go

Every scan's output is parsed into structured findings automatically — see
[The Finding Pipeline](finding-pipeline.md). If an [engagement](engagements.md)
is active, findings are tagged to it; either way they feed the
[Asset Inventory](asset-inventory.md).

## Next steps

- [The Finding Pipeline](finding-pipeline.md) — what happens to scan output
- [Engagements](engagements.md) — group a whole test session and produce a report
