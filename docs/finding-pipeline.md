# The Finding Pipeline

This is the heart of kali-mcp and the thing that sets it apart from simply
running tools by hand. **Raw tool output never reaches the AI.** Every result is
transformed into clean, structured, trustworthy data first.

## Why this exists

If you hand an AI the raw text dump of an nmap or nikto scan, three bad things happen:

1. It wastes context re-parsing noisy text every time.
2. It hallucinates — inventing or misreading findings.
3. It has no memory across tools — the same issue found by two scanners looks like two problems.

The pipeline solves all three by producing **findings**: small structured records
with a fixed shape.

## What a finding looks like

```json
{
  "host": "10.10.10.5",
  "port": 445,
  "service": "smb",
  "title": "SMB null session allowed",
  "severity": "medium",
  "confidence": "high",
  "evidence": "Null session enumeration succeeded",
  "tool": "enum4linux"
}
```

- **severity** — how bad it is: `info` < `low` < `medium` < `high` < `critical`
- **confidence** — how sure we are it's *real* (a separate axis from severity)
- **evidence** — the concrete proof, quoted from the tool output

## The pipeline, step by step

```
Raw tool output
     │
     ▼  1. Extraction  (per-tool parser — 21 tools)
Structured findings: {host, port, service, title, severity, confidence, evidence, tool}
     │
     ▼  2. Active verification  (web paths: gobuster/ffuf)
        • random baseline request fingerprints the "not found" response
        • soft-404s and catch-all responders are dropped
        • .git / .env exposures are content-verified
        • survivors are promoted to HIGH confidence
     │
     ▼  3. Evidence floor  (anti-hallucination)
        • a finding with no real evidence is capped at LOW confidence
     │
     ▼  4. Deduplication  (keyed on host + port + title)
        • highest severity and longest evidence kept
        • 2+ distinct tools agreeing → confidence boosted (corroboration)
     │
     ▼  5. Engagement tagging  (async DB write, if an engagement is active)
     │
     ▼  6. Asset inventory ingestion  (persistent, project-wide)
     │
     ▼  7. Webhook  (fire-and-forget alert on high/critical)
```

Steps 2 and 3 are the false-positive defenses — they have their own page:
[False-Positive Reduction](false-positive-reduction.md).

## Confidence levels

Confidence is deliberately separate from severity. A finding can be *critical if
real* but *low confidence* — the pipeline tells you which.

| Level | Meaning | Typical source |
|---|---|---|
| `high` | Actively confirmed | nmap open port, hydra valid creds, sqlmap injectable, verified `.git` exposure, MSF session |
| `medium` | Template/script matched | nuclei template, wpscan vuln, nmap NSE script |
| `low` | Pattern guess / unverified | gobuster path, nikto header line, anything with no substantive evidence |

Findings that were capped by the evidence floor carry a `confidence_capped: true`
flag so you (and the AI) know the low rating is due to missing proof.

## Extractors by tool

There are 21 per-tool extractors. A sample of what each pulls out:

| Tool | What gets extracted |
|---|---|
| `nmap` | Open ports, service versions, NSE vuln findings |
| `nmap_os_detection` | OS name/version with a confidence level |
| `nuclei` | JSONL findings with severity from template metadata |
| `nikto` | High-signal findings only (XSS, SQLi, RCE) — header noise filtered out |
| `gobuster_dir/vhost` | Discovered paths with HTTP status |
| `gobuster_dns` | Discovered subdomains |
| `sqlmap` | Injectable parameters, enumerated databases |
| `hydra` | Valid credentials with port/service |
| `searchsploit` | Matching exploits from local Exploit-DB |
| `wpscan` | Vulnerable plugins with CVSS score |
| `enum4linux` | SMB users, shares, null sessions |
| `theharvester` | Emails, subdomains with IPs |
| `subfinder` / `amass` | Discovered subdomains |
| `ssh_enum_privesc` | SUID binaries, sudo NOPASSWD, Linux capabilities |
| `msf_run_module` | Meterpreter/shell sessions (critical), loot, success lines |
| `ffuf` | Discovered endpoints |

Tools without an extractor still return their raw output — the AI is instructed
(via the `reporting_rules` prompt) to treat only structured findings as fact.

## Next steps

- [False-Positive Reduction](false-positive-reduction.md) — the verification layers in depth
- [Attack Chain Engine](attack-chains.md) — how findings combine into impact
