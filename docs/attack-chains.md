# Attack Chain Engine

A single finding is rarely the whole story. The real risk in a pentest is how
several smaller issues *combine* — an exposed config file leaks a credential,
which unlocks an admin panel, which allows code execution. The attack chain
engine turns a flat list of findings into these compound-impact narratives.

## The idea

Individually, "exposed `.git`" and "admin login page found" might each be
medium severity. Together they tell a story: *the leaked repo contains
credentials that log into the admin panel*. The chain engine detects these
combinations and escalates the combined severity accordingly.

## How signals work

The engine looks for **signals** in your findings — things like `sqli`, `creds`,
`ssh_open`, `admin_panel`, `info_disclosure`. Each signal is confidence-weighted
to avoid false chains:

- **Authoritative tool match** (e.g. hydra for credentials, sqlmap for SQLi) →
  the signal always fires, regardless of confidence.
- **Keyword match + medium/high confidence** → fires (a scanner confirmed it).
- **Keyword match + low confidence** → does **not** fire.

That last rule is important: it stops a low-confidence nikto line like "password
field detected" from triggering a bogus credential-theft chain in your report.

## The chain templates

A chain is reported only when **all** of its required signals are present.

| Chain | Requires | Severity escalation |
|---|---|---|
| SQL Injection → Credential Theft → System Access | `sqli` + `ssh_open` | +1 |
| Exposed Sensitive File → Authenticated Access | `info_disclosure` + `admin_panel` | +2 |
| Admin Panel + Weak Credentials → Privileged Access | `admin_panel` + `creds` | +1 |
| Recovered Credentials → Lateral Movement | `creds` + `ssh_open` | +1 |
| Unauthenticated SMB RCE (EternalBlue class) | `smb_vuln` | +0 (already critical) |
| File Upload → Remote Code Execution | `admin_panel` + `file_upload` | +2 |
| Outdated Service + Public Exploit → Compromise | `open_port` + `exploit_available` | +1 |

## What a chain contains

Each detected chain includes:

- **name** — the chain's title
- **severity** — the escalated, combined severity (the compound impact)
- **narrative** — a human-readable explanation, ready to paste into a report
- **steps** — the contributing findings, in order, with their host and tool
- **hosts** — every affected host

## Using it

```
analyze_attack_chains()                       # correlate all current findings
analyze_attack_chains(host="10.10.10.5")      # focus on one host
analyze_attack_chains(min_confidence="medium")# only well-supported findings
```

Chains also appear automatically in the full report from
`generate_pentest_report()`.

## Design note

The engine is built from pure functions — no I/O, no tool calls — so it's fully
deterministic and unit-tested. Feeding it the same findings always produces the
same chains.

## Next steps

- [Engagements](engagements.md) — where chains show up in a report
- [False-Positive Reduction](false-positive-reduction.md) — why the input findings are trustworthy
