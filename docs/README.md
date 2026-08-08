# kali-mcp Documentation

Welcome. This is the complete documentation for **kali-mcp** — an AI-powered
penetration testing platform that turns 27+ Kali Linux security tools into 119
structured, AI-callable actions.

New here? Read the pages in order. Already set up? Jump to whatever you need.

## Getting started

1. [Installation](installation.md) — install the server and the security tools it drives
2. [Configuration](configuration.md) — connect an AI client, environment variables, tunables
3. [Workflows](workflows.md) — your first scan, and the built-in parallel workflows

## Core concepts

- [The Finding Pipeline](finding-pipeline.md) — how raw tool output becomes structured findings
- [False-Positive Reduction](false-positive-reduction.md) — why the findings you see can be trusted
- [Attack Chain Engine](attack-chains.md) — how small findings combine into real impact
- [Engagements](engagements.md) — the professional pentest workflow, start to report

## Managing scope & assets

- [Program Scope & Policy](program-scope.md) — named programs, in/out-of-scope rules, rules of engagement
- [Asset Inventory](asset-inventory.md) — a persistent, project-wide database of everything you find
- [Continuous Recon](continuous-recon.md) — scheduled passive recon with change detection

## Reference

- [Tool Reference](tools.md) — all 119 tools, grouped by phase, with parameters
- [Security Model](security.md) — scope enforcement, input validation, the credential vault, secrets
- [Deployment](deployment.md) — running as a service, the data directory
- [Testing](testing.md) — running the test suite and what it covers

---

## What is kali-mcp, in one paragraph?

kali-mcp is an [MCP](https://modelcontextprotocol.io) server. An AI assistant
(Claude, Kiro, or any MCP-compatible client) connects to it and gains the
ability to run real security tools — nmap, nuclei, sqlmap, hydra, and more.
Crucially, the AI never has to read raw terminal output: every result is parsed
into structured **findings**, deduplicated across tools, verified to cut false
positives, correlated into attack chains, and stored in a persistent asset
inventory. The AI becomes a hands-on pentest partner; you stay in control of
scope and decisions.

## A note on terminology

- **Finding** — a single structured result (an open port, a vulnerability, a
  discovered path). Every finding has a `severity`, a `confidence`, and
  `evidence`.
- **Tool** — an AI-callable action (e.g. `nmap_port_scan`). 119 are available.
- **Engagement** — a named test session that groups scope, findings, and credentials.
- **Program** — a named authorization boundary (in-scope / out-of-scope rules).
- **Scan run** — one recon cycle, recorded so later runs can be diffed for changes.
