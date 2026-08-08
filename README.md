<div align="center">

# 🐉 kali-mcp

### Your AI, holding a full Kali Linux toolkit.

**kali-mcp turns any MCP-compatible AI assistant into a hands-on penetration
testing partner** — it drives 27+ real Kali security tools through 123
AI-callable actions, and hands the AI clean, verified, structured findings
instead of raw terminal noise.

[![Tests](https://github.com/Neeraj829784/kali-mcp/actions/workflows/test.yml/badge.svg)](https://github.com/Neeraj829784/kali-mcp/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**123 MCP tools · 27+ Kali binaries · autonomous hunt mode · verification oracles + interactsh OOB + IDOR/access-control + race & secrets scanners · 7 attack-chain templates · ~450 tests**

[Quick Start](#-quick-start) · [Documentation](docs/README.md) · [Tool Reference](docs/tools.md)

</div>

---

```
You:  "Scan 10.10.10.5 and tell me what's worth attacking."

AI:   → scan_host("10.10.10.5")
      → open ports 22, 80, 445 — fans out nikto + gobuster + nuclei + enum4linux in parallel
      → 14 findings extracted, verified, and deduplicated
      → attack chain found:  Exposed .git  →  leaked creds  →  Admin Panel
      → next moves suggested:  hydra on SSH, sqlmap on the login form
```

You describe intent. The AI drives the tools. kali-mcp makes the results
trustworthy.

## ✨ Why kali-mcp

- **🧠 Structured, not raw.** Every scan result becomes a clean *finding*
  (`host`, `severity`, `confidence`, `evidence`) — never a wall of terminal text.
  → [The Finding Pipeline](docs/finding-pipeline.md)
- **🎯 Low false positives.** Findings are actively re-verified (soft-404
  baselines, catch-all clustering, `.git`/`.env` content proof), evidence-anchored,
  and cross-tool corroborated. The AI can't inflate what the tools didn't prove.
  → [False-Positive Reduction](docs/false-positive-reduction.md)
- **🔗 Impact, not just bugs.** Individual findings are correlated into named
  attack chains with ready-to-paste narratives. → [Attack Chains](docs/attack-chains.md)
- **🛰️ Change detection.** Passive recon sweeps diff against previous runs and
  surface *newly exposed* assets — where the bounties are.
  → [Continuous Recon](docs/continuous-recon.md)
- **🗂️ Memory.** A persistent asset inventory and full engagement lifecycle,
  from scope to client-ready report. → [Engagements](docs/engagements.md)
- **🔒 Safety-first.** stdio-only (no exposed network), scope allow/deny
  enforcement, argument-injection guards, an encrypted credential vault, and a
  full audit log. → [Security Model](docs/security.md)

## 🚀 Quick Start

```bash
# 1. Clone & install
git clone https://github.com/Neeraj829784/kali-mcp.git
cd kali-mcp
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 2. Verify
python3 -c "from server import mcp; print('Ready')"
```

Then point your AI client at it:

```json
{
  "mcpServers": {
    "kali-mcp": {
      "command": "/path/to/kali-mcp/.venv/bin/python",
      "args": ["/path/to/kali-mcp/server.py"]
    }
  }
}
```

Ask it to run `server_health()` to confirm the tools are installed, then
`scan_host("<your-authorized-target>")`.

Full setup — including the security tools kali-mcp drives — is in the
**[Installation guide](docs/installation.md)**.

## 📚 Documentation

Everything lives in **[`docs/`](docs/README.md)**:

| Start here | Concepts | Scope & assets | Reference |
|---|---|---|---|
| [Installation](docs/installation.md) | [Finding Pipeline](docs/finding-pipeline.md) | [Program Scope](docs/program-scope.md) | [Tool Reference](docs/tools.md) |
| [Configuration](docs/configuration.md) | [False-Positive Reduction](docs/false-positive-reduction.md) | [Asset Inventory](docs/asset-inventory.md) | [Security Model](docs/security.md) |
| [Workflows](docs/workflows.md) | [Attack Chains](docs/attack-chains.md) | [Continuous Recon](docs/continuous-recon.md) | [Deployment](docs/deployment.md) |
| [Engagements](docs/engagements.md) | | | [Testing](docs/testing.md) |

## ⚖️ Responsible use

kali-mcp runs real offensive tooling. **Only test systems you own or are
explicitly authorized to test.** Use [programs](docs/program-scope.md) to encode
your authorization boundary and stay inside it. You are responsible for how you
use this tool.

## 📄 License

MIT — see [LICENSE](LICENSE).
