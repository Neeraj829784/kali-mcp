# Configuration

This page covers three things: connecting an AI client to kali-mcp, the
environment variables you can set, and the tunable parameters in `config.py`.

## Connecting an AI client

kali-mcp speaks the [Model Context Protocol](https://modelcontextprotocol.io)
over **stdio** — the AI client launches the server as a child process and talks
to it over standard input/output. There is no network port and no login; access
is bounded by who can run the process. (This is a deliberate security choice —
see [Security Model](security.md).)

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
or the equivalent on your platform:

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

### Kiro / other MCP clients

Point the client at `server.py` using the virtual environment's Python
interpreter. The pattern is always the same: `command` = the venv Python,
`args` = the path to `server.py`.

## Environment variables

All are optional. Set them in your shell, your MCP client config's `env` block,
or the systemd unit (see [Deployment](deployment.md)).

| Variable | Default | Purpose |
|---|---|---|
| `KALI_MCP_DATA_DIR` | project directory | Where all writable state lives — databases, credential vault + key, artifacts, audit log, scope file. Set this to keep runtime data separate from the code (recommended). See [below](#the-data-directory). |
| `KALI_MCP_VAULT_KEY` | read from `vault.key` | Credential-vault encryption key. Prefer setting this from a secret manager over the on-disk key file. |
| `KALI_MCP_WEBHOOK_URL` | `""` (disabled) | HTTP endpoint for finding alerts (Slack/Discord/Teams/custom). |
| `KALI_MCP_WEBHOOK_MIN_SEVERITY` | `critical` | Minimum severity that triggers a webhook. |
| `KALI_MCP_TLS_VERIFY` | `0` (off) | Enforce TLS certificate validation in the built-in HTTP helpers. Off by default because pentest targets often use self-signed/expired certs. |
| `KALI_MCP_MAX_CONCURRENT_TOOLS` | `8` | Global cap on simultaneously-running tool subprocesses. |
| `KALI_MCP_TRANSPORT` | `stdio` | Transport. Only `stdio` is supported/safe; other values are refused unless you also set the override below. |
| `KALI_MCP_INSECURE_ALLOW_NETWORK` | unset | Escape hatch to allow a network transport. **Dangerous** — exposes unauthenticated command execution. Do not use outside an isolated lab. |

### The data directory

By default, kali-mcp writes all runtime state next to the code. Setting
`KALI_MCP_DATA_DIR` moves it all to one folder:

```bash
export KALI_MCP_DATA_DIR=/var/lib/kali-mcp
```

Everything below then lives under that directory:

```
jobs.db          engagements.db   programs.db      vault.db
vault.key        scope.txt        known_hosts      audit.log
artifacts/
```

Why this matters:

- **Clean separation** of code and data.
- **Back up or migrate** an entire engagement history by copying one folder.
- **Privacy** — the directory is created with `0700` permissions (owner-only).

The default (unset) keeps the old behaviour, so existing setups are unaffected.

## Tunable parameters (`config.py`)

Timeouts, rate limits, and wordlist locations live in `config.py`.

### Per-tool timeouts (seconds)

```python
TOOL_TIMEOUTS = {
    "nmap_port_scan":  1800,   # 30 min for a full port range
    "sqlmap":          2400,   # 40 min for deep injection testing
    "hydra":           1800,   # 30 min brute-force
    "nuclei":           900,
    "default":          120,
}
```

### Per-tool rate limits (requests/sec, `0` = unlimited)

```python
RATE_LIMITS = {
    "nuclei":       150,
    "ffuf":          40,
    "gobuster_dir":  10,
    "hydra":         16,
    "masscan":     5000,   # packets/sec — handled separately
}
```

### masscan packets-per-second by intensity

```python
MASSCAN_RATE = {
    "light":   1000,   # stealthy — VPN/remote targets
    "normal":  5000,   # balanced default
    "deep":   10000,   # fast — LAN only
}
```

### Wordlists

`config.py` lists fallback wordlist locations and resolves the first that exists,
so scans work whether you're on Kali (`/usr/share/wordlists/...`) or a system
with `seclists` installed elsewhere.

## Next steps

- [Workflows](workflows.md) — run your first scan
- [Deployment](deployment.md) — run kali-mcp as a service
