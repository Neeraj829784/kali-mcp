# Installation

This guide gets kali-mcp installed along with the security tools it drives.
kali-mcp is designed for **Kali Linux**, but it works on any Debian/Ubuntu
system where the underlying tools are available.

## Requirements

- **Python 3.11 or newer**
- A Linux host (Kali recommended — the tools and wordlists are pre-packaged there)
- The security tools you want to use (see below — missing tools degrade gracefully)

## 1. Get the code

```bash
git clone https://github.com/Neeraj829784/kali-mcp.git
cd kali-mcp
```

## 2. Create a virtual environment

Keeping dependencies in a virtual environment avoids conflicts with system Python.

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 3. Install the Python package

```bash
pip install -e ".[dev]"
```

The `[dev]` extra adds the test tooling (pytest). Omit it for a runtime-only install.

## 4. Verify it imports

```bash
python3 -c "from server import mcp; print('Ready')"
```

If that prints `Ready`, the server is installed correctly.

## 5. Install the security tools

kali-mcp shells out to real tools. On Kali/Debian/Ubuntu, install them all at once:

```bash
sudo apt install -y nmap gobuster nikto ffuf hydra sqlmap \
  subfinder amass theharvester wpscan enum4linux smbclient \
  searchsploit netcat-openbsd whois dnsutils tshark \
  metasploit-framework masscan seclists
```

`gowitness` (used for screenshots) is a Go tool, installed separately:

```bash
go install github.com/sensepost/gowitness@latest
```

### Minimum set

You don't need everything to start. This subset covers most workflows; anything
missing simply reports "tool not found" with an install hint when you try to use it:

```bash
sudo apt install -y nmap gobuster nikto nuclei ffuf hydra sqlmap
```

### One-command installer

On Kali/Debian/Ubuntu you can run the bundled installer, which sets up the venv
and installs tools for you:

```bash
curl -fsSL https://raw.githubusercontent.com/Neeraj829784/kali-mcp/main/install.sh | sudo bash
```

## 6. Preflight check

Once connected to an AI client (see [Configuration](configuration.md)), ask it to run:

```
server_health()
```

This verifies every binary, Python dependency, and wordlist so you find gaps
*before* a scan, not during one. You can also check a single tool:

```
check_binary("nmap")
```

## Next steps

- [Configuration](configuration.md) — connect your AI client and set environment variables
- [Workflows](workflows.md) — run your first scan
