#!/usr/bin/env bash
# kali-mcp installer — works on Kali Linux, Debian, and Ubuntu.
# Usage: curl -fsSL https://raw.githubusercontent.com/Neeraj829784/kali-mcp/main/install.sh | bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*"; exit 1; }

# ── Checks ────────────────────────────────────────────────────────────────────
[[ "$EUID" -ne 0 ]] && error "Run as root: sudo bash install.sh"
command -v apt-get &>/dev/null || error "apt-get not found. This script requires Debian/Ubuntu/Kali."

INSTALL_DIR="${INSTALL_DIR:-/opt/kali-mcp}"
PYTHON="${PYTHON:-python3}"

info "Installing kali-mcp to $INSTALL_DIR"

# ── System packages ───────────────────────────────────────────────────────────
info "Updating package lists..."
apt-get update -qq

info "Installing system dependencies..."
# Core tools — must succeed
apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv git curl \
    nmap nikto gobuster ffuf hydra sqlmap \
    netcat-openbsd whois dnsutils

# Optional tools — warn if unavailable (may not be in all repo mirrors)
for tool_pkg in nuclei wpscan enum4linux smbclient amass subfinder theharvester tshark wordlists; do
    apt-get install -y --no-install-recommends "$tool_pkg" 2>/dev/null || \
        warn "$tool_pkg not available in apt — install manually if needed"
done

# seclists and exploitdb are optional — don't fail if unavailable
apt-get install -y --no-install-recommends seclists exploitdb 2>/dev/null || \
    warn "seclists/exploitdb not available in this repo — install manually if needed"

# gowitness: try apt, fall back to go install
if ! command -v gowitness &>/dev/null; then
    apt-get install -y --no-install-recommends gowitness 2>/dev/null || \
        warn "gowitness not available via apt — install manually: go install github.com/sensepost/gowitness@latest"
fi

# metasploit: optional, large download — skip if not on Kali
if apt-cache show metasploit-framework &>/dev/null 2>&1; then
    info "Installing Metasploit Framework (this may take a while)..."
    apt-get install -y --no-install-recommends metasploit-framework 2>/dev/null || \
        warn "Metasploit install failed — run: apt install metasploit-framework"
else
    warn "Metasploit not in apt sources — skipping. Add Kali repos or install manually."
fi

# ── Clone or update repo ──────────────────────────────────────────────────────
if [[ -d "$INSTALL_DIR/.git" ]]; then
    info "Updating existing installation..."
    if ! git -C "$INSTALL_DIR" pull --rebase --autostash; then
        error "git pull failed. Check for local changes: git -C $INSTALL_DIR status"
    fi
else
    info "Cloning kali-mcp..."
    git clone --quiet https://github.com/Neeraj829784/kali-mcp.git "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

# ── Python virtualenv + deps ──────────────────────────────────────────────────
info "Setting up Python environment..."
$PYTHON -m venv venv
venv/bin/pip install --quiet --upgrade pip
venv/bin/pip install --quiet -e "."

# ── Verify installation ───────────────────────────────────────────────────────
info "Verifying installation..."
MISSING=()
for tool in nmap nikto gobuster ffuf hydra sqlmap nuclei wpscan enum4linux smbclient amass subfinder theharvester whois nc tshark; do
    command -v "$tool" &>/dev/null || MISSING+=("$tool")
done

# Verify Python package installed in venv
if ! venv/bin/python -c "import mcp" 2>/dev/null; then
    warn "kali-mcp Python dependencies not properly installed — try: venv/bin/pip install -e ."
fi

if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn "Some tools not found: ${MISSING[*]}"
    warn "Run: apt install ${MISSING[*]}"
else
    info "All core tools verified."
fi

# ── Claude Desktop config hint ────────────────────────────────────────────────
echo ""
info "kali-mcp installed successfully at $INSTALL_DIR"
echo ""
echo "  Add to Claude Desktop config (~/.config/Claude/claude_desktop_config.json):"
echo '  {'
echo '    "mcpServers": {'
echo '      "kali-mcp": {'
echo "        \"command\": \"$INSTALL_DIR/venv/bin/python\","
echo "        \"args\": [\"$INSTALL_DIR/server.py\"]"
echo '      }'
echo '    }'
echo '  }'
echo ""
echo "  Or run directly: $INSTALL_DIR/venv/bin/python $INSTALL_DIR/server.py"
echo ""
info "Done. Use responsibly — authorized targets only."
