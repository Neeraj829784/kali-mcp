"""
Tests for the 4 missing-item fixes:
  Fix 1 — nmap_os_detection and msf_run_module extractors
  Fix 2 — workflow.py crawler except annotated (structural check)
  Fix 3 — masscan rate configurable via MASSCAN_RATE
  Fix 4 — nmap target input validation (_validate_targets)
"""
import pytest
from findings import extract_findings


# ── Fix 1a: nmap_os_detection extractor ──────────────────────────────────────

def test_nmap_os_detection_os_details():
    """OS details line must produce a high-confidence finding."""
    output = (
        "Starting Nmap 7.94\n"
        "OS details: Linux 5.15 - 5.19\n"
        "Network Distance: 1 hop\n"
    )
    results = extract_findings("nmap_os_detection", output, "10.0.0.1")
    assert len(results) >= 1
    titles = [r["title"] for r in results]
    assert any("Linux 5.15" in t for t in titles)
    os_finding = next(r for r in results if "Linux 5.15" in r["title"])
    assert os_finding["confidence"] == "high"
    assert os_finding["tool"] == "nmap_os_detection"
    assert os_finding["severity"] == "info"


def test_nmap_os_detection_aggressive_guess():
    """Aggressive OS guess must fall back to medium confidence."""
    output = (
        "Aggressive OS guesses: Linux 4.15 (96%), Linux 5.0 (92%)\n"
        "No exact OS matches for host\n"
    )
    results = extract_findings("nmap_os_detection", output, "10.0.0.2")
    assert len(results) >= 1
    guess = results[0]
    assert "Linux 4.15" in guess["title"]
    assert guess["confidence"] == "medium"


def test_nmap_os_detection_running_line():
    """'Running:' line must produce a finding when no details are present."""
    output = "Running: Linux 5.X\n"
    results = extract_findings("nmap_os_detection", output, "10.0.0.3")
    assert len(results) >= 1
    assert any("Linux 5.X" in r["title"] for r in results)


def test_nmap_os_detection_no_match_returns_empty():
    """Output with no OS information must return empty findings."""
    output = "Host is up.\n80/tcp open http\n"
    results = extract_findings("nmap_os_detection", output, "10.0.0.4")
    assert results == []


# ── Fix 1b: msf_run_module extractor ─────────────────────────────────────────

def test_msf_run_module_session_opened():
    """Meterpreter session opened must produce a CRITICAL finding."""
    output = (
        "[*] Started reverse TCP handler on 10.0.0.10:4444\n"
        "[*] Sending stage (200262 bytes) to 10.0.0.1\n"
        "Meterpreter session 1 opened (10.0.0.10:4444 -> 10.0.0.1:49234)\n"
        "[*] Session ID 1 created in background\n"
    )
    results = extract_findings("msf_run_module", output, "10.0.0.1")
    assert len(results) >= 1
    session = next(r for r in results if r["severity"] == "critical")
    assert "session" in session["title"].lower()
    assert session["confidence"] == "high"
    assert session["tool"] == "msf_run_module"


def test_msf_run_module_shell_session():
    """Command shell session must also produce a CRITICAL finding."""
    output = "Command shell session 2 opened (10.0.0.10:4444 -> 10.0.0.2:50000)\n"
    results = extract_findings("msf_run_module", output, "10.0.0.2")
    critical = [r for r in results if r["severity"] == "critical"]
    assert len(critical) >= 1


def test_msf_run_module_plus_line():
    """[+] success lines must produce HIGH findings."""
    output = (
        "[+] 10.0.0.1:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n"
        "[+] 10.0.0.1:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-\n"
        "[+] Target is vulnerable!\n"
    )
    results = extract_findings("msf_run_module", output, "10.0.0.1")
    high = [r for r in results if r["severity"] == "high"]
    assert len(high) >= 1


def test_msf_run_module_no_output_returns_empty():
    """Module output with only info lines must return empty or low-signal findings."""
    output = (
        "[*] Reloading module cache in the background...\n"
        "[*] No session was created.\n"
    )
    results = extract_findings("msf_run_module", output, "10.0.0.1")
    critical = [r for r in results if r["severity"] == "critical"]
    assert len(critical) == 0


def test_msf_run_module_loot():
    """Loot capture line must produce a HIGH finding."""
    output = "Loot: stored as /root/.msf4/loot/20240101_loot.txt path: /etc/passwd\n"
    results = extract_findings("msf_run_module", output, "10.0.0.1")
    loot = [r for r in results if "loot" in r["title"].lower()]
    assert len(loot) >= 1
    assert loot[0]["severity"] == "high"


# ── Fix 2: crawler except pass annotation (structural) ───────────────────────

def test_crawler_except_pass_is_annotated():
    """The crawler's per-URL except:pass must have an explanatory comment."""
    source = open("workflow.py").read()
    # Find the except block in _crawl_simple
    idx = source.find("_crawl_simple")
    assert idx != -1
    crawler_section = source[idx:]
    # The pass should be followed by a comment explaining it's intentional
    assert "pass  # per-URL errors" in crawler_section or \
           "pass  #" in crawler_section, \
        "Crawler's except:pass should be annotated with a comment"


# ── Fix 3: masscan rate configurable ─────────────────────────────────────────

def test_masscan_rate_in_config():
    """MASSCAN_RATE must be defined in config with all three intensity levels."""
    from config import MASSCAN_RATE
    assert "light" in MASSCAN_RATE
    assert "normal" in MASSCAN_RATE
    assert "deep" in MASSCAN_RATE
    # Safety: light must be <= normal <= deep
    assert MASSCAN_RATE["light"] <= MASSCAN_RATE["normal"] <= MASSCAN_RATE["deep"]
    # Sanity bounds
    assert MASSCAN_RATE["light"] >= 100
    assert MASSCAN_RATE["deep"] <= 50000


def test_masscan_rate_used_in_workflow():
    """workflow.py must import MASSCAN_RATE from config (not hardcode 10000)."""
    source = open("workflow.py").read()
    assert "MASSCAN_RATE" in source, "workflow.py must use MASSCAN_RATE from config"
    assert '"10000"' not in source and "'10000'" not in source, \
        "hardcoded '10000' masscan rate should be removed in favour of MASSCAN_RATE"


def test_masscan_in_rate_limits():
    """masscan should be documented in RATE_LIMITS for consistency."""
    from config import RATE_LIMITS
    assert "masscan" in RATE_LIMITS, \
        "masscan should appear in RATE_LIMITS for documentation even if handled separately"


# ── Fix 4: nmap target input validation ──────────────────────────────────────

def test_validate_targets_valid_ip():
    from tools.reconnaissance.nmap import _validate_targets
    tokens = _validate_targets("10.0.0.1")
    assert tokens == ["10.0.0.1"]


def test_validate_targets_valid_cidr():
    from tools.reconnaissance.nmap import _validate_targets
    tokens = _validate_targets("192.168.1.0/24")
    assert tokens == ["192.168.1.0/24"]


def test_validate_targets_valid_range():
    from tools.reconnaissance.nmap import _validate_targets
    tokens = _validate_targets("10.0.0.1-10")
    assert tokens == ["10.0.0.1-10"]


def test_validate_targets_valid_hostname():
    from tools.reconnaissance.nmap import _validate_targets
    tokens = _validate_targets("target.example.com")
    assert tokens == ["target.example.com"]


def test_validate_targets_multiple():
    from tools.reconnaissance.nmap import _validate_targets
    tokens = _validate_targets("10.0.0.1 10.0.0.2")
    assert tokens == ["10.0.0.1", "10.0.0.2"]


def test_validate_targets_blocks_flag_injection():
    """--script=evil injected as a target token must raise ValueError."""
    from tools.reconnaissance.nmap import _validate_targets
    with pytest.raises(ValueError, match="Invalid target"):
        _validate_targets("--script=evil")


def test_validate_targets_blocks_semicolon():
    """Semicolon injection attempt must raise ValueError."""
    from tools.reconnaissance.nmap import _validate_targets
    with pytest.raises(ValueError, match="Invalid target"):
        _validate_targets("10.0.0.1;id")


def test_validate_targets_blocks_space_injection():
    """Newline-embedded injection must raise ValueError."""
    from tools.reconnaissance.nmap import _validate_targets
    with pytest.raises(ValueError, match="Invalid target"):
        _validate_targets("10.0.0.1\n--script=evil")


def test_validate_targets_empty_raises():
    """Empty targets string must raise ValueError."""
    from tools.reconnaissance.nmap import _validate_targets
    with pytest.raises(ValueError, match="must not be empty"):
        _validate_targets("")


def test_validate_targets_blocks_path():
    """Path-like input must raise ValueError."""
    from tools.reconnaissance.nmap import _validate_targets
    with pytest.raises(ValueError, match="Invalid target"):
        _validate_targets("/etc/passwd")
