"""
Tests for suggest.py — auto-suggest next steps after tool completion.
Previously untested; these cover all 8 tool branches.
"""
import pytest
from suggest import suggest_next


# ── nmap branch ───────────────────────────────────────────────────────────────

def test_nmap_ssh_open_suggests_hydra():
    results = suggest_next("nmap_port_scan", "22/tcp   open  ssh OpenSSH 8.9", "10.0.0.1")
    tools = [s["tool"] for s in results]
    assert "hydra_bruteforce" in tools
    ssh_sugg = next(s for s in results if s["tool"] == "hydra_bruteforce")
    assert ssh_sugg["params"]["service"] == "ssh"
    assert ssh_sugg["params"]["target"] == "10.0.0.1"


def test_nmap_http_suggests_nikto_gobuster_nuclei():
    output = "80/tcp   open  http Apache httpd 2.4.49"
    results = suggest_next("nmap_port_scan", output, "10.0.0.1")
    tools = [s["tool"] for s in results]
    assert "nikto_scan" in tools
    assert "gobuster_dir" in tools
    assert "nuclei_scan" in tools


def test_nmap_smb_suggests_enum4linux_and_vulnscan():
    output = "445/tcp  open  microsoft-ds Windows 7 SMB"
    results = suggest_next("nmap_port_scan", output, "10.0.0.2")
    tools = [s["tool"] for s in results]
    assert "enum4linux_scan" in tools
    assert "nmap_vuln_scan" in tools


def test_nmap_mysql_suggests_hydra():
    output = "3306/tcp open  mysql MySQL 5.7"
    results = suggest_next("nmap_port_scan", output, "10.0.0.3")
    tools = [s["tool"] for s in results]
    assert "hydra_bruteforce" in tools
    mysql_sugg = next(s for s in results if s["tool"] == "hydra_bruteforce")
    assert mysql_sugg["params"]["service"] == "mysql"


def test_nmap_ftp_suggests_hydra():
    output = "21/tcp   open  ftp vsftpd 3.0.3"
    results = suggest_next("nmap_port_scan", output, "10.0.0.4")
    tools = [s["tool"] for s in results]
    assert "hydra_bruteforce" in tools
    ftp = next(s for s in results if s["tool"] == "hydra_bruteforce")
    assert ftp["params"]["service"] == "ftp"


def test_nmap_rdp_suggests_hydra():
    output = "3389/tcp open  ms-wbt-server Windows RDP"
    results = suggest_next("nmap_port_scan", output, "10.0.0.5")
    tools = [s["tool"] for s in results]
    assert "hydra_bruteforce" in tools
    rdp = next(s for s in results if s["tool"] == "hydra_bruteforce")
    assert rdp["params"]["service"] == "rdp"


def test_nmap_no_interesting_ports_returns_empty():
    output = "9999/tcp open  abyss"
    results = suggest_next("nmap_port_scan", output, "10.0.0.6")
    assert results == []


# ── gobuster/ffuf branch ──────────────────────────────────────────────────────

def test_gobuster_admin_page_suggests_http_request():
    output = "/admin (Status: 200)"
    results = suggest_next("gobuster_dir", output, "10.0.0.1")
    tools = [s["tool"] for s in results]
    assert "http_request" in tools


def test_gobuster_wordpress_suggests_wpscan():
    output = "/wp-admin (Status: 200)\n/wp-login.php (Status: 200)"
    results = suggest_next("gobuster_dir", output, "10.0.0.1")
    tools = [s["tool"] for s in results]
    assert "wpscan_scan" in tools


def test_gobuster_php_pages_suggests_sqlmap():
    output = "/index.php (Status: 200)\n/login.php (Status: 200)"
    results = suggest_next("gobuster_dir", output, "10.0.0.1")
    tools = [s["tool"] for s in results]
    assert "sqlmap_scan" in tools


# ── nikto branch ─────────────────────────────────────────────────────────────

def test_nikto_sql_indicator_suggests_sqlmap():
    output = "+ SQL injection possible in parameter id"
    results = suggest_next("nikto", output, "10.0.0.1")
    tools = [s["tool"] for s in results]
    assert "sqlmap_scan" in tools


def test_nikto_xss_suggests_ffuf():
    output = "+ XSS reflected in parameter q"
    results = suggest_next("nikto", output, "10.0.0.1")
    tools = [s["tool"] for s in results]
    assert "ffuf_fuzz" in tools


def test_nikto_no_match_returns_empty():
    output = "+ Server: Apache/2.4.49\n+ Retrieved x-powered-by header: PHP/7.4"
    results = suggest_next("nikto", output, "10.0.0.1")
    assert results == []


# ── hydra branch ─────────────────────────────────────────────────────────────

def test_hydra_cred_found_suggests_store_and_privesc():
    output = "[22][ssh] host: 10.0.0.1   login: admin   password: password123"
    results = suggest_next("hydra", output, "10.0.0.1")
    tools = [s["tool"] for s in results]
    assert "creds_store" in tools
    assert "ssh_enum_privesc" in tools
    store = next(s for s in results if s["tool"] == "creds_store")
    assert store["params"]["username"] == "admin"
    assert store["params"]["password"] == "password123"


def test_hydra_no_cred_returns_empty():
    output = "1 of 1 target completed, 0 valid passwords found"
    results = suggest_next("hydra", output, "10.0.0.1")
    assert results == []


# ── sqlmap branch ─────────────────────────────────────────────────────────────

def test_sqlmap_injectable_suggests_enumerate_dbs():
    output = "Parameter: id is injectable\nType: boolean-based"
    results = suggest_next("sqlmap", output, "10.0.0.1")
    tools = [s["tool"] for s in results]
    assert "sqlmap_scan" in tools
    enum = next(s for s in results if s["tool"] == "sqlmap_scan")
    assert enum["params"].get("enumerate_dbs") is True


def test_sqlmap_users_table_suggests_dump():
    output = "injectable\ndvwa users table found"
    results = suggest_next("sqlmap", output, "10.0.0.1")
    tools = [s["tool"] for s in results]
    assert "sqlmap_scan" in tools
    dump = next((s for s in results if s["params"].get("dump")), None)
    assert dump is not None


# ── ssh_enum_privesc branch ───────────────────────────────────────────────────

def test_privesc_suid_suggests_ssh_exec():
    output = "=== SUID ===\n/usr/bin/find\n/usr/bin/python3"
    results = suggest_next("ssh_enum_privesc", output, "10.0.0.1")
    tools = [s["tool"] for s in results]
    assert "ssh_exec" in tools


def test_privesc_sudo_suggests_ssh_exec():
    output = "=== SUDO ===\n(ALL : ALL) NOPASSWD: /bin/bash"
    results = suggest_next("ssh_enum_privesc", output, "10.0.0.1")
    tools = [s["tool"] for s in results]
    assert "ssh_exec" in tools


# ── nuclei/wpscan branch ──────────────────────────────────────────────────────

def test_nuclei_critical_suggests_searchsploit():
    output = "[critical] CVE-2021-44228 matched"
    results = suggest_next("nuclei", output, "http://10.0.0.1")
    tools = [s["tool"] for s in results]
    assert "searchsploit_search" in tools


def test_wpscan_high_suggests_searchsploit():
    output = "[high] WordPress plugin XYZ 1.0 vulnerable"
    results = suggest_next("wpscan", output, "http://10.0.0.1")
    tools = [s["tool"] for s in results]
    assert "searchsploit_search" in tools


def test_unknown_tool_returns_empty():
    results = suggest_next("unknown_tool_xyz", "some output", "10.0.0.1")
    assert results == []


# ── return structure ──────────────────────────────────────────────────────────

def test_suggestion_has_required_keys():
    """Every suggestion must have reason, tool, and params keys."""
    output = "22/tcp open ssh\n80/tcp open http\n445/tcp open smb"
    results = suggest_next("nmap_port_scan", output, "10.0.0.1")
    assert results, "Should have at least one suggestion"
    for s in results:
        assert "reason" in s, f"Missing 'reason' in {s}"
        assert "tool" in s,   f"Missing 'tool' in {s}"
        assert "params" in s, f"Missing 'params' in {s}"
