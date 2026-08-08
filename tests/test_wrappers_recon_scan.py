"""Mock-based tests for reconnaissance + scanning tool wrappers.

These run entirely offline (no real binaries, no network) via the `fake_exec`
fixture, so CI can verify the tool-wrapper layer — command construction, flag
handling, and graceful errors — on every push.
"""
import pytest
from tests.conftest import call
from scope import clear_scope


@pytest.fixture(autouse=True)
def lab_mode():
    clear_scope()
    yield
    clear_scope()


@pytest.fixture
def wordlist(tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("admin\nlogin\nindex\n")
    return str(wl)


# ── Reconnaissance ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_nmap_host_discovery(mcp_server, fake_exec):
    await call(mcp_server, "nmap_host_discovery", {"targets": "10.0.0.0/24"})
    assert fake_exec.cmd_contains("nmap", "-sn", "10.0.0.0/24")


@pytest.mark.asyncio
async def test_nmap_port_scan_wait(mcp_server, fake_exec):
    # wait=True → run_and_wait, deterministic command capture
    await call(mcp_server, "nmap_port_scan",
               {"targets": "10.0.0.5", "ports": "22,80", "scan_type": "sT",
                "timing": "T4", "wait": True})
    assert fake_exec.cmd_contains("nmap", "-sT", "-T4", "-p", "22,80", "10.0.0.5")


@pytest.mark.asyncio
async def test_nmap_service_detection(mcp_server, fake_exec):
    await call(mcp_server, "nmap_service_detection",
               {"targets": "10.0.0.5", "ports": "80", "version_intensity": 7})
    assert fake_exec.cmd_contains("nmap", "-sV", "--version-intensity", "7", "-p", "80")


@pytest.mark.asyncio
async def test_nmap_vuln_scan(mcp_server, fake_exec):
    await call(mcp_server, "nmap_vuln_scan",
               {"targets": "10.0.0.5", "ports": "445", "scripts": "smb-vuln-ms17-010"})
    assert fake_exec.cmd_contains("nmap", "--script=smb-vuln-ms17-010", "-p", "445")


@pytest.mark.asyncio
async def test_nmap_aggressive_scan(mcp_server, fake_exec):
    await call(mcp_server, "nmap_aggressive_scan", {"targets": "10.0.0.5", "ports": "1-100"})
    assert fake_exec.cmd_contains("nmap", "-A", "-p", "1-100")


@pytest.mark.asyncio
async def test_nmap_os_detection_with_sudo(mcp_server, fake_exec, monkeypatch):
    # Pretend passwordless sudo is available so the command is built (not the error)
    monkeypatch.setattr("tools.reconnaissance.nmap.can_sudo_noninteractive", lambda: True)
    monkeypatch.setattr("tools.reconnaissance.nmap._IS_ROOT", False)
    await call(mcp_server, "nmap_os_detection", {"targets": "10.0.0.5"})
    assert fake_exec.cmd_contains("nmap", "-O", "--osscan-guess", "10.0.0.5")


@pytest.mark.asyncio
async def test_nmap_os_detection_no_sudo_errors(mcp_server, fake_exec, monkeypatch):
    monkeypatch.setattr("tools.reconnaissance.nmap.can_sudo_noninteractive", lambda: False)
    monkeypatch.setattr("tools.reconnaissance.nmap._IS_ROOT", False)
    r = await call(mcp_server, "nmap_os_detection", {"targets": "10.0.0.5"})
    assert "requires root" in r.get("error", "").lower()


@pytest.mark.asyncio
async def test_nmap_target_validation_blocks_injection(mcp_server, fake_exec):
    r = await call(mcp_server, "nmap_port_scan", {"targets": "--script=evil", "wait": True})
    assert "error" in r and not fake_exec.calls  # rejected before any execution


@pytest.mark.asyncio
async def test_subfinder_flags(mcp_server, fake_exec):
    await call(mcp_server, "subfinder_enumerate",
               {"domain": "example.com", "all_sources": True})
    assert fake_exec.cmd_contains("subfinder", "-d", "example.com", "-silent", "-all")


@pytest.mark.asyncio
async def test_amass_passive(mcp_server, fake_exec):
    await call(mcp_server, "amass_enum", {"domain": "example.com", "passive": True})
    assert fake_exec.cmd_contains("amass", "enum", "-d", "example.com", "-passive")


@pytest.mark.asyncio
async def test_theharvester(mcp_server, fake_exec):
    await call(mcp_server, "theharvester_search", {"domain": "example.com", "limit": 200})
    assert fake_exec.cmd_contains("theHarvester", "-d", "example.com", "-l", "200", "-b")


@pytest.mark.asyncio
async def test_dig_record_and_short(mcp_server, fake_exec):
    await call(mcp_server, "dig_lookup", {"domain": "example.com", "record_type": "MX", "short": True})
    assert fake_exec.cmd_contains("dig", "example.com", "MX", "+short")


@pytest.mark.asyncio
async def test_dig_zone_transfer(mcp_server, fake_exec):
    await call(mcp_server, "dig_zone_transfer", {"domain": "example.com", "nameserver": "1.2.3.4"})
    assert fake_exec.cmd_contains("dig", "@1.2.3.4", "example.com", "AXFR")


# ── Scanning ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_gobuster_dir_extensions(mcp_server, fake_exec, wordlist):
    fake_exec.set_output("")  # empty → no findings → no verify network call
    await call(mcp_server, "gobuster_dir",
               {"url": "http://example.com/", "wordlist": wordlist,
                "extensions": "php,html", "threads": 5})
    assert fake_exec.cmd_contains("gobuster", "dir", "-u", "http://example.com/",
                                  "-x", "php,html", "-t", "5")


@pytest.mark.asyncio
async def test_gobuster_dns(mcp_server, fake_exec, wordlist):
    await call(mcp_server, "gobuster_dns",
               {"domain": "example.com", "wordlist": wordlist, "show_ips": True})
    assert fake_exec.cmd_contains("gobuster", "dns", "-d", "example.com", "-i")


@pytest.mark.asyncio
async def test_gobuster_vhost(mcp_server, fake_exec, wordlist):
    fake_exec.set_output("")
    await call(mcp_server, "gobuster_vhost",
               {"url": "http://example.com", "wordlist": wordlist, "append_domain": True})
    assert fake_exec.cmd_contains("gobuster", "vhost", "--append-domain")


@pytest.mark.asyncio
async def test_nikto_ssl(mcp_server, fake_exec):
    await call(mcp_server, "nikto_scan",
               {"target": "example.com", "port": 443, "ssl": True, "max_time": "30s"})
    assert fake_exec.cmd_contains("nikto", "-h", "example.com", "-p", "443",
                                  "-maxtime", "30s", "-ssl")


@pytest.mark.asyncio
async def test_ffuf_post_and_headers(mcp_server, fake_exec, wordlist):
    fake_exec.set_output("")
    await call(mcp_server, "ffuf_fuzz",
               {"url": "http://example.com/FUZZ", "wordlist": wordlist,
                "data": "a=FUZZ", "headers": "X-Test: 1", "threads": 5})
    # -w before -u; POST switched on by data; header passed through
    assert fake_exec.cmd_contains("ffuf", "-w", "-u", "http://example.com/FUZZ",
                                  "-d", "a=FUZZ", "-X", "POST", "-H", "X-Test: 1")


@pytest.mark.asyncio
async def test_enum4linux_auth(mcp_server, fake_exec):
    await call(mcp_server, "enum4linux_scan",
               {"target": "10.0.0.5", "username": "bob", "password": "pw"})
    assert fake_exec.cmd_contains("enum4linux", "-a", "-u", "bob", "-p", "pw", "10.0.0.5")


@pytest.mark.asyncio
async def test_smbclient_anonymous(mcp_server, fake_exec):
    await call(mcp_server, "smbclient_list_shares", {"target": "10.0.0.5"})
    assert fake_exec.cmd_contains("smbclient", "-L", "10.0.0.5", "-N")


@pytest.mark.asyncio
async def test_fast_port_scan_needs_sudo(mcp_server, fake_exec, monkeypatch):
    monkeypatch.setattr("tools.scanning.fast_port_scan.can_sudo_noninteractive", lambda: False)
    r = await call(mcp_server, "fast_port_scan", {"target": "10.0.0.5"})
    assert "requires root" in r.get("error", "").lower()


@pytest.mark.asyncio
async def test_fast_port_scan_with_sudo_builds_masscan(mcp_server, fake_exec, monkeypatch):
    monkeypatch.setattr("tools.scanning.fast_port_scan.can_sudo_noninteractive", lambda: True)
    fake_exec.set_output("")  # no open ports parsed → skips nmap phase
    await call(mcp_server, "fast_port_scan",
               {"target": "10.0.0.5", "ports": "1-1000", "rate": 2000})
    assert fake_exec.any_cmd_contains("masscan", "10.0.0.5", "--rate", "2000")
