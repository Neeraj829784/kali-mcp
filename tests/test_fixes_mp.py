"""
Tests for the 4 medium-priority fixes:
  Fix 1 — scope.py thread-safe cache
  Fix 2 — job_manager.py retry with backoff
  Fix 3 — chains.py confidence-weighted signals
  Fix 4 — remediation.py CVE-specific guidance
"""
import asyncio
import threading
import time

import pytest
import pytest_asyncio


# ── Fix 1: thread-safe scope cache ───────────────────────────────────────────

def test_scope_cache_survives_concurrent_invalidation(tmp_path, monkeypatch):
    """Concurrent invalidate + load must not produce None or raise."""
    import scope as s
    monkeypatch.setattr(s, "SCOPE_FILE", str(tmp_path / "scope.txt"))
    s.clear_scope()
    s.add_scope("10.0.0.1")

    errors = []

    def reader():
        for _ in range(50):
            try:
                entries = s._load_scope()
                assert entries is not None
            except Exception as e:
                errors.append(e)

    def writer():
        for _ in range(50):
            try:
                s._invalidate()
            except Exception as e:
                errors.append(e)

    threads = [threading.Thread(target=reader) for _ in range(4)]
    threads += [threading.Thread(target=writer) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Thread safety errors: {errors}"


def test_scope_check_scope_thread_safe(tmp_path, monkeypatch):
    """check_scope must not raise due to cache race under concurrent calls."""
    import scope as s
    monkeypatch.setattr(s, "SCOPE_FILE", str(tmp_path / "scope2.txt"))
    s.clear_scope()
    s.add_scope("192.168.1.0/24")

    errors = []

    def check():
        for _ in range(30):
            try:
                s.check_scope("192.168.1.50")
            except ValueError:
                pass  # out-of-scope raises are expected, not errors
            except Exception as e:
                errors.append(e)

    def invalidate():
        for _ in range(30):
            s._invalidate()

    ts = [threading.Thread(target=check) for _ in range(5)]
    ts += [threading.Thread(target=invalidate) for _ in range(2)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()

    assert not errors, f"Unexpected errors: {errors}"


# ── Fix 2: retry logic ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_job_retries_on_timeout(tmp_path, monkeypatch):
    """A job that times out must be retried up to _MAX_RETRIES times."""
    import job_manager as jm_mod
    from job_manager import JobManager

    monkeypatch.setattr(jm_mod, "JOBS_DB_PATH", str(tmp_path / "jobs.db"))
    monkeypatch.setattr(jm_mod, "ARTIFACTS_DIR", str(tmp_path))
    monkeypatch.setattr(jm_mod, "_MAX_RETRIES", 2)
    monkeypatch.setattr(jm_mod, "_RETRY_BASE_DELAY", 0.05)  # fast test

    attempt_log: list[int] = []
    original_run = jm_mod._executor.run

    async def mock_run(cmd, timeout, **kwargs):
        attempt_log.append(1)
        # Fail first 2 calls with timeout, succeed on 3rd
        if len(attempt_log) < 3:
            return {"timed_out": True, "return_code": -1, "stdout": ""}
        return {"timed_out": False, "return_code": 0, "stdout": "done"}

    monkeypatch.setattr(jm_mod._executor, "run", mock_run)

    jm = JobManager()
    await jm.init_db()
    result = await jm.run_and_wait("test_retry", ["echo", "x"], timeout=1)

    assert result["status"] == "completed", f"Expected completed, got: {result}"
    assert len(attempt_log) == 3, f"Expected 3 attempts, got {len(attempt_log)}"


@pytest.mark.asyncio
async def test_job_no_retry_on_permanent_error(tmp_path, monkeypatch):
    """'Tool not found' errors must NOT be retried — permanent failure."""
    import job_manager as jm_mod
    from job_manager import JobManager

    monkeypatch.setattr(jm_mod, "JOBS_DB_PATH", str(tmp_path / "jobs2.db"))
    monkeypatch.setattr(jm_mod, "ARTIFACTS_DIR", str(tmp_path))
    monkeypatch.setattr(jm_mod, "_MAX_RETRIES", 2)
    monkeypatch.setattr(jm_mod, "_RETRY_BASE_DELAY", 0.05)

    attempt_log: list[int] = []

    async def mock_run(cmd, timeout, **kwargs):
        attempt_log.append(1)
        return {"error": "Tool not found: nonexistent_tool",
                "return_code": -1, "timed_out": False, "stdout": ""}

    monkeypatch.setattr(jm_mod._executor, "run", mock_run)

    jm = JobManager()
    await jm.init_db()
    result = await jm.run_and_wait("test_perm", ["nonexistent_tool"], timeout=5)

    assert result["status"] == "failed"
    assert len(attempt_log) == 1, f"Permanent error should not retry, got {len(attempt_log)} attempts"


@pytest.mark.asyncio
async def test_retry_count_visible_in_list_jobs(tmp_path, monkeypatch):
    """retry_count must appear in list_jobs output."""
    import job_manager as jm_mod
    from job_manager import JobManager

    monkeypatch.setattr(jm_mod, "JOBS_DB_PATH", str(tmp_path / "jobs3.db"))
    monkeypatch.setattr(jm_mod, "ARTIFACTS_DIR", str(tmp_path))
    monkeypatch.setattr(jm_mod, "_MAX_RETRIES", 1)
    monkeypatch.setattr(jm_mod, "_RETRY_BASE_DELAY", 0.05)

    call_count = [0]

    async def mock_run(cmd, timeout, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return {"timed_out": True, "return_code": -1, "stdout": ""}
        return {"timed_out": False, "return_code": 0, "stdout": "ok"}

    monkeypatch.setattr(jm_mod._executor, "run", mock_run)

    jm = JobManager()
    await jm.init_db()
    await jm.run_and_wait("test_retry_count", ["echo", "hi"], timeout=1)

    jobs = await jm.list_jobs(5)
    assert jobs, "Should have at least one job"
    assert "retry_count" in jobs[0], "retry_count must be in list_jobs output"


# ── Fix 3: confidence-weighted chain signals ──────────────────────────────────

def test_low_conf_nikto_password_field_no_cred_chain():
    """A low-confidence Nikto finding mentioning 'password' must NOT trigger
    the credential chain signal — classic false positive from old keyword matching."""
    from chains import build_attack_chains

    findings = [
        # Nikto low-conf "password field" noise
        {"host": "10.0.0.1", "title": "Password field found via form",
         "severity": "info", "tool": "nikto", "confidence": "low",
         "evidence": "password", "port": 80, "service": "http"},
        # SSH open
        {"host": "10.0.0.1", "title": "Open port 22/ssh",
         "severity": "info", "tool": "nmap", "confidence": "high",
         "evidence": "ssh", "port": 22, "service": "ssh"},
    ]
    chains = build_attack_chains(findings)
    chain_names = [c["name"] for c in chains]
    assert "Recovered Credentials → Lateral Movement → Privilege Escalation" not in chain_names, \
        "Low-conf Nikto noise should NOT trigger credential chain"


def test_hydra_high_conf_cred_triggers_chain():
    """Hydra confirmed credentials (high confidence) MUST trigger the chain."""
    from chains import build_attack_chains

    findings = [
        {"host": "10.0.0.1", "title": "Valid credentials found for ssh",
         "severity": "critical", "tool": "hydra", "confidence": "high",
         "evidence": "admin:password123", "port": 22, "service": "ssh"},
        {"host": "10.0.0.1", "title": "Open port 22/ssh",
         "severity": "info", "tool": "nmap", "confidence": "high",
         "evidence": "ssh", "port": 22, "service": "ssh"},
    ]
    chains = build_attack_chains(findings)
    chain_names = [c["name"] for c in chains]
    assert "Recovered Credentials → Lateral Movement → Privilege Escalation" in chain_names, \
        "High-conf Hydra creds must trigger credential chain"


def test_sqlmap_confirmed_sqli_triggers_chain():
    """SQLMap confirmed injection must trigger the SQLi chain."""
    from chains import build_attack_chains

    findings = [
        {"host": "10.0.0.1", "title": "SQL Injection in parameter 'id'",
         "severity": "critical", "tool": "sqlmap", "confidence": "high",
         "evidence": "injectable", "port": 80, "service": "http"},
        {"host": "10.0.0.1", "title": "Open port 22/ssh",
         "severity": "info", "tool": "nmap", "confidence": "high",
         "evidence": "ssh", "port": 22, "service": "ssh"},
    ]
    chains = build_attack_chains(findings)
    chain_names = [c["name"] for c in chains]
    assert "SQL Injection → Credential Theft → System Access" in chain_names


def test_low_conf_sqli_keyword_no_chain():
    """Low-confidence text mentioning 'sql injection' (e.g. from gobuster path)
    must NOT trigger the SQLi chain — only high-conf or authoritative tool."""
    from chains import build_attack_chains

    findings = [
        {"host": "10.0.0.1", "title": "Found path /sql-injection-test [200]",
         "severity": "low", "tool": "gobuster", "confidence": "low",
         "evidence": "sql injection", "port": 80, "service": "http"},
        {"host": "10.0.0.1", "title": "Open port 22/ssh",
         "severity": "info", "tool": "nmap", "confidence": "high",
         "evidence": "ssh", "port": 22, "service": "ssh"},
    ]
    chains = build_attack_chains(findings)
    chain_names = [c["name"] for c in chains]
    assert "SQL Injection → Credential Theft → System Access" not in chain_names


# ── Fix 4: CVE-specific remediation ──────────────────────────────────────────

def test_log4shell_cve_gets_specific_remediation():
    """CVE-2021-44228 in a finding title must return Log4Shell-specific guidance."""
    from remediation import get_remediation
    finding = {
        "title": "CVE-2021-44228 — Log4Shell JNDI injection",
        "evidence": "Matched CVE-2021-44228 in /app/log4j",
        "tool": "nuclei", "service": "http",
    }
    short, detail = get_remediation(finding)
    assert "Log4j" in short or "Log4Shell" in short
    assert "2.17.1" in detail  # specific version in the fix


def test_eternalblue_cve_gets_specific_remediation():
    """CVE-2017-0144 in evidence must return EternalBlue-specific guidance."""
    from remediation import get_remediation
    finding = {
        "title": "SMB vulnerability detected",
        "evidence": "CVE-2017-0144 confirmed",
        "tool": "nmap", "service": "smb",
    }
    short, detail = get_remediation(finding)
    assert "EternalBlue" in short or "MS17-010" in short
    assert "SMBv1" in detail


def test_unknown_cve_falls_back_to_keyword():
    """An unknown CVE should fall through to keyword matching, not default."""
    from remediation import get_remediation
    finding = {
        "title": "CVE-9999-99999 — SQL injection found",
        "evidence": "injectable parameter",
        "tool": "sqlmap", "service": "http",
    }
    short, detail = get_remediation(finding)
    # Should match the sql injection keyword rule, not the generic default
    assert "Parameterised" in short or "ORM" in short


def test_no_cve_keyword_match_sql():
    """Finding with no CVE but matching SQL injection keywords → keyword fix."""
    from remediation import get_remediation
    finding = {
        "title": "SQL Injection in parameter id",
        "evidence": "injectable",
        "tool": "sqlmap", "service": "http",
    }
    short, detail = get_remediation(finding)
    assert "Parameterised" in short


def test_no_match_returns_default():
    """Finding with no CVE and no keyword matches → default remediation."""
    from remediation import get_remediation
    finding = {
        "title": "Unknown misconfiguration",
        "evidence": "something unusual",
        "tool": "manual", "service": "",
    }
    short, detail = get_remediation(finding)
    assert short == "Investigate and Remediate"


def test_suid_privesc_gets_remediation():
    """SUID finding from ssh_enum_privesc must get privesc remediation."""
    from remediation import get_remediation
    finding = {
        "title": "SUID binaries found (12 total)",
        "evidence": "/usr/bin/find, /usr/bin/python3",
        "tool": "ssh_enum_privesc", "service": "",
    }
    short, detail = get_remediation(finding)
    assert "Privilege" in short or "privesc" in detail.lower() or "sudo" in detail.lower()
