"""Tests for attack-chain engine — pure functions, no I/O, no subprocess."""
import pytest
from chains import build_attack_chains


def _f(host, title, severity, evidence="", port=0, tool="test", confidence="medium"):
    return {
        "host": host, "port": port, "title": title, "severity": severity,
        "evidence": evidence, "tool": tool, "confidence": confidence,
    }


def test_sqli_ssh_chain_detected():
    findings = [
        _f("10.0.0.1", "SQL Injection in id", "critical", "injectable", tool="sqlmap"),
        _f("10.0.0.1", "Open port 22/ssh", "info", "SSH", port=22, tool="nmap"),
    ]
    chains = build_attack_chains(findings)
    assert len(chains) >= 1
    sql_chain = [c for c in chains if "SQL Injection" in c["name"]]
    assert len(sql_chain) == 1


def test_chain_escalates_severity():
    findings = [
        _f("10.0.0.1", "Found login page", "medium", "/admin", tool="gobuster"),
        _f("10.0.0.1", "Valid credentials found for ssh", "medium", "root:toor", tool="hydra"),
    ]
    chains = build_attack_chains(findings)
    # Two medium findings produce chains that escalate to high
    assert all(c["severity"] == "high" for c in chains)


def test_no_chain_when_signal_missing():
    findings = [
        _f("10.0.0.1", "SQL Injection in id", "critical", "injectable", tool="sqlmap"),
    ]
    chains = build_attack_chains(findings)
    sql_ssh = [c for c in chains if "SQL Injection" in c["name"]]
    assert len(sql_ssh) == 0


def test_smb_chain_standalone():
    findings = [
        _f("10.0.0.1", "MS17-010 EternalBlue", "critical", "smb-vuln", tool="nmap"),
    ]
    chains = build_attack_chains(findings)
    smb = [c for c in chains if "SMB" in c["name"] or "EternalBlue" in c["name"]]
    assert len(smb) >= 1


def test_chains_sorted_critical_first():
    findings = [
        _f("h1", "Valid credentials found", "critical", "root:root", tool="hydra"),
        _f("h1", "Open port 22/ssh", "info", "SSH", port=22, tool="nmap"),
        _f("h2", "Found login page", "low", "/admin", tool="gobuster"),
        _f("h2", "Open port 80/http", "info", "http", port=80, tool="nmap"),
        _f("h2", "Searchsploit CVE-2021", "high", "exploit", tool="searchsploit"),
    ]
    chains = build_attack_chains(findings)
    assert len(chains) > 1
    sevs = [c["severity"] for c in chains]
    assert sevs == sorted(sevs, reverse=True, key=lambda s: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(s, 0))


def test_empty_findings_returns_empty():
    assert build_attack_chains([]) == []
