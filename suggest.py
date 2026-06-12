"""
Auto-suggest next steps based on tool findings.
Called after each tool completes — returns actionable suggestions.
"""
import re


def suggest_next(tool: str, output: str, target: str) -> list[dict]:
    """
    Return a list of suggested next steps based on what was found.
    Each suggestion has: tool, reason, params (ready to call).
    """
    suggestions = []
    out = output.lower()

    if tool in ("nmap_host_discovery", "nmap_port_scan", "nmap_service_detection", "nmap_aggressive_scan"):
        # Port-based suggestions
        if "22/tcp" in out or "ssh" in out:
            suggestions.append({
                "reason": "SSH port open — check for weak credentials",
                "tool": "hydra_bruteforce",
                "params": {"target": target, "service": "ssh",
                           "userlist": "/usr/share/wordlists/metasploit/unix_users.txt",
                           "passlist": "/usr/share/wordlists/fasttrack.txt"}
            })
        if any(p in out for p in ["80/tcp", "443/tcp", "8080/tcp", "8443/tcp", "http"]):
            suggestions.append({
                "reason": "HTTP service found — scan for vulnerabilities",
                "tool": "nikto_scan",
                "params": {"target": target}
            })
            suggestions.append({
                "reason": "HTTP service found — enumerate directories",
                "tool": "gobuster_dir",
                "params": {"url": f"http://{target}/"}
            })
            suggestions.append({
                "reason": "HTTP service found — run nuclei CVE templates",
                "tool": "nuclei_scan",
                "params": {"target": f"http://{target}", "severity": "medium,high,critical"}
            })
        if any(p in out for p in ["445/tcp", "139/tcp", "smb", "samba"]):
            suggestions.append({
                "reason": "SMB port open — enumerate users, shares, and misconfigs",
                "tool": "enum4linux_scan",
                "params": {"target": target}
            })
            suggestions.append({
                "reason": "SMB port open — check for EternalBlue and other SMB vulns",
                "tool": "nmap_vuln_scan",
                "params": {"targets": target, "ports": "445",
                           "scripts": "smb-vuln-ms17-010,smb-vuln-ms08-067,smb-security-mode"}
            })
        if any(p in out for p in ["3306/tcp", "mysql"]):
            suggestions.append({
                "reason": "MySQL port open — brute-force credentials",
                "tool": "hydra_bruteforce",
                "params": {"target": target, "service": "mysql",
                           "username": "root", "passlist": "/usr/share/wordlists/fasttrack.txt"}
            })
        if any(p in out for p in ["21/tcp", "ftp"]):
            suggestions.append({
                "reason": "FTP port open — check anonymous login and brute-force",
                "tool": "hydra_bruteforce",
                "params": {"target": target, "service": "ftp",
                           "username": "anonymous", "password": "anonymous"}
            })
        if any(p in out for p in ["3389/tcp", "rdp"]):
            suggestions.append({
                "reason": "RDP port open — brute-force credentials",
                "tool": "hydra_bruteforce",
                "params": {"target": target, "service": "rdp",
                           "userlist": "/usr/share/wordlists/metasploit/unix_users.txt",
                           "passlist": "/usr/share/wordlists/fasttrack.txt"}
            })

    elif tool in ("gobuster_dir", "ffuf_fuzz"):
        # Check if login/admin pages found
        if any(p in out for p in ["/admin", "/login", "/wp-admin", "/phpmyadmin"]):
            url = f"http://{target}"
            suggestions.append({
                "reason": "Admin/login page found — check for default credentials",
                "tool": "http_request",
                "params": {"url": url, "extract_text": True}
            })
        if "/wp-" in out or "wordpress" in out:
            suggestions.append({
                "reason": "WordPress detected — run WPScan",
                "tool": "wpscan_scan",
                "params": {"url": f"http://{target}"}
            })
        if any(ext in out for ext in [".php", ".asp", ".aspx", ".jsp"]):
            suggestions.append({
                "reason": "Dynamic pages found — test for SQL injection",
                "tool": "sqlmap_scan",
                "params": {"url": f"http://{target}/<found_path>?id=1",
                           "note": "Replace <found_path> with a discovered dynamic page"}
            })

    elif tool == "nikto":
        if "sql" in out or "inject" in out:
            suggestions.append({
                "reason": "Potential SQL injection indicator found by Nikto",
                "tool": "sqlmap_scan",
                "params": {"url": f"http://{target}/", "level": 2}
            })
        if "xss" in out or "cross-site" in out:
            suggestions.append({
                "reason": "XSS indicator found — test with ffuf parameter fuzzing",
                "tool": "ffuf_fuzz",
                "params": {"url": f"http://{target}/?FUZZ=<script>alert(1)</script>",
                           "match_codes": "200"}
            })

    elif tool == "hydra":
        # Extract found creds and suggest using them
        cred_match = re.search(r"\[(\d+)\]\[(\w+)\] host: \S+\s+login: (\S+)\s+password: (\S+)", output)
        if cred_match:
            port, service, user, pwd = cred_match.groups()
            suggestions.append({
                "reason": f"Valid {service} creds found — store them and connect",
                "tool": "creds_store",
                "params": {"host": target, "service": service, "port": int(port),
                           "username": user, "password": pwd, "source_tool": "hydra"}
            })
            if service == "ssh":
                suggestions.append({
                    "reason": "Valid SSH creds — enumerate privilege escalation vectors",
                    "tool": "ssh_enum_privesc",
                    "params": {"host": target, "username": user, "password": pwd}
                })

    elif tool == "sqlmap":
        if "injectable" in out:
            suggestions.append({
                "reason": "SQLi confirmed — enumerate databases",
                "tool": "sqlmap_scan",
                "params": {"url": f"http://{target}/",
                           "enumerate_dbs": True, "note": "Rerun with enumerate_dbs=True"}
            })
        if "dvwa" in out or "users" in out.lower():
            suggestions.append({
                "reason": "Database found — dump user table for credentials",
                "tool": "sqlmap_scan",
                "params": {"url": f"http://{target}/", "dump": True,
                           "database": "dvwa", "table": "users"}
            })

    elif tool == "ssh_enum_privesc":
        if "suid" in out:
            suid_bins = re.findall(r"/usr/bin/\w+|/bin/\w+", output)
            if suid_bins:
                suggestions.append({
                    "reason": f"SUID binaries found — check GTFOBins for privesc: {suid_bins[:3]}",
                    "tool": "ssh_exec",
                    "params": {"host": target, "command": "sudo -l 2>/dev/null; getcap -r / 2>/dev/null | head -20"}
                })
        if "sudo" in out:
            suggestions.append({
                "reason": "sudo permissions found — review for privesc opportunities",
                "tool": "ssh_exec",
                "params": {"host": target, "command": "sudo -l"}
            })

    elif tool in ("nuclei", "wpscan"):
        if any(s in out for s in ["critical", "high"]):
            suggestions.append({
                "reason": "High/critical vulnerabilities found — search for exploits",
                "tool": "searchsploit_search",
                "params": {"query": target}
            })

    return suggestions
