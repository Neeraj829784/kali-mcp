from scope import check_scope
from tools.base import ToolExecutor

_ex = ToolExecutor()


def _register(mcp, job_mgr):

    @mcp.tool()
    async def smbclient_list_shares(
        target: str,
        username: str = "",
        password: str = "",
        port: int = 445,
    ) -> dict:
        """
        List SMB shares on a target host using smbclient.
        target: IP or hostname
        username: SMB username (leave empty for anonymous)
        password: SMB password (leave empty for anonymous)
        port: SMB port (default 445)
        """
        check_scope(target)
        cmd = ["smbclient", "-L", target, "-p", str(port), "-g"]
        if username:
            cmd += ["-U", f"{username}%{password}" if password else username]
        else:
            cmd += ["-N"]
        result = await _ex.run(cmd, timeout=30)
        # Extract share findings inline
        output = result.get("stdout", "")
        if output:
            from findings import _finding, CONF_HIGH, LOW, MEDIUM
            findings = []
            for line in output.splitlines():
                parts = line.split("|")
                if len(parts) >= 2 and parts[0] in ("Disk", "IPC", "Printer"):
                    share = parts[1].strip()
                    sev = MEDIUM if parts[0] == "Disk" else LOW
                    findings.append(_finding(
                        host=target, title=f"SMB share accessible: {share}",
                        severity=sev, evidence=line.strip(),
                        tool="smbclient", confidence=CONF_HIGH,
                    ))
            if findings:
                result["findings"] = findings
                result["findings_count"] = len(findings)
        return result
