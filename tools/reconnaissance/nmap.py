import os

from config import TOOL_TIMEOUTS
from scope import check_scope
from tools.base import ToolExecutor
from parsers import parse_nmap_xml

_ex = ToolExecutor()
_IS_ROOT = os.geteuid() == 0


def _register(mcp, job_mgr):

    @mcp.tool()
    async def nmap_host_discovery(targets: str) -> dict:
        """
        Ping scan to discover live hosts (-sn). Fast, no port scan.
        targets: IPs, ranges, or CIDR (e.g. '192.168.1.0/24', '10.0.0.1-10')
        """
        for t in targets.split():
            check_scope(t)
        cmd = ["nmap", "-sn"] + targets.split()
        return await _ex.run(cmd, timeout=TOOL_TIMEOUTS["nmap_host_discovery"])

    @mcp.tool()
    async def nmap_port_scan(
        targets: str,
        ports: str = "1-1000",
        scan_type: str = "auto",
        timing: str = "T4",
        wait: bool = False,
    ) -> dict:
        """
        Port scan returning job_id (async by default) or blocking until complete.
        targets: IPs/ranges/hostnames (space-separated for multiple)
        ports: '1-65535', '22,80,443', or 'top100'
        scan_type: 'auto' (sS if root else sT), 'sS' (SYN/root only),
                   'sT' (TCP connect), 'sU' (UDP), 'sA' (ACK)
        timing: T0-T5 (T4=fast, T3=normal, T2=polite)
        wait: if True, blocks until scan completes and returns full output
        """
        for t in targets.split():
            check_scope(t)
        if ports == "top100":
            port_args = ["--top-ports", "100"]
        else:
            port_args = ["-p", ports]
        effective_type = scan_type
        if scan_type == "auto":
            effective_type = "sS" if _IS_ROOT else "sT"
        cmd = ["nmap", f"-{effective_type}", f"-{timing}"] + port_args + targets.split()
        if wait:
            return await job_mgr.run_and_wait("nmap_port_scan", cmd, TOOL_TIMEOUTS["nmap_port_scan"])
        return {"job_id": await job_mgr.create_job("nmap_port_scan", cmd, TOOL_TIMEOUTS["nmap_port_scan"]),
                "note": f"Using -{effective_type} ({'SYN/root' if effective_type == 'sS' else 'TCP connect'}). Pass wait=True to block."}

    @mcp.tool()
    async def nmap_service_detection(
        targets: str,
        ports: str = "1-1000",
        version_intensity: int = 5,
    ) -> dict:
        """
        Detect service versions on open ports (-sV).
        version_intensity: 0 (light) to 9 (try all probes)
        """
        for t in targets.split():
            check_scope(t)
        cmd = ["nmap", "-sV", "--version-intensity", str(version_intensity),
               "-p", ports] + targets.split()
        return await job_mgr.run_and_wait("nmap_service_detection", cmd, TOOL_TIMEOUTS["nmap_service_detection"])

    @mcp.tool()
    async def nmap_os_detection(targets: str) -> dict:
        """
        OS detection scan (-O). Automatically uses sudo if not root.
        targets: IPs/ranges/hostnames
        """
        for t in targets.split():
            check_scope(t)
        base = ["nmap", "-O", "--osscan-guess"] + targets.split()
        cmd = base if _IS_ROOT else ["sudo", "-n"] + base
        return await job_mgr.run_and_wait("nmap_os_detection", cmd, TOOL_TIMEOUTS["nmap_os_detection"])

    @mcp.tool()
    async def nmap_vuln_scan(
        targets: str,
        ports: str = "1-1000",
        scripts: str = "vuln",
    ) -> dict:
        """
        NSE vulnerability script scan.
        scripts: NSE script categories — 'vuln', 'safe', 'vuln and safe',
                 'exploit', or specific scripts like 'smb-vuln-ms17-010'
        """
        for t in targets.split():
            check_scope(t)
        cmd = ["nmap", f"--script={scripts}", "-p", ports] + targets.split()
        return await job_mgr.run_and_wait("nmap_vuln_scan", cmd, TOOL_TIMEOUTS["nmap_vuln_scan"])

    @mcp.tool()
    async def nmap_aggressive_scan(targets: str, ports: str = "1-1000") -> dict:
        """
        Aggressive scan (-A): OS + version + default scripts + traceroute.
        targets: IPs/ranges/hostnames
        """
        for t in targets.split():
            check_scope(t)
        cmd = ["nmap", "-A", "-p", ports] + targets.split()
        return await job_mgr.run_and_wait("nmap_aggressive_scan", cmd, TOOL_TIMEOUTS["nmap_aggressive_scan"])

    @mcp.tool()
    async def nmap_xml_scan(
        targets: str,
        ports: str = "1-1000",
        scan_type: str = "auto",
        timing: str = "T4",
        service_detection: bool = True,
    ) -> dict:
        """
        Port scan with XML output — returns fully structured host/port/service data.
        Unlike nmap_port_scan (raw text), this parses XML into structured dicts so
        findings, services, and OS guesses are immediately usable without regex.
        targets: IPs/ranges/hostnames (space-separated)
        ports: '1-65535', '22,80,443', or 'top100'
        scan_type: 'auto' (sS if root else sT), 'sS', 'sT'
        timing: T0-T5
        service_detection: include -sV service version probing (default True)
        Returns: structured dict with hosts[], each containing ports[], services, os[]
        """
        import tempfile
        for t in targets.split():
            check_scope(t)

        if ports == "top100":
            port_args = ["--top-ports", "100"]
        else:
            port_args = ["-p", ports]

        effective_type = scan_type
        if scan_type == "auto":
            effective_type = "sS" if _IS_ROOT else "sT"

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = tmp.name

        try:
            cmd = ["nmap", f"-{effective_type}", f"-{timing}", "-oX", xml_path]
            if service_detection:
                cmd += ["-sV", "--version-intensity", "5"]
            cmd += port_args + targets.split()

            result = await _ex.run(cmd, timeout=TOOL_TIMEOUTS["nmap_port_scan"],
                                   tool_name="nmap_port_scan")
            if result.get("error"):
                return result

            with open(xml_path, "r", errors="replace") as f:
                xml_content = f.read()

            parsed = parse_nmap_xml(xml_content)
            parsed["raw_output"] = result.get("stdout", "")[:500]  # brief summary

            # Auto-extract findings from the text output too
            from findings import extract_findings
            from suggest import suggest_next
            findings = extract_findings("nmap_port_scan", result.get("stdout", ""), targets.split()[0])
            if findings:
                parsed["findings"] = findings
                parsed["findings_count"] = len(findings)
            suggestions = suggest_next("nmap_port_scan", result.get("stdout", ""), targets.split()[0])
            if suggestions:
                parsed["suggested_next"] = suggestions

            return parsed
        finally:
            if os.path.exists(xml_path):
                os.unlink(xml_path)
