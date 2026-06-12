"""Fast port scan: masscan for speed, then nmap for service detection on open ports."""
import re
import tempfile
import os

from config import TOOL_TIMEOUTS, ARTIFACTS_DIR
from scope import check_scope
from tools.base import ToolExecutor

_ex = ToolExecutor()


def _register(mcp, job_mgr):

    @mcp.tool()
    async def fast_port_scan(
        target: str,
        ports: str = "0-65535",
        rate: int = 5000,
        service_detection: bool = True,
    ) -> dict:
        """
        Fast port scan using masscan (discovery) + nmap (service detection).
        Much faster than nmap alone for large ranges — masscan at 5000 pps finds
        all open ports, then nmap does targeted -sV only on those ports.
        target: IP, CIDR range (e.g. '192.168.1.0/24'), or hostname
        ports: port range (default all ports '0-65535')
        rate: masscan packets per second — higher = faster but more noisy (default 5000)
              Use 1000 for stealth, 10000+ for speed on local networks
        service_detection: run nmap -sV on discovered ports (default True)
        Returns: open ports with services, much faster than full nmap scan
        NOTE: masscan requires root/sudo for raw sockets
        """
        check_scope(target)
        out_file = os.path.join(ARTIFACTS_DIR, f"masscan_{target.replace('/', '_')}.txt")

        # Step 1: masscan fast discovery
        masscan_cmd = [
            "sudo", "-n", "masscan", target,
            "-p", ports,
            "--rate", str(rate),
            "-oL", out_file,
            "--wait", "3",
        ]
        masscan_result = await _ex.run(masscan_cmd, timeout=TOOL_TIMEOUTS.get("nmap_port_scan", 600))
        if masscan_result.get("error") and "not found" in masscan_result.get("error", ""):
            return masscan_result  # binary missing

        # Parse masscan output for open ports
        open_ports = []
        if os.path.exists(out_file):
            with open(out_file) as f:
                for line in f:
                    m = re.match(r"open tcp (\d+) (\S+)", line)
                    if m:
                        open_ports.append(int(m.group(1)))

        result = {
            "masscan_output": masscan_result.get("stdout", ""),
            "open_ports": sorted(set(open_ports)),
            "open_port_count": len(open_ports),
        }

        if not open_ports:
            result["note"] = "No open ports found by masscan"
            return result

        # Step 2: nmap targeted service detection on found ports
        if service_detection and open_ports:
            ports_str = ",".join(str(p) for p in sorted(set(open_ports)))
            nmap_result = await _ex.run(
                ["nmap", "-sT", "-sV", "--version-intensity", "5",
                 "-p", ports_str, target],
                timeout=300
            )
            result["nmap_service_output"] = nmap_result.get("stdout", "")
            # Extract service lines
            services = []
            for line in nmap_result.get("stdout", "").splitlines():
                if "/tcp" in line and "open" in line:
                    services.append(line.strip())
            result["services"] = services

            from suggest import suggest_next
            suggestions = suggest_next(
                "nmap_port_scan", nmap_result.get("stdout", ""), target
            )
            if suggestions:
                result["suggested_next"] = suggestions

        return result
