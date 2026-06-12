"""PCAP parser using tshark/scapy."""
import os
import tempfile

from config import ARTIFACTS_DIR
from tools.base import ToolExecutor

_ex = ToolExecutor()


def _register(mcp, job_mgr):

    @mcp.tool()
    async def pcap_extract(pcap_path: str) -> dict:
        """
        Extract credentials and key data from a PCAP file.
        Extracts: HTTP requests (headers, POST data), FTP/Telnet/SMTP credentials,
        DNS queries, common protocol usernames/passwords.
        pcap_path: path to .pcap or .pcapng file
        Returns: structured findings by protocol
        """
        if not os.path.exists(pcap_path):
            return {"error": f"File not found: {pcap_path}"}

        findings = {}

        # HTTP requests with tshark
        r = await _ex.run([
            "tshark", "-r", pcap_path, "-Y", "http.request",
            "-T", "fields",
            "-e", "http.request.method",
            "-e", "http.host",
            "-e", "http.request.uri",
            "-e", "http.request.full_uri",
            "-e", "http.file_data"
        ], timeout=30)
        if r.get("stdout"):
            http_reqs = []
            for line in r["stdout"].splitlines():
                parts = line.split("\t")
                if len(parts) >= 3:
                    http_reqs.append({
                        "method": parts[0],
                        "host": parts[1] if len(parts) > 1 else "",
                        "uri": parts[2] if len(parts) > 2 else "",
                        "data": parts[4] if len(parts) > 4 else "",
                    })
            findings["http"] = http_reqs

        # FTP credentials
        r = await _ex.run([
            "tshark", "-r", pcap_path, "-Y", "ftp.request.command == USER or ftp.request.command == PASS",
            "-T", "fields", "-e", "ftp.request.command", "-e", "ftp.request.arg"
        ], timeout=30)
        if r.get("stdout"):
            creds = {}
            for line in r["stdout"].splitlines():
                parts = line.split("\t")
                if len(parts) == 2:
                    if parts[0] == "USER":
                        creds["user"] = parts[1]
                    elif parts[0] == "PASS":
                        creds["password"] = parts[1]
            if creds:
                findings["ftp_creds"] = creds

        # Telnet data (look for common patterns)
        r = await _ex.run([
            "tshark", "-r", pcap_path, "-Y", "telnet",
            "-T", "fields", "-e", "telnet.data"
        ], timeout=30)
        if r.get("stdout"):
            telnet_data = r["stdout"][:1000]  # first 1KB
            findings["telnet_data"] = telnet_data

        # DNS queries
        r = await _ex.run([
            "tshark", "-r", pcap_path, "-Y", "dns.flags.response == 0",
            "-T", "fields", "-e", "dns.qry.name"
        ], timeout=30)
        if r.get("stdout"):
            queries = list(set(r["stdout"].splitlines()))[:50]
            findings["dns_queries"] = queries

        # SMTP
        r = await _ex.run([
            "tshark", "-r", pcap_path, "-Y", "smtp",
            "-T", "fields", "-e", "smtp.req.command", "-e", "smtp.req.parameter"
        ], timeout=30)
        if r.get("stdout"):
            smtp = r["stdout"][:500]
            findings["smtp"] = smtp

        return {"pcap": pcap_path, "findings": findings, "total_protocols": len(findings)}

    @mcp.tool()
    async def pcap_protocols(pcap_path: str) -> dict:
        """
        Get protocol hierarchy and conversation list for a PCAP — overview of what's
        actually in the capture (HTTP, DNS, SMB, FTP, Telnet, SMTP, ICMP, ARP, etc.).
        Use this BEFORE pcap_extract to know what protocols to look for.
        pcap_path: path to .pcap or .pcapng file
        Returns: protocol breakdown by packet count + endpoint conversations
        """
        if not os.path.exists(pcap_path):
            return {"error": f"File not found: {pcap_path}"}

        # Protocol hierarchy stats
        proto = await _ex.run([
            "tshark", "-r", pcap_path, "-q", "-z", "io,phs"
        ], timeout=30)

        # Endpoint conversations (IP)
        conv = await _ex.run([
            "tshark", "-r", pcap_path, "-q", "-z", "conv,ip"
        ], timeout=30)

        # Total packet count
        count = await _ex.run([
            "capinfos", "-c", "-T", "-r", pcap_path
        ], timeout=15)

        return {
            "pcap": pcap_path,
            "protocol_hierarchy": proto.get("stdout", "")[:5000],
            "ip_conversations": conv.get("stdout", "")[:3000],
            "info": count.get("stdout", "")[:500],
        }

    @mcp.tool()
    async def tshark_query(
        pcap_path: str,
        display_filter: str = "",
        fields: str = "",
        max_lines: int = 200,
    ) -> dict:
        """
        Run an arbitrary tshark query on a PCAP file.
        pcap_path: path to PCAP file
        display_filter: Wireshark display filter e.g. 'http.request', 'tcp.port==21',
                        'smb', 'dns.qry.name', 'frame.number == 42'
        fields: comma-separated tshark fields to extract e.g.
                'ip.src,ip.dst,tcp.port,http.request.uri'
        max_lines: max output lines (default 200)
        """
        if not os.path.exists(pcap_path):
            return {"error": f"File not found: {pcap_path}"}

        cmd = ["tshark", "-r", pcap_path]
        if display_filter:
            cmd += ["-Y", display_filter]
        if fields:
            cmd += ["-T", "fields"]
            for f in fields.split(","):
                cmd += ["-e", f.strip()]

        result = await _ex.run(cmd, timeout=60)
        if result.get("stdout"):
            lines = result["stdout"].splitlines()[:max_lines]
            result["lines"] = lines
            result["line_count"] = len(lines)
            result["truncated"] = len(result["stdout"].splitlines()) > max_lines
            del result["stdout"]
        return result
