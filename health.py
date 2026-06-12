"""Health check / preflight tool — verify all binaries are installed before committing to a workflow."""
import os
import shutil

# All tools the MCP server depends on
_REQUIRED_BINARIES = {
    "reconnaissance": ["nmap", "whois", "dig", "subfinder", "theHarvester", "amass"],
    "scanning": ["nikto", "gobuster", "enum4linux", "smbclient", "ffuf"],
    "vulnerability": ["searchsploit", "nuclei", "wpscan"],
    "exploitation": ["sqlmap", "hydra", "msfconsole", "msfvenom", "netcat", "ssh"],
    "analysis": ["tshark"],
}

_OPTIONAL_BINARIES = ["sshpass", "ncat"]

_WORDLIST_PATHS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/rockyou.txt",
]


def _register(mcp, job_mgr):

    @mcp.tool()
    async def server_health() -> dict:
        """
        Preflight check — verifies all tool binaries, Python deps, and wordlists.
        Run this at the start of an engagement to avoid surprises mid-workflow.
        Returns: status per category, missing tools with install hints, available wordlists.
        """
        results: dict = {"ok": [], "missing": [], "categories": {}}

        for category, binaries in _REQUIRED_BINARIES.items():
            cat_status = {"installed": [], "missing": []}
            for b in binaries:
                if shutil.which(b):
                    cat_status["installed"].append(b)
                    results["ok"].append(b)
                else:
                    cat_status["missing"].append(b)
                    results["missing"].append(b)
            results["categories"][category] = cat_status

        # Optional tools
        results["optional"] = {
            b: "installed" if shutil.which(b) else "missing"
            for b in _OPTIONAL_BINARIES
        }

        # Wordlists
        results["wordlists"] = {
            path: os.path.exists(path) for path in _WORDLIST_PATHS
        }

        # Python deps
        py_deps = {}
        for mod in ["paramiko", "httpx", "aiosqlite", "mcp"]:
            try:
                __import__(mod)
                py_deps[mod] = "installed"
            except ImportError:
                py_deps[mod] = "missing"
        results["python_deps"] = py_deps

        # Privilege check
        results["running_as_root"] = os.geteuid() == 0
        if not results["running_as_root"]:
            results["root_note"] = "nmap -sS, -O, and raw socket scans require root. Use sudo or scan_type='sT'."

        # Summary
        results["summary"] = (
            f"{len(results['ok'])} tools installed, "
            f"{len(results['missing'])} missing"
        )
        results["overall_status"] = "healthy" if not results["missing"] else "degraded"

        return results

    @mcp.tool()
    async def check_binary(name: str) -> dict:
        """
        Check if a specific binary is installed and where it is.
        name: binary name e.g. 'nmap', 'sshpass', 'msfconsole'
        """
        path = shutil.which(name)
        return {
            "binary": name,
            "installed": path is not None,
            "path": path,
        }
