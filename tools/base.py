import asyncio
import os
import shutil
import signal
import tempfile

# Map of common tools to install hints
_INSTALL_HINTS = {
    "nmap": "apt install nmap",
    "nikto": "apt install nikto",
    "sqlmap": "apt install sqlmap",
    "gobuster": "apt install gobuster",
    "hydra": "apt install hydra",
    "ffuf": "apt install ffuf",
    "subfinder": "apt install subfinder",
    "nuclei": "apt install nuclei",
    "amass": "apt install amass",
    "theHarvester": "apt install theharvester",
    "searchsploit": "apt install exploitdb",
    "wpscan": "apt install wpscan",
    "enum4linux": "apt install enum4linux",
    "smbclient": "apt install smbclient",
    "netcat": "apt install netcat-openbsd",
    "ncat": "apt install nmap (ncat ships with nmap)",
    "whois": "apt install whois",
    "dig": "apt install dnsutils",
    "msfconsole": "apt install metasploit-framework",
    "msfvenom": "apt install metasploit-framework",
    "sshpass": "apt install sshpass (or use key_file parameter instead)",
    "tshark": "apt install tshark",
    "ssh": "apt install openssh-client",
}


class ToolExecutor:
    async def run(self, cmd: list[str], timeout: int = 120, output_file: str = "",
                  pid_holder: list[int] | None = None) -> dict:
        """
        Run a command. Streams output to a temp file to avoid pipe deadlock and OOM.
        If output_file is given, output is written there instead.
        Process runs in its own session (setsid) so the whole process group
        can be killed on timeout or cancel.
        If pid_holder is provided, the child PID is appended to it so callers
        (e.g. JobManager.cancel_job) can kill the process group on demand.
        """
        binary = cmd[0]
        if not shutil.which(binary):
            hint = _INSTALL_HINTS.get(binary, f"install {binary} or check PATH")
            return {
                "error": f"Tool not found: {binary}",
                "hint": f"To fix: {hint}",
                "return_code": -1,
            }

        use_temp = not output_file
        if use_temp:
            fd, out_path = tempfile.mkstemp(prefix="kali-mcp-")
            os.close(fd)
        else:
            out_path = output_file

        try:
            with open(out_path, "wb") as out_fh:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=out_fh,
                    stderr=asyncio.subprocess.STDOUT,
                    # New session so we can kill the whole process group
                    preexec_fn=os.setsid,
                )

            # Expose the PID so cancel/timeout can kill the whole process group
            if pid_holder is not None:
                pid_holder.append(proc.pid)

            try:
                await asyncio.wait_for(proc.wait(), timeout=timeout)
                timed_out = False
            except asyncio.TimeoutError:
                _kill_pgroup(proc.pid)
                timed_out = True

            # Read output from file (safe — no OOM, no deadlock)
            with open(out_path, "r", errors="replace") as f:
                output = f.read()

            return {
                "stdout": output.strip(),
                "stderr": "",
                "return_code": proc.returncode if not timed_out else -1,
                "timed_out": timed_out,
                "output_file": out_path if not use_temp else None,
            }
        except Exception as e:
            return {"error": str(e), "return_code": -1}
        finally:
            if use_temp and os.path.exists(out_path):
                os.unlink(out_path)


def _kill_pgroup(pid: int):
    try:
        pgid = os.getpgid(pid)
        os.killpg(pgid, signal.SIGTERM)
        # Give 2s then SIGKILL
        import threading
        def force_kill():
            import time; time.sleep(2)
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        threading.Thread(target=force_kill, daemon=True).start()
    except ProcessLookupError:
        pass
