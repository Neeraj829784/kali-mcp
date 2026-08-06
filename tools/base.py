import asyncio
import os
import shutil
import signal
import tempfile
import time

from config import RATE_LIMITS, MAX_CONCURRENT_TOOLS

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

# Per-tool rate limiting state: tool_name → monotonic timestamp of last launch
# Keyed by tool name (matching RATE_LIMITS keys in config.py).
# asyncio.Lock per tool prevents concurrent launches from racing past the gate.
_rate_last: dict[str, float] = {}
_rate_locks: dict[str, asyncio.Lock] = {}


def _get_rate_lock(tool_name: str) -> asyncio.Lock:
    """Return (creating if needed) the per-tool asyncio.Lock for rate gating."""
    if tool_name not in _rate_locks:
        _rate_locks[tool_name] = asyncio.Lock()
    return _rate_locks[tool_name]


# Global cap on concurrently-running tool subprocesses. Created lazily because a
# Semaphore must bind to the running event loop.
_concurrency_sem: asyncio.Semaphore | None = None


def _get_concurrency_sem() -> asyncio.Semaphore:
    global _concurrency_sem
    if _concurrency_sem is None:
        _concurrency_sem = asyncio.Semaphore(MAX_CONCURRENT_TOOLS)
    return _concurrency_sem


async def _rate_gate(tool_name: str) -> None:
    """
    Enforce RATE_LIMITS[tool_name] (requests/sec).
    If the limit is 0 or the tool is not listed, returns immediately.
    Uses a per-tool async lock so parallel callers queue up rather than
    all racing through together.
    """
    rps = RATE_LIMITS.get(tool_name, 0)
    if not rps:
        return  # no limit configured

    interval = 1.0 / rps
    lock = _get_rate_lock(tool_name)

    async with lock:
        now = time.monotonic()
        last = _rate_last.get(tool_name, 0.0)
        wait = interval - (now - last)
        if wait > 0:
            await asyncio.sleep(wait)
        _rate_last[tool_name] = time.monotonic()


def guard_token(value: str, field: str = "argument") -> None:
    """Reject a value that could be mis-parsed as a command-line flag.

    Everything here is executed via exec() with an argv list, so classic shell
    injection is impossible. The residual risk is *argument injection*: a value
    like '-oN/tmp/x' or '--script=evil' landing in a positional argv slot and
    being interpreted as a flag by the target tool. Callers pass user/LLM-supplied
    positional values (targets, URLs, domains, query terms) through this guard.

    Raises ValueError if `value` is a string beginning with '-'.
    """
    if isinstance(value, str) and value.startswith("-"):
        raise ValueError(
            f"Refusing {field} that starts with '-' (possible argument injection): {value!r}"
        )


_SUDO_NONINTERACTIVE: bool | None = None


def can_sudo_noninteractive() -> bool:
    """Return True if passwordless sudo is available (`sudo -n true` succeeds).

    Cached after the first probe. Tools that rely on `sudo -n` (nmap -O, masscan)
    use this to fail loudly with an actionable hint instead of silently returning
    a 'sudo: a password is required' error buried in tool output.
    """
    global _SUDO_NONINTERACTIVE
    if _SUDO_NONINTERACTIVE is None:
        if os.geteuid() == 0:
            _SUDO_NONINTERACTIVE = True
        elif not shutil.which("sudo"):
            _SUDO_NONINTERACTIVE = False
        else:
            try:
                import subprocess
                r = subprocess.run(
                    ["sudo", "-n", "true"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=5,
                )
                _SUDO_NONINTERACTIVE = r.returncode == 0
            except Exception:
                _SUDO_NONINTERACTIVE = False
    return _SUDO_NONINTERACTIVE


def sudo_required_error(feature: str) -> dict:
    """Standard error payload when a raw-socket feature has no root/sudo access."""
    return {
        "error": f"{feature} requires root or passwordless sudo, and neither is available.",
        "hint": (
            "Run the server as root, or configure passwordless sudo for the "
            "relevant binary (e.g. an /etc/sudoers.d rule for nmap/masscan), or "
            "use a scan mode that does not need raw sockets (e.g. nmap scan_type='sT')."
        ),
        "return_code": -1,
    }


class ToolExecutor:
    async def run(
        self,
        cmd: list[str],
        timeout: int = 120,
        output_file: str = "",
        pid_holder: list[int] | None = None,
        tool_name: str = "",
    ) -> dict:
        """
        Run a command. Streams output to a temp file to avoid pipe deadlock and OOM.
        If output_file is given, output is written there instead.
        Process runs in its own session (setsid) so the whole process group
        can be killed on timeout or cancel.
        If pid_holder is provided, the child PID is appended to it so callers
        (e.g. JobManager.cancel_job) can kill the process group on demand.

        tool_name: optional logical name used for rate-limiting (e.g. 'nuclei',
                   'gobuster_dir'). Defaults to the binary name (cmd[0]) if not set.
        """
        binary = cmd[0]
        if not shutil.which(binary):
            hint = _INSTALL_HINTS.get(binary, f"install {binary} or check PATH")
            return {
                "error": f"Tool not found: {binary}",
                "hint": f"To fix: {hint}",
                "return_code": -1,
            }

        # ── Rate limiting ─────────────────────────────────────────────────────
        # Use explicit tool_name if provided, fall back to binary name so that
        # e.g. gobuster_dir and gobuster_dns get separate buckets.
        await _rate_gate(tool_name or binary)

        use_temp = not output_file
        if use_temp:
            fd, out_path = tempfile.mkstemp(prefix="kali-mcp-")
            os.close(fd)
        else:
            out_path = output_file

        try:
            # Global concurrency cap — bound simultaneously-running subprocesses.
            async with _get_concurrency_sem():
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
            import time as _t
            _t.sleep(2)
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        threading.Thread(target=force_kill, daemon=True).start()
    except ProcessLookupError:
        pass


def safe_save_path(save_to: str) -> str:
    """Resolve a user-supplied save_to path to an allowlisted directory.

    Allowed: artifacts dir, /tmp, /var/tmp. Raises ValueError otherwise.
    This blocks path traversal and writes to sensitive locations.
    """
    from config import ARTIFACTS_DIR
    artifacts = os.path.realpath(ARTIFACTS_DIR)
    candidate = (
        os.path.realpath(save_to)
        if os.path.isabs(save_to)
        else os.path.realpath(os.path.join(artifacts, save_to))
    )
    allowed = [artifacts, os.path.realpath("/tmp"), os.path.realpath("/var/tmp")]
    for root in allowed:
        try:
            if os.path.commonpath([root, candidate]) == root:
                return candidate
        except ValueError:
            continue
    raise ValueError(
        f"save_to must resolve inside {artifacts}, /tmp, or /var/tmp; "
        f"'{save_to}' resolves outside all of them."
    )
