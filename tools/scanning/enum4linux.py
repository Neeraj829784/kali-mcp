from config import TOOL_TIMEOUTS
from scope import check_scope


def _register(mcp, job_mgr):

    @mcp.tool()
    async def enum4linux_scan(
        target: str,
        username: str = "",
        password: str = "",
    ) -> dict:
        """
        Full SMB/NetBIOS enumeration using enum4linux (-a covers all).
        Enumerates: users, shares, groups, password policy, OS info, printers.
        target: IP address of Windows/Samba host
        username: optional username for authenticated scan
        password: optional password for authenticated scan
        """
        check_scope(target)
        # -a is the correct flag (all enumeration). Individual flags are NOT
        # additive with -a and cause unpredictable output.
        cmd = ["enum4linux", "-a"]
        if username:
            cmd += ["-u", username]
        if password:
            cmd += ["-p", password]
        cmd.append(target)
        return await job_mgr.run_and_wait("enum4linux", cmd, TOOL_TIMEOUTS["enum4linux"])
