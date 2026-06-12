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
        return await _ex.run(cmd, timeout=30)
