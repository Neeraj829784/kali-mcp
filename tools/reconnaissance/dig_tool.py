from scope import check_scope
from tools.base import ToolExecutor, guard_token

_ex = ToolExecutor()


def _register(mcp, job_mgr):

    @mcp.tool()
    async def dig_lookup(
        domain: str,
        record_type: str = "A",
        dns_server: str = "",
        short: bool = False,
    ) -> dict:
        """
        DNS lookup using dig.
        domain: target domain (e.g. 'example.com')
        record_type: A, AAAA, MX, NS, TXT, CNAME, SOA, ANY
        dns_server: optional DNS server to query (e.g. '8.8.8.8')
        short: return short output only
        """
        check_scope(domain)
        try:
            guard_token(record_type, "record_type")
            if dns_server:
                guard_token(dns_server, "dns_server")
        except ValueError as e:
            return {"error": str(e), "return_code": -1}
        cmd = ["dig"]
        if dns_server:
            cmd += [f"@{dns_server}"]
        cmd += [domain, record_type]
        if short:
            cmd += ["+short"]
        return await _ex.run(cmd, timeout=30)

    @mcp.tool()
    async def dig_zone_transfer(domain: str, nameserver: str) -> dict:
        """
        Attempt DNS zone transfer (AXFR).
        domain: target domain
        nameserver: nameserver to request transfer from
        """
        check_scope(domain)
        return await _ex.run(["dig", f"@{nameserver}", domain, "AXFR"], timeout=30)
