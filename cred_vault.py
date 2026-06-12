"""Credential vault — stores discovered credentials across the engagement.

Secrets (password / hash) are encrypted at rest with Fernet (AES-128-CBC +
HMAC). The key is read from the KALI_MCP_VAULT_KEY env var if set, otherwise
from a local `vault.key` file (created 0600, git-ignored). Losing the key
makes existing ciphertext unrecoverable, so back it up with the engagement.
"""
import os
import sqlite3
from datetime import datetime, timezone

from cryptography.fernet import Fernet, InvalidToken

VAULT_DB = os.path.join(os.path.dirname(__file__), "vault.db")
KEY_FILE = os.path.join(os.path.dirname(__file__), "vault.key")

# Busy timeout (seconds) so concurrent writers wait instead of erroring out.
_SQLITE_TIMEOUT = 30


def _load_key() -> bytes:
    """Load the vault key from env or the local key file, creating one if absent."""
    env_key = os.environ.get("KALI_MCP_VAULT_KEY")
    if env_key:
        return env_key.encode()
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read().strip()
    # Generate a new key with restrictive permissions (owner read/write only).
    key = Fernet.generate_key()
    fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    return key


_fernet = Fernet(_load_key())


def _encrypt(value: str) -> str:
    """Encrypt a secret. Empty values pass through unchanged."""
    if not value:
        return value
    return _fernet.encrypt(value.encode()).decode()


def _decrypt(value: str) -> str:
    """
    Decrypt a stored secret. Falls back to returning the value as-is if it is
    not valid ciphertext (e.g. legacy plaintext rows written before encryption).
    """
    if not value:
        return value
    try:
        return _fernet.decrypt(value.encode()).decode()
    except (InvalidToken, ValueError):
        return value


def _conn():
    db = sqlite3.connect(VAULT_DB, timeout=_SQLITE_TIMEOUT)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=30000")
    db.execute("""
        CREATE TABLE IF NOT EXISTS creds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT NOT NULL,
            port INTEGER,
            service TEXT,
            username TEXT,
            password TEXT,
            hash TEXT,
            source_tool TEXT,
            notes TEXT,
            discovered_at TEXT NOT NULL
        )
    """)
    db.commit()
    return db


def _store(host, username, password, hash_, service, port, source_tool, notes):
    now = datetime.now(timezone.utc).isoformat()
    with _conn() as db:
        cur = db.execute(
            "INSERT INTO creds (host,port,service,username,password,hash,source_tool,notes,discovered_at) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (host, port or None, service, username,
             _encrypt(password), _encrypt(hash_), source_tool, notes, now),
        )
        return cur.lastrowid


def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["password"] = _decrypt(d.get("password", ""))
    d["hash"] = _decrypt(d.get("hash", ""))
    return d


def _register(mcp, job_mgr):

    @mcp.tool()
    async def creds_store(
        host: str,
        username: str,
        password: str = "",
        hash: str = "",
        service: str = "",
        port: int = 0,
        source_tool: str = "",
        notes: str = "",
    ) -> dict:
        """
        Store discovered credentials in the vault (passwords/hashes encrypted at rest).
        host: target host IP or hostname
        username: discovered username
        password: plaintext password (leave empty if only hash available)
        hash: password hash (e.g. NTLM, bcrypt)
        service: service type e.g. 'ssh', 'http', 'smb', 'ftp', 'mysql'
        port: service port
        source_tool: which tool found this (e.g. 'hydra', 'sqlmap', 'manual')
        notes: any additional context
        """
        import asyncio
        cred_id = await asyncio.to_thread(
            _store, host, username, password, hash, service, port, source_tool, notes
        )
        return {"id": cred_id, "stored": True, "host": host, "username": username,
                "service": service or "unknown"}

    @mcp.tool()
    async def creds_list(host: str = "", service: str = "") -> list:
        """
        List stored credentials, optionally filtered by host or service.
        host: filter by host IP/hostname (empty = all hosts)
        service: filter by service type e.g. 'ssh', 'http' (empty = all)
        Returns credentials with decrypted passwords/hashes for use in further attacks.
        """
        import asyncio

        def _query():
            query = "SELECT * FROM creds WHERE 1=1"
            params = []
            if host:
                query += " AND host = ?"
                params.append(host)
            if service:
                query += " AND service = ?"
                params.append(service)
            query += " ORDER BY discovered_at DESC"
            with _conn() as db:
                rows = db.execute(query, params).fetchall()
            return [_row_to_dict(r) for r in rows]

        return await asyncio.to_thread(_query)

    @mcp.tool()
    async def creds_use(host: str, service: str = "") -> dict:
        """
        Get the most recently discovered credential for a host/service.
        Use this before attacking a service to check if we already have valid creds.
        host: target host
        service: optional service filter e.g. 'ssh'
        Returns: best credential to try (decrypted), or empty if none found.
        """
        import asyncio

        def _query():
            query = "SELECT * FROM creds WHERE host = ?"
            params = [host]
            if service:
                query += " AND service = ?"
                params.append(service)
            query += " ORDER BY discovered_at DESC LIMIT 1"
            with _conn() as db:
                row = db.execute(query, params).fetchone()
            return row

        row = await asyncio.to_thread(_query)
        if not row:
            return {"found": False, "host": host, "hint": "No stored creds. Run hydra_bruteforce or check other hosts."}
        r = _row_to_dict(row)
        r["found"] = True
        return r

    @mcp.tool()
    async def creds_delete(cred_id: int) -> dict:
        """Delete a credential from the vault by its ID."""
        import asyncio

        def _delete():
            with _conn() as db:
                db.execute("DELETE FROM creds WHERE id = ?", (cred_id,))

        await asyncio.to_thread(_delete)
        return {"deleted": True, "id": cred_id}
