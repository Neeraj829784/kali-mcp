"""
Program scope & policy engine — named bug-bounty/pentest programs with in/out-of-scope.

This module sits on top of scope.py to provide:
  - Named programs (e.g. 'Acme-BugBounty-2026', 'ClientX-Pentest-Q3')
  - In-scope rules: explicit allowlist of targets/hosts
  - Out-of-scope rules: explicit denylist (overrides allowlist)
  - Rules of engagement: max_findings, duration_hours, reporting_format, etc.
  - Approval grants: who can activate/modify the program

All data persists in PROGRAMS_DB_PATH (git-ignored sqlite DB).
"""
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import aiosqlite

from config import PROGRAMS_DB_PATH

# Module-level active program (in-memory, reset on restart)
_active_program: dict | None = None

_SCHEMA = """
    CREATE TABLE IF NOT EXISTS programs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        client TEXT,
        in_scope TEXT DEFAULT '[]',
        out_of_scope TEXT DEFAULT '[]',
        rules TEXT DEFAULT '{}',
        approvers TEXT DEFAULT '[]',
        status TEXT DEFAULT 'draft',
        created_at TEXT NOT NULL,
        updated_at TEXT
    );
    CREATE TABLE IF NOT EXISTS app_state (
        key TEXT PRIMARY KEY,
        value TEXT
    );
"""


@asynccontextmanager
async def _get_db():
    async with aiosqlite.connect(PROGRAMS_DB_PATH, timeout=30) as db:
        db.row_factory = aiosqlite.Row
        try:
            yield db
        finally:
            await db.close()


async def init_db() -> None:
    """Create tables. Called once at server startup."""
    async with _get_db() as db:
        await db.executescript(_SCHEMA)
        await db.commit()
    await _restore_active()


async def _persist_active_id(prog_id: int | None) -> None:
    async with _get_db() as db:
        if prog_id is None:
            await db.execute("DELETE FROM app_state WHERE key='active_program_id'")
        else:
            await db.execute(
                "INSERT INTO app_state (key, value) VALUES ('active_program_id', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(prog_id),),
            )
        await db.commit()


async def _restore_active() -> None:
    global _active_program
    async with _get_db() as db:
        async with db.execute(
            "SELECT value FROM app_state WHERE key='active_program_id'"
        ) as cur:
            row = await cur.fetchone()
        if not row or row[0] is None:
            return
        try:
            prog_id = int(row[0])
        except (TypeError, ValueError):
            return
        async with db.execute(
            "SELECT * FROM programs WHERE id=?", (prog_id,)
        ) as cur:
            row = await cur.fetchone()
    if not row:
        await _persist_active_id(None)
        return
    try:
        in_scope = json.loads(row["in_scope"]) if row["in_scope"] else []
        out_of_scope = json.loads(row["out_of_scope"]) if row["out_of_scope"] else []
        rules = json.loads(row["rules"]) if row["rules"] else {}
        approvers = json.loads(row["approvers"]) if row["approvers"] else []
    except (TypeError, ValueError):
        in_scope = []
        out_of_scope = []
        rules = {}
        approvers = []
    global scope
    import scope as scope_mod
    scope_mod.set_scope(in_scope)
    scope_mod.set_denylist(out_of_scope)
    _active_program = {
        "id": row["id"],
        "name": row["name"],
        "client": row["client"],
        "in_scope": in_scope,
        "out_of_scope": out_of_scope,
        "rules": rules,
        "approvers": approvers,
        "status": row["status"],
    }


def get_active() -> dict | None:
    return _active_program


def _register(mcp, job_mgr):

    @mcp.tool()
    async def program_scope_start(
        name: str,
        in_scope: list[str],
        out_of_scope: list[str] | None = None,
        client: str = "",
        rules: dict | None = None,
        approvers: list[str] | None = None,
    ) -> dict:
        """
        Start or update a named program scope.

        name: program name e.g. 'ClientX-WebApp-2026'
        in_scope: list of allowed targets e.g. ['10.10.10.0/24', 'example.com']
        out_of_scope: list of explicitly blocked targets (e.g. ['10.10.10.254'])
        client: optional client name
        rules: dict of rules of engagement: max_findings, duration_hours, reporting_format
        approvers: list of approved agents/humans who can modify/activate this program
        """
        global _active_program
        out_of_scope = out_of_scope or []
        rules = rules or {}
        approvers = approvers or []
        from scope import set_scope, set_denylist
        set_scope(in_scope)
        set_denylist(out_of_scope)

        now = datetime.now(timezone.utc).isoformat()
        async with _get_db() as db:
            await db.execute(
                "INSERT OR IGNORE INTO programs "
                "(name,client,in_scope,out_of_scope,rules,approvers,status,created_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (name, client, json.dumps(in_scope), json.dumps(out_of_scope),
                 json.dumps(rules), json.dumps(approvers), "active", now),
            )
            await db.execute(
                "UPDATE programs SET client=?,in_scope=?,out_of_scope=?,rules=?,"
                "approvers=?,status='active',updated_at=? WHERE name=?",
                (client, json.dumps(in_scope), json.dumps(out_of_scope),
                 json.dumps(rules), json.dumps(approvers), now, name),
            )
            async with db.execute("SELECT id FROM programs WHERE name=?", (name,)) as cur:
                row = await cur.fetchone()
            prog_id = row[0]
            await db.commit()

        _active_program = {
            "id": prog_id,
            "name": name,
            "client": client,
            "in_scope": in_scope,
            "out_of_scope": out_of_scope,
            "rules": rules,
            "approvers": approvers,
            "status": "active",
        }
        await _persist_active_id(prog_id)
        return {
            "program": name,
            "status": "started",
            "in_scope": in_scope,
            "out_of_scope": out_of_scope,
            "rules": rules,
        }

    @mcp.tool()
    async def program_scope_status() -> dict:
        """Show the current active program scope."""
        global _active_program
        if not _active_program:
            return {"active": False, "hint": "Start one with program_scope_start()"}
        return {"active": True, **_active_program}

    @mcp.tool()
    async def program_scope_list() -> list:
        """List all programs (draft/active/ended)."""
        async with _get_db() as db:
            async with db.execute("SELECT * FROM programs ORDER BY created_at DESC") as cur:
                rows = await cur.fetchall()
        return [dict(r) for r in rows]

    @mcp.tool()
    async def program_scope_end() -> dict:
        """Close the current program scope and clear scope restrictions."""
        global _active_program
        if not _active_program:
            return {"error": "No active program"}
        from scope import clear_scope, clear_denylist
        async with _get_db() as db:
            await db.execute(
                "UPDATE programs SET status='ended', updated_at=? WHERE id=?",
                (datetime.now(timezone.utc).isoformat(), _active_program["id"]),
            )
            await db.commit()
        name = _active_program["name"]
        _active_program = None
        await _persist_active_id(None)
        clear_scope()
        clear_denylist()
        return {"program": name, "status": "ended", "scope": "cleared"}

    @mcp.tool()
    async def program_scope_add_targets(targets: list[str]) -> dict:
        """Add targets to the current program's in-scope list."""
        global _active_program
        if not _active_program:
            return {"error": "No active program. Run program_scope_start() first."}
        from scope import set_scope as _set_scope
        new_targets = [t for t in targets if t not in _active_program["in_scope"]]
        if not new_targets:
            return {"added": [], "in_scope": _active_program["in_scope"]}
        updated = _active_program["in_scope"] + new_targets
        _active_program["in_scope"] = updated
        _set_scope(updated)
        async with _get_db() as db:
            await db.execute(
                "UPDATE programs SET in_scope=?, updated_at=? WHERE id=?",
                (json.dumps(updated), datetime.now(timezone.utc).isoformat(),
                 _active_program["id"]),
            )
            await db.commit()
        return {"added": new_targets, "in_scope": updated}

    @mcp.tool()
    async def program_scope_remove_targets(targets: list[str]) -> dict:
        """Remove targets from the current program's in-scope list."""
        global _active_program
        if not _active_program:
            return {"error": "No active program"}
        from scope import set_scope as _set_scope
        old = _active_program["in_scope"]
        updated = [t for t in old if t not in targets]
        if len(updated) == len(old):
            return {"removed": [], "in_scope": old}
        _active_program["in_scope"] = updated
        _set_scope(updated)
        async with _get_db() as db:
            await db.execute(
                "UPDATE programs SET in_scope=?, updated_at=? WHERE id=?",
                (json.dumps(updated), datetime.now(timezone.utc).isoformat(),
                 _active_program["id"]),
            )
            await db.commit()
        return {"removed": targets, "in_scope": updated}

    @mcp.tool()
    async def program_scope_out_of_scope(targets: list[str]) -> dict:
        """Add targets to the out-of-scope (deny) list."""
        global _active_program
        if not _active_program:
            return {"error": "No active program"}
        from scope import set_denylist as _set_denylist
        new_targets = [t for t in targets if t not in _active_program["out_of_scope"]]
        if not new_targets:
            return {"added": [], "out_of_scope": _active_program["out_of_scope"]}
        updated = _active_program["out_of_scope"] + new_targets
        _active_program["out_of_scope"] = updated
        _set_denylist(updated)
        async with _get_db() as db:
            await db.execute(
                "UPDATE programs SET out_of_scope=?, updated_at=? WHERE id=?",
                (json.dumps(updated), datetime.now(timezone.utc).isoformat(),
                 _active_program["id"]),
            )
            await db.commit()
        return {"added": new_targets, "out_of_scope": updated}

    @mcp.tool()
    async def program_scope_allow(target: str) -> dict:
        """Explicitly allow a target that is otherwise out of scope."""
        global _active_program
        if not _active_program:
            return {"error": "No active program"}
        from scope import set_scope as _set_scope
        # Add to in_scope if not present
        if target not in _active_program["in_scope"]:
            updated = _active_program["in_scope"] + [target]
            _active_program["in_scope"] = updated
            _set_scope(updated)
            async with _get_db() as db:
                await db.execute(
                    "UPDATE programs SET in_scope=?, updated_at=? WHERE id=?",
                    (json.dumps(updated), datetime.now(timezone.utc).isoformat(),
                     _active_program["id"]),
                )
                await db.commit()
        return {"status": "allowed", "target": target, "in_scope": _active_program["in_scope"]}

    @mcp.tool()
    async def program_scope_deny(target: str) -> dict:
        """Explicitly deny a target, blocking it even if in in_scope."""
        global _active_program
        if not _active_program:
            return {"error": "No active program"}
        from scope import set_denylist as _set_denylist
        if target not in _active_program["out_of_scope"]:
            updated = _active_program["out_of_scope"] + [target]
            _active_program["out_of_scope"] = updated
            _set_denylist(updated)
            async with _get_db() as db:
                await db.execute(
                    "UPDATE programs SET out_of_scope=?, updated_at=? WHERE id=?",
                    (json.dumps(updated), datetime.now(timezone.utc).isoformat(),
                     _active_program["id"]),
                )
                await db.commit()
        return {"status": "denied", "target": target, "out_of_scope": _active_program["out_of_scope"]}
