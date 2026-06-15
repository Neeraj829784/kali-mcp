import asyncio
import json
import logging
import os
import signal
import tempfile
import uuid
from datetime import datetime, timezone, timedelta

import aiosqlite

from config import JOBS_DB_PATH, ARTIFACTS_DIR
from tools.base import ToolExecutor, _kill_pgroup

_log = logging.getLogger(__name__)

# Retry configuration
# Only transient failures are retried (timeout, process crash).
# Permanent failures (binary not found, scope error) are NOT retried.
_MAX_RETRIES = 2
_RETRY_BASE_DELAY = 2.0   # seconds — doubles each attempt (2s, 4s)

_executor = ToolExecutor()
# job_id -> (asyncio.Task, pid)
_running: dict[str, tuple[asyncio.Task, list[int]]] = {}


class JobManager:
    async def init_db(self):
        async with aiosqlite.connect(JOBS_DB_PATH, timeout=30) as db:
            await db.execute("PRAGMA journal_mode=WAL")
            await db.execute("PRAGMA busy_timeout=30000")
            await db.execute("""
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    tool TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    output_file TEXT,
                    result TEXT,
                    error TEXT,
                    retry_count INTEGER NOT NULL DEFAULT 0
                )
            """)
            # Migrations for older schemas
            try:
                await db.execute("ALTER TABLE jobs ADD COLUMN output_file TEXT")
            except Exception:
                pass  # column already exists — expected on upgrade
            try:
                await db.execute("ALTER TABLE jobs ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0")
            except Exception:
                pass  # column already exists — expected on upgrade
            await db.commit()
        await self._reap_ghost_jobs()
        await self._purge_old_jobs()

    async def _reap_ghost_jobs(self):
        """Mark any 'running' jobs left from a previous session as 'failed'."""
        async with aiosqlite.connect(JOBS_DB_PATH, timeout=30) as db:
            await db.execute(
                "UPDATE jobs SET status='failed', error='Server restarted while job was running' "
                "WHERE status IN ('running', 'pending')"
            )
            await db.commit()

    async def _purge_old_jobs(self, days: int = 7):
        """Delete jobs older than `days` days."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        async with aiosqlite.connect(JOBS_DB_PATH, timeout=30) as db:
            # Clean up output files first
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT output_file FROM jobs WHERE created_at < ?", (cutoff,)
            ) as cur:
                rows = await cur.fetchall()
            for row in rows:
                if row["output_file"] and os.path.exists(row["output_file"]):
                    os.unlink(row["output_file"])
            await db.execute("DELETE FROM jobs WHERE created_at < ?", (cutoff,))
            await db.commit()

    async def create_job(self, tool: str, cmd: list[str], timeout: int) -> str:
        job_id = str(uuid.uuid4())[:8]
        now = datetime.now(timezone.utc).isoformat()
        out_file = os.path.join(ARTIFACTS_DIR, f"{tool}_{job_id}.txt")
        async with aiosqlite.connect(JOBS_DB_PATH, timeout=30) as db:
            await db.execute(
                "INSERT INTO jobs (id, tool, status, created_at, output_file) VALUES (?, ?, 'pending', ?, ?)",
                (job_id, tool, now, out_file),
            )
            await db.commit()
        pid_holder: list[int] = []
        task = asyncio.create_task(self._run_job(job_id, tool, cmd, timeout, out_file, pid_holder))
        _running[job_id] = (task, pid_holder)
        return job_id

    async def run_and_wait(self, tool: str, cmd: list[str], timeout: int) -> dict:
        """
        Create a job, run it, and return the result when done.
        Automatically extracts normalized findings and suggested next steps.
        """
        job_id = str(uuid.uuid4())[:8]
        now = datetime.now(timezone.utc).isoformat()
        out_file = os.path.join(ARTIFACTS_DIR, f"{tool}_{job_id}.txt")
        async with aiosqlite.connect(JOBS_DB_PATH, timeout=30) as db:
            await db.execute(
                "INSERT INTO jobs (id, tool, status, created_at, output_file) VALUES (?, ?, 'pending', ?, ?)",
                (job_id, tool, now, out_file),
            )
            await db.commit()
        pid_holder: list[int] = []
        task = asyncio.create_task(self._run_job(job_id, tool, cmd, timeout, out_file, pid_holder))
        _running[job_id] = (task, pid_holder)
        await task
        result = await self.get_job(job_id)

        # Auto-extract findings and suggestions
        output = result.get("output", "")
        if output:
            try:
                from findings import extract_findings
                from suggest import suggest_next
                import engagement as eng_mod
                # Best-effort target extraction from cmd — skip flag values and file paths
                target = next((a for a in reversed(cmd)
                               if a and not a.startswith("-") and a != cmd[0]
                               and not os.path.exists(a) and "/" not in a), "")
                findings = extract_findings(tool, output, target)
                if findings:
                    # Run soft-404 / wildcard verification on web path findings
                    if tool in ("gobuster_dir", "gobuster_vhost", "ffuf"):
                        from findings import verify_web_findings
                        base_url = next(
                            (a for a in cmd if a.startswith("http")), ""
                        )
                        if base_url:
                            findings = await verify_web_findings(findings, base_url)
                    result["findings"] = findings
                    result["findings_count"] = len(findings)
                    # Auto-tag to active engagement + webhook alert for high/critical
                    from webhook import notify as _webhook_notify
                    active_eng = eng_mod.get_active()
                    eng_name = active_eng["name"] if active_eng else ""
                    for f in findings:
                        await eng_mod.tag_finding(f, job_id)
                        if f.get("severity") in ("critical", "high"):
                            asyncio.create_task(_webhook_notify(f, eng_name))
                suggestions = suggest_next(tool, output, target)
                if suggestions:
                    result["suggested_next"] = suggestions
            except Exception:
                _log.debug("Finding extraction failed for tool=%s job=%s",
                           tool, job_id, exc_info=True)

        return result

    async def _run_job(self, job_id: str, tool: str, cmd: list[str], timeout: int, out_file: str, pid_holder: list[int]):
        await self._update(job_id, status="running")

        last_result: dict = {}
        for attempt in range(1 + _MAX_RETRIES):
            if attempt > 0:
                # Exponential backoff: 2s, 4s
                delay = _RETRY_BASE_DELAY * (2 ** (attempt - 1))
                await asyncio.sleep(delay)
                await self._update(job_id, status="running",
                                   error=f"Retrying (attempt {attempt + 1})...",
                                   retry_count=attempt)

            # Fresh output file per attempt so partial output from a failed
            # attempt doesn't pollute the final result
            attempt_out = out_file if attempt == 0 else f"{out_file}.retry{attempt}"
            pid_holder.clear()

            last_result = await _executor.run(
                cmd, timeout,
                output_file=attempt_out,
                pid_holder=pid_holder,
                tool_name=tool,
            )

            timed_out = last_result.get("timed_out", False)
            is_permanent_error = (
                "Tool not found" in last_result.get("error", "")
                or "not in scope" in last_result.get("error", "")
            )

            # Success or permanent error — stop retrying
            if not timed_out and not (
                "error" in last_result and last_result.get("return_code") == -1
            ):
                # Copy retry attempt output to canonical out_file path
                if attempt > 0 and os.path.exists(attempt_out):
                    import shutil
                    shutil.move(attempt_out, out_file)
                break

            if is_permanent_error:
                break  # no point retrying "binary not found"

            # Clean up partial retry file before next attempt
            if attempt > 0 and os.path.exists(attempt_out):
                try:
                    os.unlink(attempt_out)
                except OSError:
                    pass

        completed_at = datetime.now(timezone.utc).isoformat()
        retry_count = await self._get_retry_count(job_id)

        # Clean up any leftover retry temp files from failed attempts
        for i in range(1, _MAX_RETRIES + 1):
            retry_file = f"{out_file}.retry{i}"
            if os.path.exists(retry_file):
                try:
                    os.unlink(retry_file)
                except OSError:
                    pass

        if last_result.get("timed_out"):
            await self._update(job_id, status="failed",
                               error=f"Timed out after {timeout}s (tried {retry_count + 1}x)",
                               completed_at=completed_at)
        elif "error" in last_result and last_result.get("return_code") == -1:
            await self._update(job_id, status="failed",
                               error=last_result["error"],
                               completed_at=completed_at)
        else:
            await self._update(job_id, status="completed",
                               result=json.dumps({"return_code": last_result.get("return_code")}),
                               error=None,
                               completed_at=completed_at)
        _running.pop(job_id, None)

    async def _get_retry_count(self, job_id: str) -> int:
        async with aiosqlite.connect(JOBS_DB_PATH, timeout=30) as db:
            async with db.execute(
                "SELECT retry_count FROM jobs WHERE id = ?", (job_id,)
            ) as cur:
                row = await cur.fetchone()
        return row[0] if row else 0

    async def _update(self, job_id: str, **fields):
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [job_id]
        async with aiosqlite.connect(JOBS_DB_PATH, timeout=30) as db:
            await db.execute(f"UPDATE jobs SET {set_clause} WHERE id = ?", values)
            await db.commit()

    async def get_job(self, job_id: str, tail: int = 0) -> dict:
        async with aiosqlite.connect(JOBS_DB_PATH, timeout=30) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)) as cur:
                row = await cur.fetchone()
        if not row:
            return {"error": f"Job {job_id} not found"}
        d = dict(row)
        if d.get("result"):
            d["result"] = json.loads(d["result"])
        # Read output from file (supports partial reads for running jobs)
        out_file = d.get("output_file")
        if out_file and os.path.exists(out_file):
            with open(out_file, "r", errors="replace") as f:
                content = f.read()
            if tail > 0:
                lines = content.splitlines()
                d["output"] = "\n".join(lines[-tail:])
            else:
                d["output"] = content
        return d

    async def list_jobs(self, limit: int = 20) -> list:
        async with aiosqlite.connect(JOBS_DB_PATH, timeout=30) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT id, tool, status, created_at, completed_at, retry_count FROM jobs "
                "ORDER BY created_at DESC LIMIT ?", (limit,)
            ) as cur:
                rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def cancel_job(self, job_id: str) -> bool:
        entry = _running.get(job_id)
        if not entry:
            return False
        task, pid_holder = entry
        # Kill entire process group
        if pid_holder:
            _kill_pgroup(pid_holder[0])
        if not task.done():
            task.cancel()
        await self._update(job_id, status="cancelled",
                           completed_at=datetime.now(timezone.utc).isoformat())
        _running.pop(job_id, None)
        return True
