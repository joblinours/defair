"""Profile runs — ``PRUN-NNN``: prepare the evidence, execute a profile's DAG.

Lifecycle: ``pending`` → ``running`` → ``completed`` | ``completed_with_errors``
| ``failed`` | ``cancelled`` (``cancelling`` in between when asked to stop).

A run executes in a detached worker process (``defair run worker``) so a
long profile never blocks the CLI or an MCP call; its state lives in the
``profile_runs`` table and in ``<workspace>/runs/PRUN-NNN/run.json``, written
after every step and always at the end — even when the run fails.

Secrets (archive password, key passphrase) reach the worker through a 0600
file in /tmp that the worker deletes as soon as it has read it; they are
never stored, logged, written to run.json or put on a command line.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import aiosqlite
import structlog

from defair.database import db_lock
from defair.orchestrator.dag import StepResult, execute
from defair.orchestrator.profile import ENGINES, auto_profile, load_profile
from defair.orchestrator.steps import StepContext, record_outputs, run_step

log = structlog.get_logger(component="orchestrator.runs")

ACTIVE = ("pending", "running", "cancelling")
SECRET_ENV = ("DEFAIR_EVIDENCE_PASSWORD", "DEFAIR_KEY_PASSPHRASE")


def workspace() -> Path:
    return Path(os.environ.get("DEFAIR_WORKSPACE", "/workspace"))


def run_dir(run_number: str) -> Path:
    return workspace() / "runs" / run_number


# ---------------------------------------------------------------------------
# Rows
# ---------------------------------------------------------------------------


def _row_to_dict(row) -> dict:
    data = dict(row)
    data["params"] = json.loads(data.get("params") or "{}")
    data["steps"] = json.loads(data.get("steps") or "[]")
    return data


async def get_run(conn: aiosqlite.Connection, run: str) -> dict:
    cursor = await conn.execute(
        "SELECT * FROM profile_runs WHERE id = ? OR run_number = ?", (run, run)
    )
    row = await cursor.fetchone()
    if row is None:
        raise ValueError(f"Profile run not found: {run}")
    return _row_to_dict(row)


async def list_runs(conn: aiosqlite.Connection, case_id: str | None = None) -> list[dict]:
    if case_id:
        from defair.services.case_service import resolve_case_id

        case_id = await resolve_case_id(conn, case_id)
        cursor = await conn.execute(
            "SELECT * FROM profile_runs WHERE case_id = ? ORDER BY created_at DESC", (case_id,)
        )
    else:
        cursor = await conn.execute("SELECT * FROM profile_runs ORDER BY created_at DESC")
    return [_summary(_row_to_dict(r)) for r in await cursor.fetchall()]


def _summary(run: dict) -> dict:
    steps = run["steps"]
    counts: dict[str, int] = {}
    for step in steps:
        counts[step["status"]] = counts.get(step["status"], 0) + 1
    return {
        "run_number": run["run_number"],
        "profile": run["profile"],
        "engine": run["engine"],
        "status": run["status"],
        "evidence_id": run["evidence_id"],
        "steps": counts,
        "created_at": run["created_at"],
        "started_at": run["started_at"],
        "completed_at": run["completed_at"],
        "error": run["error"],
        "manifest": run["manifest_path"],
    }


async def _update(conn: aiosqlite.Connection, run_id: str, **fields) -> None:
    if not fields:
        return
    for key in ("params", "steps"):
        if key in fields:
            fields[key] = json.dumps(fields[key], default=str)
    assignments = ", ".join(f"{k} = ?" for k in fields)
    await conn.execute(f"UPDATE profile_runs SET {assignments} WHERE id = ?",
                       (*fields.values(), run_id))
    await conn.commit()


async def create_run(
    conn: aiosqlite.Connection,
    case_id: str,
    evidence_id: str,
    profile: str,
    engine: str = "auto",
    params: dict | None = None,
) -> dict:
    """Register a pending profile run."""
    from defair.services.case_service import resolve_case_id
    from defair.services.evidence_service import get_evidence

    if engine not in ENGINES:
        raise ValueError(f"Unknown engine '{engine}'. Use one of: {', '.join(ENGINES)}")
    if profile != "auto":
        load_profile(profile)  # validates the name
    case_uuid = await resolve_case_id(conn, case_id)
    evidence = await get_evidence(conn, evidence_id)
    if evidence is None:
        raise ValueError(f"Evidence not found: {evidence_id}")

    async with db_lock(conn):
        cursor = await conn.execute(
            "SELECT MAX(CAST(SUBSTR(run_number, 6) AS INTEGER)) FROM profile_runs"
        )
        seq = ((await cursor.fetchone())[0] or 0) + 1
        run = {
            "id": uuid4().hex,
            "run_number": f"PRUN-{seq:03d}",
            "case_id": case_uuid,
            "evidence_id": evidence.id,
            "profile": profile,
            "engine": engine,
        }
        await conn.execute(
            """INSERT INTO profile_runs
            (id, run_number, case_id, evidence_id, profile, engine, status, params, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)""",
            (*run.values(), json.dumps(params or {}), datetime.now(UTC).isoformat()),
        )
        await conn.commit()
    return await get_run(conn, run["id"])


# ---------------------------------------------------------------------------
# Liveness / cancel
# ---------------------------------------------------------------------------


def is_alive(pid: int | None) -> bool:
    if not pid:
        return False
    stat = Path(f"/proc/{pid}/stat")
    if stat.exists():
        try:
            return stat.read_text().split(") ", 1)[1][0] != "Z"  # zombie = dead
        except (OSError, IndexError):
            return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


async def run_status(conn: aiosqlite.Connection, run: str) -> dict:
    """Current state; a run whose worker died is marked failed."""
    data = await get_run(conn, run)
    if data["status"] in ("running", "cancelling") and not is_alive(data["pid"]):
        status = "cancelled" if data["status"] == "cancelling" else "failed"
        error = data["error"] or "worker process exited unexpectedly (see worker.log)"
        await _update(conn, data["id"], status=status, error=error,
                      completed_at=datetime.now(UTC).isoformat())
        data = await get_run(conn, run)
    result = _summary(data)
    result["step_details"] = data["steps"]
    log_file = run_dir(data["run_number"]) / "worker.log"
    if log_file.exists():
        result["worker_log_tail"] = log_file.read_text(errors="replace")[-2000:]
    return result


async def cancel_run(conn: aiosqlite.Connection, run: str) -> dict:
    data = await get_run(conn, run)
    if data["status"] not in ACTIVE:
        raise ValueError(f"{data['run_number']} is not running (status: {data['status']})")
    if is_alive(data["pid"]):
        await _update(conn, data["id"], status="cancelling")
        os.kill(data["pid"], signal.SIGTERM)
    else:
        await _update(conn, data["id"], status="cancelled",
                      completed_at=datetime.now(UTC).isoformat())
    return await run_status(conn, run)


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------


def spawn_worker(
    run_number: str,
    db_path: str,
    secrets: dict | None = None,
    resume: bool = False,
) -> int:
    """Start ``defair run worker`` detached from the caller; returns its pid."""
    directory = run_dir(run_number)
    directory.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, "-c", "from defair.cli.main import cli; cli()",
           "--db", db_path, "run", "worker", run_number]
    if resume:
        cmd.append("--resume")
    secrets = {k: v for k, v in (secrets or {}).items() if v}
    if secrets:
        fd, path = tempfile.mkstemp(prefix="defair-secrets-", dir="/tmp")
        with os.fdopen(fd, "w") as fh:  # mkstemp creates the file 0600
            json.dump(secrets, fh)
        cmd.extend(["--secrets-file", path])
    env = {k: v for k, v in os.environ.items() if k not in SECRET_ENV}
    with (directory / "worker.log").open("ab") as out:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
            start_new_session=True, env=env,
        )
    return proc.pid


def read_secrets_file(path: str | None) -> dict:
    if not path:
        return {}
    p = Path(path)
    try:
        return json.loads(p.read_text())
    finally:
        p.unlink(missing_ok=True)


def _final_status(profile, results: dict[str, StepResult], cancelled: bool) -> str:
    if cancelled:
        return "cancelled"
    optional = {s.id for s in profile.steps if s.optional}
    bad = [r for r in results.values() if r.status in ("failed", "timeout", "cancelled")]
    if not bad:
        return "completed"
    if all(r.id in optional for r in bad):
        return "completed_with_errors"
    ran = [r for r in results.values() if r.status == "completed"]
    return "completed_with_errors" if ran else "failed"


async def _tool_versions(conn: aiosqlite.Connection, run_numbers: list[str]) -> dict:
    if not run_numbers:
        return {}
    marks = ",".join("?" * len(run_numbers))
    cursor = await conn.execute(
        f"SELECT run_number, tool_name, tool_version, status, duration_seconds "
        f"FROM tool_runs WHERE run_number IN ({marks})", run_numbers,
    )
    return {r["run_number"]: dict(r) for r in await cursor.fetchall()}


async def _write_manifest(conn, run: dict, prepared: dict | None, results: dict[str, StepResult],
                          status: str, error: str | None = None) -> Path:
    from defair import __version__

    steps = [r.to_dict() for r in results.values()]
    numbers = [t["run_number"] for s in steps for t in s.get("tool_runs", []) if t.get("run_number")]
    versions = await _tool_versions(conn, numbers)
    for step in steps:
        for tool_run in step.get("tool_runs", []):
            info = versions.get(tool_run.get("run_number"))
            if info:
                tool_run["tool_version"] = info["tool_version"]
    try:
        from defair.rules.lock import load_lock

        rules = {"lock_generated_at": load_lock().generated_at}
    except Exception:  # noqa: BLE001 — rules are optional for non-scan profiles
        rules = {}
    cursor = await conn.execute(
        "SELECT COUNT(*) FROM findings WHERE case_id = ?", (run["case_id"],)
    )
    findings = (await cursor.fetchone())[0]
    manifest = {
        "run_number": run["run_number"],
        "defair_version": __version__,
        "profile": run["profile"],
        "engine": run["engine"],
        "status": status,
        "error": error,
        "case_id": run["case_id"],
        "evidence_id": run["evidence_id"],
        "started_at": run.get("started_at"),
        "updated_at": datetime.now(UTC).isoformat(),
        "evidence": {k: v for k, v in (prepared or {}).items() if k != "selectors"},
        "selectors": {k: len(v) for k, v in ((prepared or {}).get("selectors") or {}).items()},
        "rules": rules,
        "steps": steps,
        "artifacts": sum(s.get("artifacts", 0) or 0 for s in steps),
        "case_findings": findings,
    }
    path = run_dir(run["run_number"]) / "run.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(manifest, indent=1, default=str))
    tmp.replace(path)  # atomic: readers never see a partial file
    return path


async def execute_run(
    conn: aiosqlite.Connection,
    run: str,
    secrets: dict | None = None,
    resume: bool = False,
    max_parallel: int = 4,
    default_timeout: int | None = 7200,
    default_retries: int = 0,
    cancel_event: asyncio.Event | None = None,
) -> dict:
    """Execute a profile run in the current process (the worker body)."""
    from defair.sources.prepare import PreparationError, Secrets, prepare_evidence

    data = await get_run(conn, run)
    cancel_event = cancel_event or asyncio.Event()
    started = data["started_at"] if resume and data["started_at"] else datetime.now(UTC).isoformat()
    await _update(conn, data["id"], status="running", pid=os.getpid(), started_at=started,
                  error=None, completed_at=None)
    data = await get_run(conn, run)

    loop = asyncio.get_running_loop()
    try:
        loop.add_signal_handler(signal.SIGTERM, cancel_event.set)
    except (NotImplementedError, RuntimeError, ValueError):
        pass  # not the main thread (tests)

    async def watch_db() -> None:
        while not cancel_event.is_set():
            await asyncio.sleep(2)
            cursor = await conn.execute("SELECT status FROM profile_runs WHERE id = ?", (data["id"],))
            row = await cursor.fetchone()
            if row and row[0] == "cancelling":
                cancel_event.set()

    log.info("profile_run_started", run=data["run_number"], profile=data["profile"],
             engine=data["engine"], evidence_id=data["evidence_id"], resume=resume,
             secrets=sorted(k for k, v in (secrets or {}).items() if v))
    watcher = asyncio.create_task(watch_db())
    prepared: dict | None = None
    results: dict[str, StepResult] = {}
    status, error = "failed", None
    try:
        secrets = secrets or {}
        prepared = await prepare_evidence(
            conn, data["evidence_id"],
            Secrets(password=secrets.get("password"), private_key=secrets.get("private_key"),
                    passphrase=secrets.get("passphrase")),
            workspace=workspace(),
        )
        profile_name = data["profile"]
        if profile_name == "auto":
            profile_name = auto_profile(prepared.get("platform", "unknown"))
            await _update(conn, data["id"], profile=profile_name)
            data["profile"] = profile_name
        profile = load_profile(profile_name)

        ctx = StepContext(conn=conn, case_id=data["case_id"], evidence_id=data["evidence_id"],
                          prepared=prepared, engine=data["engine"],
                          output_base=str(workspace() / "analysis"))
        previous = {s["id"]: s for s in data["steps"]} if resume else None
        for step_id, prev in (previous or {}).items():
            if prev.get("status") == "completed":
                record_outputs(ctx, step_id, prev)

        async def on_update(current: dict[str, StepResult]) -> None:
            await _update(conn, data["id"], steps=[r.to_dict() for r in current.values()])
            await _write_manifest(conn, data, prepared, current, "running")

        results = await execute(
            profile.steps, lambda step: run_step(ctx, step),
            max_parallel=max_parallel, default_timeout=default_timeout,
            default_retries=default_retries, cancel_event=cancel_event,
            on_update=on_update, previous=previous,
        )
        status = _final_status(profile, results, cancel_event.is_set())
    except PreparationError as e:
        status, error = "failed", f"preparation failed: {e}"
    except Exception as e:
        status, error = "failed", f"{type(e).__name__}: {e}"
        log.exception("profile_run_crashed", run=data["run_number"])
    finally:
        watcher.cancel()
        manifest = await _write_manifest(conn, data, prepared, results, status, error)
        await _update(conn, data["id"], status=status, error=error,
                      steps=[r.to_dict() for r in results.values()],
                      manifest_path=str(manifest), completed_at=datetime.now(UTC).isoformat())
    log.info("profile_run_finished", run=data["run_number"], status=status, error=error,
             profile=data["profile"], engine=data["engine"],
             steps={r.id: r.status for r in results.values()})
    return await run_status(conn, data["id"])
