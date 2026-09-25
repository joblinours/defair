"""Normalization service — replay, re-run and statistics of the pipeline.

- ``replay``: rebuild a case's artifacts from the normalized JSONL files
  (e.g. after the database was lost). Each file is checked against the
  SHA-256 recorded when it was written; a mismatching file is not loaded.
- ``rerun``: re-normalize a tool run from its raw output (e.g. after a
  normalizer fix). Artifact ids are deterministic, so findings keep pointing
  at the same artifacts.
- ``stats``: per-run counters (rows read, normalized, skipped, errors,
  unparseable timestamps, reasons) and the JSONL files produced.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import aiosqlite
import structlog

from defair.normalizers.pipeline import bulk_insert, normalize_run, read_jsonl

log = structlog.get_logger(component="normalization_service")


async def _resolve_run(conn: aiosqlite.Connection, run_id_or_number: str) -> dict:
    cursor = await conn.execute(
        "SELECT * FROM tool_runs WHERE id = ? OR run_number = ?",
        (run_id_or_number, run_id_or_number),
    )
    row = await cursor.fetchone()
    if row is None:
        raise ValueError(f"Tool run not found: {run_id_or_number}")
    return dict(row)


async def replay(
    conn: aiosqlite.Connection,
    case_id: str,
    json_dir: str | None = None,
) -> dict:
    """Rebuild artifacts from the normalized JSONL files of a case.

    Args:
        conn: Database connection.
        case_id: Case ID or case number.
        json_dir: Directory to scan for ``*.jsonl`` instead of the files
            recorded in ``normalized_files`` (when the database was lost).
            Such files have no recorded hash and are loaded as-is.

    Returns:
        Files loaded / refused and artifacts restored.
    """
    from defair.services.case_service import resolve_case_id

    case_id = await resolve_case_id(conn, case_id)
    if json_dir:
        files = [{"path": str(p), "sha256": None} for p in sorted(Path(json_dir).rglob("*.jsonl"))]
    else:
        cursor = await conn.execute(
            "SELECT path, sha256 FROM normalized_files WHERE case_id = ? ORDER BY path",
            (case_id,),
        )
        files = [dict(r) for r in await cursor.fetchall()]

    loaded, refused, restored = [], [], 0
    for f in files:
        path = Path(f["path"])
        if not path.exists():
            refused.append({"path": str(path), "reason": "missing"})
            continue
        if f["sha256"] and hashlib.sha256(path.read_bytes()).hexdigest() != f["sha256"]:
            refused.append({"path": str(path), "reason": "sha256 mismatch"})
            continue
        artifacts = [a for a in read_jsonl(path) if a.get("case_id") == case_id]
        restored += await bulk_insert(conn, artifacts)
        loaded.append(str(path))

    log.info("normalization_replayed", case_id=case_id, files=len(loaded),
             refused=len(refused), artifacts=restored)
    return {"case_id": case_id, "files_loaded": len(loaded), "refused": refused,
            "artifacts_restored": restored}


async def rerun(conn: aiosqlite.Connection, run_id_or_number: str) -> dict:
    """Re-normalize one tool run from its raw output."""
    from defair.normalizers.eztools import get_normalizer

    run = await _resolve_run(conn, run_id_or_number)
    if not run.get("output_path") or not Path(run["output_path"]).exists():
        raise ValueError(f"Raw output of {run['run_number']} not found: {run.get('output_path')}")
    normalizer = get_normalizer(run["tool_name"])
    if normalizer is None:
        raise ValueError(f"No normalizer for tool '{run['tool_name']}'")

    cursor = await conn.execute(
        "SELECT id, artifact_number FROM artifacts WHERE run_id = ?", (run["id"],)
    )
    numbers = {r["id"]: r["artifact_number"] for r in await cursor.fetchall()}
    await conn.execute("DELETE FROM artifacts WHERE run_id = ?", (run["id"],))
    stats = await normalize_run(conn, run, normalizer, keep_numbers=numbers)
    return {"run_number": run["run_number"], "tool": run["tool_name"],
            "artifacts_before": len(numbers), "artifacts_after": stats["normalized"],
            "stats": {k: v for k, v in stats.items() if k != "files"}}


async def stats(conn: aiosqlite.Connection, run_id_or_number: str) -> dict:
    """Normalization counters and JSONL files of a tool run."""
    run = await _resolve_run(conn, run_id_or_number)
    cursor = await conn.execute(
        "SELECT artifact_type, path, sha256, records FROM normalized_files WHERE run_id = ?",
        (run["id"],),
    )
    return {
        "run_number": run["run_number"],
        "tool": run["tool_name"],
        "status": run["status"],
        "stats": json.loads(run.get("normalization_stats") or "{}"),
        "files": [dict(r) for r in await cursor.fetchall()],
    }
