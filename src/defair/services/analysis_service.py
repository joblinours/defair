"""Analysis service — orchestrates tool execution and artifact normalization.

This is the core service for v0.2: it runs forensic tools against evidence,
captures provenance (ToolRun), normalizes outputs into Artifacts, and
stores everything in the database.

Runs INSIDE the container (not on the host).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import aiosqlite
import structlog

from defair.models.tool_run import ToolRun, ToolRunStatus, generate_run_number
from defair.normalizers.eztools import get_normalizer
from defair.tools.registry import ToolRegistry, get_default_registry

log = structlog.get_logger(component="analysis_service")


async def _next_run_number(conn: aiosqlite.Connection) -> str:
    """Generate the next run number."""
    cursor = await conn.execute("SELECT COUNT(*) FROM tool_runs")
    row = await cursor.fetchone()
    count = row[0] if row else 0
    return generate_run_number(count + 1)


async def run_tool(
    conn: aiosqlite.Connection,
    tool_name: str,
    input_path: str,
    case_id: str,
    evidence_id: str | None = None,
    output_base: str = "/workspace/analysis",
    registry: ToolRegistry | None = None,
    **kwargs,
) -> ToolRun:
    """Execute a forensic tool and store the run record.

    Args:
        conn: Database connection (inside container).
        tool_name: Tool identifier (e.g. "mftecmd").
        input_path: Path to input file/directory.
        case_id: Case ID.
        evidence_id: Optional evidence ID.
        output_base: Base output directory.
        registry: Optional tool registry (uses default if None).
        **kwargs: Tool-specific options.

    Returns:
        The completed ToolRun with execution details.
    """
    from defair.services.case_service import resolve_case_id

    # Resolve case_number (CASE-YYYY-NNN) → UUID if needed
    case_id = await resolve_case_id(conn, case_id)

    if registry is None:
        registry = get_default_registry()

    tool = registry.get(tool_name)
    if tool is None:
        raise ValueError(f"Unknown tool: {tool_name}")

    if not tool.is_available():
        raise RuntimeError(
            f"Tool '{tool_name}' is not available. "
            f"Binary '{tool.manifest().command}' not found."
        )

    # Generate run number and output directory
    run_number = await _next_run_number(conn)
    output_dir = str(Path(output_base) / tool_name / run_number)

    # Execute
    tool_run = await tool.run(
        input_path=input_path,
        output_dir=output_dir,
        case_id=case_id,
        evidence_id=evidence_id,
        run_number=run_number,
        **kwargs,
    )

    # Store in database
    await _save_tool_run(conn, tool_run)

    return tool_run


async def run_tool_and_normalize(
    conn: aiosqlite.Connection,
    tool_name: str,
    input_path: str,
    case_id: str,
    evidence_id: str | None = None,
    output_base: str = "/workspace/analysis",
    registry: ToolRegistry | None = None,
    **kwargs,
) -> dict:
    """Execute a tool, normalize outputs, and store artifacts.

    This is the high-level function that combines execution + normalization.

    Returns:
        Summary dict with run details and artifact count.
    """
    tool_run = await run_tool(
        conn, tool_name, input_path, case_id,
        evidence_id=evidence_id,
        output_base=output_base,
        registry=registry,
        **kwargs,
    )

    # Use the resolved UUID from tool_run (run_tool resolves case_number → UUID)
    resolved_case_id = tool_run.case_id

    # Normalize outputs
    artifact_count = 0
    if tool_run.status == ToolRunStatus.COMPLETED and tool_run.output_path:
        normalizer = get_normalizer(tool_name)
        if normalizer:
            artifacts = normalizer.normalize_directory(
                tool_run.output_path,
                case_id=resolved_case_id,
                evidence_id=evidence_id,
                run_id=tool_run.id,
            )
            artifact_count = len(artifacts)

            # Store artifacts
            for art in artifacts:
                await _save_artifact(conn, art)

    return {
        "run_id": tool_run.id,
        "run_number": tool_run.run_number,
        "case_id": resolved_case_id,
        "tool": tool_name,
        "status": tool_run.status,
        "exit_code": tool_run.exit_code,
        "duration_seconds": tool_run.duration_seconds,
        "output_files": len(tool_run.output_files),
        "artifacts_produced": artifact_count,
    }


async def list_tool_runs(
    conn: aiosqlite.Connection,
    case_id: str | None = None,
) -> list[dict]:
    """List tool runs, optionally filtered by case."""
    if case_id:
        from defair.services.case_service import resolve_case_id

        case_id = await resolve_case_id(conn, case_id)
        cursor = await conn.execute(
            "SELECT * FROM tool_runs WHERE case_id = ? ORDER BY created_at DESC",
            (case_id,),
        )
    else:
        cursor = await conn.execute(
            "SELECT * FROM tool_runs ORDER BY created_at DESC"
        )
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_tool_run(
    conn: aiosqlite.Connection,
    run_id_or_number: str,
) -> dict | None:
    """Get a specific tool run by ID or run number."""
    cursor = await conn.execute(
        "SELECT * FROM tool_runs WHERE id = ? OR run_number = ?",
        (run_id_or_number, run_id_or_number),
    )
    row = await cursor.fetchone()
    if row is None:
        return None
    return dict(row)


async def list_artifacts(
    conn: aiosqlite.Connection,
    case_id: str | None = None,
    category: str | None = None,
    artifact_type: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """List artifacts with optional filters."""
    query = "SELECT * FROM artifacts WHERE 1=1"
    params: list = []

    if case_id:
        from defair.services.case_service import resolve_case_id

        case_id = await resolve_case_id(conn, case_id)
        query += " AND case_id = ?"
        params.append(case_id)
    if category:
        query += " AND category = ?"
        params.append(category)
    if artifact_type:
        query += " AND artifact_type LIKE ?"
        params.append(f"%{artifact_type}%")

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    cursor = await conn.execute(query, params)
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def _save_tool_run(conn: aiosqlite.Connection, run: ToolRun) -> None:
    """Insert a tool run record into the database."""
    await conn.execute(
        """INSERT INTO tool_runs
        (id, run_number, case_id, evidence_id, tool_name, tool_version,
         command, parameters, status, exit_code, stdout, stderr,
         output_path, output_files, output_hash,
         started_at, completed_at, duration_seconds, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            run.id, run.run_number, run.case_id, run.evidence_id,
            run.tool_name, run.tool_version,
            run.command, json.dumps(run.parameters),
            run.status, run.exit_code,
            run.stdout[:10000],  # Truncate large outputs
            run.stderr[:10000],
            run.output_path, json.dumps(run.output_files),
            run.output_hash,
            run.started_at.isoformat() if run.started_at else None,
            run.completed_at.isoformat() if run.completed_at else None,
            run.duration_seconds,
            run.created_at.isoformat(),
        ),
    )
    await conn.commit()


async def _save_artifact(conn: aiosqlite.Connection, art: dict) -> None:
    """Insert a normalized artifact into the database."""
    from uuid import uuid4

    from defair.models.artifact import generate_artifact_number

    # Get next artifact number
    cursor = await conn.execute("SELECT COUNT(*) FROM artifacts")
    row = await cursor.fetchone()
    count = row[0] if row else 0
    art_number = generate_artifact_number(count + 1)

    art_id = uuid4().hex
    category = art.get("category", "other")
    if hasattr(category, "value"):
        category = category.value

    await conn.execute(
        """INSERT INTO artifacts
        (id, artifact_number, case_id, evidence_id, run_id,
         artifact_type, category, source_tool, source_file,
         timestamp, end_timestamp, hostname, username,
         description, data, tags, severity, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            art_id, art_number,
            art.get("case_id", ""), art.get("evidence_id"),
            art.get("run_id"),
            art.get("artifact_type", "unknown"),
            category,
            art.get("source_tool", ""),
            art.get("source_file", ""),
            art.get("timestamp"),
            art.get("end_timestamp"),
            art.get("hostname"),
            art.get("username"),
            art.get("description", ""),
            json.dumps(art.get("data", {})),
            json.dumps(art.get("tags", [])),
            art.get("severity"),
            datetime.now(UTC).isoformat(),
        ),
    )
    await conn.commit()
