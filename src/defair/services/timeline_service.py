"""Timeline service — unified timeline from all artifacts.

Operates on the existing artifacts table, providing:
- Timeline summary (stats, time range, breakdown)
- Timeline search (full-text + filters)
- Timeline export (CSV, JSONL)
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import aiosqlite
import structlog

log = structlog.get_logger(component="timeline_service")


async def build_timeline(
    conn: aiosqlite.Connection,
    case_id: str,
) -> dict:
    """Build a timeline summary for a case.

    Returns stats: total events, time range, breakdown by tool and category.
    """
    # Total count
    cursor = await conn.execute(
        "SELECT COUNT(*) FROM artifacts WHERE case_id = ? AND timestamp IS NOT NULL",
        (case_id,),
    )
    total = (await cursor.fetchone())[0]

    # Time range
    cursor = await conn.execute(
        """SELECT MIN(timestamp), MAX(timestamp)
        FROM artifacts WHERE case_id = ? AND timestamp IS NOT NULL""",
        (case_id,),
    )
    row = await cursor.fetchone()
    earliest = row[0] if row else None
    latest = row[1] if row else None

    # Breakdown by source_tool
    cursor = await conn.execute(
        """SELECT source_tool, COUNT(*) as cnt
        FROM artifacts WHERE case_id = ? AND timestamp IS NOT NULL
        GROUP BY source_tool ORDER BY cnt DESC""",
        (case_id,),
    )
    by_tool = {r["source_tool"]: r["cnt"] for r in await cursor.fetchall()}

    # Breakdown by category
    cursor = await conn.execute(
        """SELECT category, COUNT(*) as cnt
        FROM artifacts WHERE case_id = ? AND timestamp IS NOT NULL
        GROUP BY category ORDER BY cnt DESC""",
        (case_id,),
    )
    by_category = {r["category"]: r["cnt"] for r in await cursor.fetchall()}

    # Severity breakdown
    cursor = await conn.execute(
        """SELECT severity, COUNT(*) as cnt
        FROM artifacts WHERE case_id = ? AND severity IS NOT NULL
        GROUP BY severity ORDER BY cnt DESC""",
        (case_id,),
    )
    by_severity = {r["severity"]: r["cnt"] for r in await cursor.fetchall()}

    result = {
        "case_id": case_id,
        "total_events": total,
        "earliest": earliest,
        "latest": latest,
        "by_tool": by_tool,
        "by_category": by_category,
        "by_severity": by_severity,
    }

    log.info("timeline_built", case_id=case_id, total=total)
    return result


async def search_timeline(
    conn: aiosqlite.Connection,
    case_id: str,
    query: str | None = None,
    from_time: str | None = None,
    to_time: str | None = None,
    hostname: str | None = None,
    username: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    source_tool: str | None = None,
    artifact_type: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """Search the timeline with filters.

    Returns artifacts ordered by timestamp ASC.
    """
    sql = "SELECT * FROM artifacts WHERE case_id = ? AND timestamp IS NOT NULL"
    params: list = [case_id]

    if query:
        sql += " AND (description LIKE ? OR data LIKE ?)"
        like = f"%{query}%"
        params.extend([like, like])

    if from_time:
        sql += " AND timestamp >= ?"
        params.append(from_time)

    if to_time:
        sql += " AND timestamp <= ?"
        params.append(to_time)

    if hostname:
        sql += " AND hostname LIKE ?"
        params.append(f"%{hostname}%")

    if username:
        sql += " AND username LIKE ?"
        params.append(f"%{username}%")

    if category:
        sql += " AND category = ?"
        params.append(category)

    if severity:
        sql += " AND severity = ?"
        params.append(severity)

    if source_tool:
        sql += " AND source_tool = ?"
        params.append(source_tool)

    if artifact_type:
        sql += " AND artifact_type LIKE ?"
        params.append(f"%{artifact_type}%")

    sql += " ORDER BY timestamp ASC LIMIT ?"
    params.append(limit)

    cursor = await conn.execute(sql, params)
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def export_timeline(
    conn: aiosqlite.Connection,
    case_id: str,
    format: str = "csv",
    output_path: str | None = None,
    **filters,
) -> dict:
    """Export the timeline to CSV or JSONL.

    Args:
        conn: DB connection.
        case_id: Case to export.
        format: "csv" or "jsonl".
        output_path: Where to write (default: /workspace/timeline/).
        **filters: Same filters as search_timeline.

    Returns:
        Dict with path, count, format.
    """
    # Fetch all matching artifacts (no limit)
    events = await search_timeline(conn, case_id, limit=100000, **filters)

    if not output_path:
        output_path = f"/workspace/timeline/timeline_{case_id[:8]}.{format}"

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    if format == "csv":
        _export_csv(events, output_path)
    else:
        _export_jsonl(events, output_path)

    log.info("timeline_exported", case_id=case_id, format=format, count=len(events))
    return {
        "path": output_path,
        "count": len(events),
        "format": format,
    }


def _export_csv(events: list[dict], path: str) -> None:
    """Write events to CSV."""
    if not events:
        Path(path).write_text("")
        return

    fields = [
        "timestamp", "artifact_type", "category", "severity",
        "hostname", "username", "description", "source_tool",
        "source_file", "data",
    ]

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for e in events:
            writer.writerow(e)


def _export_jsonl(events: list[dict], path: str) -> None:
    """Write events to JSONL."""
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(json.dumps(e, default=str) + "\n" for e in events)
