"""Timeline service — one timeline over artifacts and supertimeline events.

Two stores, one view:

- ``artifacts``: every normalized artifact (EZ Tools, native parsers,
  Dissect, Hayabusa, Raijin…), source ``artifacts``;
- ``timeline_events`` (v0.5): Plaso (``plaso``) and Sleuth Kit bodyfile
  (``tsk``) events — millions of rows, no ART-NNN.

Both are projected on common columns (timestamp, timestamp_desc, message,
description, artifact_type, source_tool, source_file, hostname, username,
parser…) and merged in time order. Text search uses LIKE on artifacts and
the FTS5 index (whole words / phrases) on timeline events. Exports stream
both stores merged by time, with no row limit.
"""

from __future__ import annotations

import csv
import json
from collections.abc import AsyncIterator
from pathlib import Path

import aiosqlite
import structlog

log = structlog.get_logger(component="timeline_service")

EXPORT_FORMATS = ("csv", "jsonl", "timesketch")
SOURCES = ("artifacts", "plaso", "tsk")
EVENT_SOURCES = ("plaso", "tsk")

ARTIFACT_COLUMNS = (
    "'artifact' AS record, id, artifact_number, case_id, evidence_id, run_id, timestamp, "
    "timestamp_desc, message, description, artifact_type, category, severity, hostname, username, "
    "source_tool, source_file, NULL AS parser, data, provenance, tags"
)
EVENT_COLUMNS = (
    "'event' AS record, id, NULL AS artifact_number, case_id, evidence_id, run_id, timestamp, "
    "timestamp_desc, message, message AS description, source_long AS artifact_type, NULL AS category, "
    "NULL AS severity, hostname, username, source AS source_tool, filename AS source_file, parser, data, "
    "provenance, NULL AS tags"
)


def _sources(sources) -> tuple[str, ...]:
    if not sources:
        return SOURCES
    if isinstance(sources, str):
        sources = [s.strip() for s in sources.split(",") if s.strip()]
    unknown = set(sources) - set(SOURCES)
    if unknown:
        raise ValueError(f"Unknown timeline source(s) {sorted(unknown)}; use {', '.join(SOURCES)}")
    return tuple(sources)


def fts_phrase(query: str) -> str:
    """User text → an FTS5 phrase query (no operator injection)."""
    return '"' + query.replace('"', '""') + '"'


async def build_timeline(conn: aiosqlite.Connection, case_id: str) -> dict:
    """Timeline summary: counts, time range, breakdowns (artifacts + events)."""
    from defair.services.case_service import resolve_case_id

    case_id = await resolve_case_id(conn, case_id)

    cursor = await conn.execute(
        "SELECT COUNT(*), MIN(timestamp), MAX(timestamp) FROM artifacts "
        "WHERE case_id = ? AND timestamp IS NOT NULL", (case_id,))
    artifacts, a_min, a_max = await cursor.fetchone()
    cursor = await conn.execute(
        "SELECT COUNT(*), MIN(timestamp), MAX(timestamp) FROM timeline_events "
        "WHERE case_id = ? AND timestamp IS NOT NULL", (case_id,))
    events, e_min, e_max = await cursor.fetchone()

    async def breakdown(sql: str) -> dict:
        cursor = await conn.execute(sql, (case_id,))
        return {r[0]: r[1] for r in await cursor.fetchall()}

    by_tool = await breakdown(
        "SELECT source_tool, COUNT(*) AS n FROM artifacts WHERE case_id = ? AND timestamp IS NOT NULL "
        "GROUP BY source_tool ORDER BY n DESC")
    by_category = await breakdown(
        "SELECT category, COUNT(*) AS n FROM artifacts WHERE case_id = ? AND timestamp IS NOT NULL "
        "GROUP BY category ORDER BY n DESC")
    by_severity = await breakdown(
        "SELECT severity, COUNT(*) AS n FROM artifacts WHERE case_id = ? AND severity IS NOT NULL "
        "GROUP BY severity ORDER BY n DESC")
    by_source = await breakdown(
        "SELECT source, COUNT(*) AS n FROM timeline_events WHERE case_id = ? AND timestamp IS NOT NULL "
        "GROUP BY source ORDER BY n DESC")
    by_parser = await breakdown(
        "SELECT source || ':' || COALESCE(parser, '?'), COUNT(*) AS n FROM timeline_events "
        "WHERE case_id = ? AND timestamp IS NOT NULL GROUP BY source, parser ORDER BY n DESC LIMIT 50")

    bounds = [t for t in (a_min, e_min) if t]
    tops = [t for t in (a_max, e_max) if t]
    result = {
        "case_id": case_id,
        "total_events": artifacts + events,
        "artifact_events": artifacts,
        "supertimeline_events": events,
        "earliest": min(bounds) if bounds else None,
        "latest": max(tops) if tops else None,
        "by_tool": by_tool,
        "by_category": by_category,
        "by_severity": by_severity,
        "by_source": {"artifacts": artifacts, **by_source},
        "by_parser": by_parser,
    }
    log.info("timeline_built", case_id=case_id, total=result["total_events"])
    return result


def _artifact_where(case_id: str, query, from_time, to_time, hostname, username, category, severity,
                    source_tool, artifact_type) -> tuple[str, list]:
    where = ["case_id = ?", "timestamp IS NOT NULL"]
    params: list = [case_id]
    if query:
        where.append("(description LIKE ? OR message LIKE ? OR data LIKE ?)")
        params.extend([f"%{query}%"] * 3)
    for clause, value in (("timestamp >= ?", from_time), ("timestamp <= ?", to_time),
                          ("category = ?", category), ("severity = ?", severity),
                          ("source_tool = ?", source_tool)):
        if value:
            where.append(clause)
            params.append(value)
    for column, value in (("hostname", hostname), ("username", username), ("artifact_type", artifact_type)):
        if value:
            where.append(f"{column} LIKE ?")
            params.append(f"%{value}%")
    return " AND ".join(where), params


def _event_where(case_id: str, sources: tuple[str, ...], query, from_time, to_time, hostname, username,
                 source_tool, artifact_type, parser) -> tuple[str, list]:
    where = ["case_id = ?", "timestamp IS NOT NULL",
             f"source IN ({', '.join('?' * len(sources))})"]
    params: list = [case_id, *sources]
    if query:
        where.append("rowid IN (SELECT rowid FROM timeline_events_fts WHERE timeline_events_fts MATCH ?)")
        params.append(fts_phrase(query))
    for clause, value in (("timestamp >= ?", from_time), ("timestamp <= ?", to_time),
                          ("source = ?", source_tool), ("parser = ?", parser)):
        if value:
            where.append(clause)
            params.append(value)
    for column, value in (("hostname", hostname), ("username", username), ("source_long", artifact_type)):
        if value:
            where.append(f"{column} LIKE ?")
            params.append(f"%{value}%")
    return " AND ".join(where), params


def _plan(case_id: str, sources, query, from_time, to_time, hostname, username, category, severity,
          source_tool, artifact_type, parser) -> list[tuple[str, list]]:
    """(SELECT …, params) per store, each ordered by time."""
    sources = _sources(sources)
    selects = []
    # category / severity / parser only exist on one side: they exclude the other
    if "artifacts" in sources and not parser and source_tool not in EVENT_SOURCES:
        clause, params = _artifact_where(case_id, query, from_time, to_time, hostname, username,
                                         category, severity, source_tool, artifact_type)
        selects.append((f"SELECT {ARTIFACT_COLUMNS} FROM artifacts WHERE {clause}", params))
    event_sources = tuple(s for s in sources if s in EVENT_SOURCES)
    if event_sources and not category and not severity and source_tool in (None, *EVENT_SOURCES):
        clause, params = _event_where(case_id, event_sources, query, from_time, to_time, hostname,
                                      username, source_tool, artifact_type, parser)
        selects.append((f"SELECT {EVENT_COLUMNS} FROM timeline_events WHERE {clause}", params))
    return selects


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
    offset: int = 0,
    sources: str | list[str] | None = None,
    parser: str | None = None,
) -> list[dict]:
    """Search the merged timeline, ordered by timestamp.

    Args:
        sources: ``artifacts``, ``plaso``, ``tsk`` (list or comma string; default all).
        parser: Plaso parser / ``fls`` (timeline events only).
        query: LIKE on artifacts; FTS5 phrase on timeline events.
    """
    from defair.services.case_service import resolve_case_id

    case_id = await resolve_case_id(conn, case_id)
    selects = _plan(case_id, sources, query, from_time, to_time, hostname, username, category,
                    severity, source_tool, artifact_type, parser)
    if not selects:
        return []
    top = limit + offset
    # each store gives its own first (limit + offset) rows, then they are merged
    parts, params = [], []
    for sql, part_params in selects:
        parts.append(f"SELECT * FROM ({sql} ORDER BY timestamp ASC LIMIT ?)")
        params.extend([*part_params, top])
    cursor = await conn.execute(
        f"SELECT * FROM ({' UNION ALL '.join(parts)}) ORDER BY timestamp ASC LIMIT ? OFFSET ?",
        [*params, limit, offset])
    return [dict(r) for r in await cursor.fetchall()]


async def iter_timeline(conn: aiosqlite.Connection, case_id: str, **filters) -> AsyncIterator[dict]:
    """Every matching row of both stores, merged by time, streamed (exports)."""
    from defair.services.case_service import resolve_case_id

    case_id = await resolve_case_id(conn, case_id)
    names = ("query", "from_time", "to_time", "hostname", "username", "category", "severity",
             "source_tool", "artifact_type", "parser")
    selects = _plan(case_id, filters.get("sources"), *(filters.get(n) for n in names))
    cursors = []
    for sql, params in selects:
        cursors.append(await conn.execute(f"{sql} ORDER BY timestamp ASC", params))
    heads = [await c.fetchone() for c in cursors]
    while any(h is not None for h in heads):
        index = min((i for i, h in enumerate(heads) if h is not None), key=lambda i: heads[i]["timestamp"])
        yield dict(heads[index])
        heads[index] = await cursors[index].fetchone()


async def export_timeline(
    conn: aiosqlite.Connection,
    case_id: str,
    format: str = "csv",
    output_path: str | None = None,
    **filters,
) -> dict:
    """Export the merged timeline (streamed, no row limit).

    Args:
        format: "csv", "jsonl" or "timesketch" (JSONL with message /
            datetime / timestamp_desc, importable with timesketch_importer).
        output_path: Where to write (default: /workspace/timeline/).
        **filters: Same filters as search_timeline (incl. ``sources``, ``parser``).
    """
    if format not in EXPORT_FORMATS:
        raise ValueError(f"Unknown export format '{format}'. Use one of: {', '.join(EXPORT_FORMATS)}")
    if not output_path:
        suffix = "jsonl" if format == "timesketch" else format
        output_path = f"/workspace/timeline/timeline_{case_id[:8]}.{suffix}"
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with open(output_path, "w", newline="", encoding="utf-8") as fh:  # noqa: ASYNC230 — streamed writes
        writer = None
        if format == "csv":
            writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
        async for event in iter_timeline(conn, case_id, **filters):
            if writer is not None:
                writer.writerow(event)
            elif format == "timesketch":
                fh.write(json.dumps(timesketch_record(event), default=str) + "\n")
            else:
                fh.write(json.dumps(event, default=str) + "\n")
            count += 1
    log.info("timeline_exported", case_id=case_id, format=format, count=count)
    return {"path": output_path, "count": count, "format": format}


CSV_FIELDS = [
    "timestamp", "timestamp_desc", "message", "artifact_type", "category", "severity",
    "hostname", "username", "description", "source_tool", "parser", "source_file",
    "artifact_number", "data",
]


def timesketch_record(event: dict) -> dict:
    """Timesketch JSONL: required ``message``, ``datetime``, ``timestamp_desc``."""
    data = event.get("data")
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError:
            data = {"raw": data}
    record = {
        "message": event.get("message") or event.get("description") or event.get("artifact_type"),
        "datetime": event["timestamp"],
        "timestamp_desc": event.get("timestamp_desc") or "Event Time",
        "artifact_type": event.get("artifact_type"),
        "artifact_number": event.get("artifact_number"),
        "category": event.get("category"),
        "severity": event.get("severity"),
        "hostname": event.get("hostname"),
        "username": event.get("username"),
        "source_tool": event.get("source_tool"),
        "parser": event.get("parser"),
        "source_file": event.get("source_file"),
        "data": data,
    }
    return {k: v for k, v in record.items() if v is not None}
