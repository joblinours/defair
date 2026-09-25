"""Typed EVTX views — filtered, column-projected views over EVTX artifacts.

The views are declared in ``src/defair/data/evtx_views.yaml`` (channel +
EventIDs → named columns). They read the EVTX artifacts already in the case,
whichever parser produced them (EvtxECmd, the native parser or Dissect), so
an analyst asks for "logons" or "services" instead of opening CSV files.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

import aiosqlite
import yaml

VIEWS_FILE = Path(__file__).resolve().parent.parent / "data" / "evtx_views.yaml"
# Same expression as the idx_artifacts_event_id index (schema v4)
EVENT_ID_SQL = "CAST(json_extract(provenance, '$.event_id') AS INTEGER)"
CHANNEL_SQL = "lower(json_extract(provenance, '$.channel'))"


@lru_cache(maxsize=1)
def load_views(path: Path = VIEWS_FILE) -> dict[str, dict]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data.get("views") or {}


def list_views() -> list[dict]:
    return [
        {"name": name, "description": view.get("description", ""),
         "events": [f"{m['channel']}: {', '.join(str(e) for e in m['event_ids'])}"
                    for m in view.get("match", [])],
         "columns": list((view.get("columns") or {}).keys())}
        for name, view in load_views().items()
    ]


def _event_fields(art: dict) -> dict:
    data = art.get("data") or {}
    fields = dict(data)
    fields.update(data.get("event_data") or {})
    return fields


def project(art: dict, columns: dict[str, list[str]]) -> dict:
    """One row of a view: common columns + the view's own columns."""
    fields = _event_fields(art)
    provenance = art.get("provenance") or {}
    row = {
        "artifact": art.get("artifact_number"),
        "timestamp": art.get("timestamp"),
        "event_id": provenance.get("event_id") or fields.get("event_id") or fields.get("EventID"),
        "channel": provenance.get("channel") or fields.get("channel") or fields.get("Channel"),
        "computer": art.get("hostname"),
        "description": art.get("description"),
    }
    for column, candidates in columns.items():
        value = next((fields[c] for c in candidates if fields.get(c) not in (None, "", "-")), None)
        row[column] = value
    return row


async def get_view(
    conn: aiosqlite.Connection,
    case_id: str,
    name: str,
    since: str | None = None,
    until: str | None = None,
    hostname: str | None = None,
    username: str | None = None,
    event_id: int | None = None,
    order: str = "asc",
    limit: int = 200,
    offset: int = 0,
) -> dict:
    """Rows of one view for a case, in time order."""
    from defair.services.artifact_service import _row
    from defair.services.case_service import resolve_case_id

    views = load_views()
    if name not in views:
        raise ValueError(f"Unknown EVTX view '{name}'. Available: {', '.join(sorted(views))}")
    view = views[name]

    where = ["case_id = ?", "artifact_type LIKE 'windows.evtx.%'"]
    params: list = [await resolve_case_id(conn, case_id)]
    matches = []
    for match in view.get("match", []):
        ids = [int(e) for e in match["event_ids"] if event_id is None or int(e) == event_id]
        if not ids:
            continue
        clause = f"{EVENT_ID_SQL} IN ({', '.join('?' * len(ids))})"
        params_match = list(ids)
        if match.get("channel", "*") != "*":
            clause += f" AND {CHANNEL_SQL} = ?"
            params_match.append(match["channel"].lower())
        matches.append(f"({clause})")
        params.extend(params_match)
    if not matches:
        return {"view": name, "total": 0, "offset": offset, "limit": limit, "rows": []}
    where.append(f"({' OR '.join(matches)})")
    if since:
        where.append("timestamp >= ?")
        params.append(since)
    if until:
        where.append("timestamp <= ?")
        params.append(until)
    if hostname:
        where.append("hostname LIKE ?")
        params.append(f"%{hostname}%")
    if username:
        where.append("(username LIKE ? OR data LIKE ?)")
        params.extend([f"%{username}%"] * 2)
    clause = " AND ".join(where)
    direction = "DESC" if order.lower() == "desc" else "ASC"

    cursor = await conn.execute(f"SELECT COUNT(*) FROM artifacts WHERE {clause}", params)
    total = (await cursor.fetchone())[0]
    cursor = await conn.execute(
        f"SELECT * FROM artifacts WHERE {clause} "
        f"ORDER BY timestamp IS NULL, timestamp {direction}, artifact_number LIMIT ? OFFSET ?",
        [*params, limit, offset],
    )
    columns = view.get("columns") or {}
    rows = [project(_row(r), columns) for r in await cursor.fetchall()]
    return {"view": name, "description": view.get("description", ""), "total": total,
            "offset": offset, "limit": limit, "columns": list(columns), "rows": rows}


def dumps(result: dict) -> str:
    return json.dumps(result, indent=2, default=str)
