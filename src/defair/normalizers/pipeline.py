"""Normalization pipeline — tool output → JSONL → case database.

Inspired by ArtefactProcessor (intermediate JSONL, batched bulk indexing,
re-sync from JSONL), adapted to DEFAIR's provenance model:

1. the tool's normalizer produces artifact dicts;
2. each artifact gets a common envelope (``provenance``), ISO 8601 UTC
   timestamps (an unparseable time stays ``None`` — never "now"), timeline
   fields (``timestamp_desc``, ``message``) and a deterministic id derived
   from ``(run_id, record_key)``;
3. artifacts are written to ``<workspace>/normalized/<artifact_type>/<RUN>.jsonl``
   (hashed, recorded in ``normalized_files``);
4. then bulk-inserted in batches.

Because ids are deterministic and the JSONL holds final rows, the database can
be rebuilt from the JSONL alone (``replay``) or from the raw tool output after
a normalizer fix (``rerun``) without breaking findings that reference artifacts.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid4, uuid5

import aiosqlite
import structlog

from defair.database import db_lock
from defair.normalizers.timestamps import to_utc_iso

log = structlog.get_logger(component="normalization")

BATCH_SIZE = 2000
ARTIFACT_NAMESPACE = uuid5(NAMESPACE_URL, "https://github.com/joblinours/defair/artifact")

# What the main timestamp means, by artifact type prefix (longest prefix wins)
TIMESTAMP_DESC: dict[str, str] = {
    "windows.mft": "Created ($SI)",
    "windows.evtx": "Event Logged",
    "windows.hayabusa": "Event Logged",
    "detection.sigma": "Event Logged",
    "windows.prefetch": "Last Executed",
    "windows.registry": "Key Last Written",
    "windows.amcache": "Key Last Written",
    "windows.shimcache": "File Last Modified",
    "windows.lnk": "Target Created",
    "windows.jumplist": "Target Created",
    "windows.recyclebin": "Deleted",
    "windows.shellbags": "Last Interacted",
    "windows.timeline": "Activity Start",
    "windows.browser": "Recorded",
    "windows.sqlite": "Recorded",
    "windows.srum": "Recorded",
    "windows.usn": "USN Record Updated",
    "windows.ual": "Last Access",
    "windows.ntfs.indx_slack": "Created ($FN, INDX slack)",
    "windows.ntfs.logfile": "Recorded ($LogFile)",
    "windows.defender": "Event Logged",
    "windows.powershell.history": "Command Run",
    "windows.scheduled_task": "Task Registered",
    "windows.rdp": "Cache Modified",
    "windows.iis": "Request Received",
    "windows.system": "Recorded",
}

ARTIFACT_COLUMNS = (
    "id", "artifact_number", "case_id", "evidence_id", "run_id",
    "artifact_type", "category", "source_tool", "source_file",
    "timestamp", "end_timestamp", "timestamp_desc", "message",
    "hostname", "username", "description", "data", "tags", "severity",
    "provenance", "record_key", "created_at",
)
_JSON_COLUMNS = {"data", "tags", "provenance"}


def timestamp_desc_for(artifact_type: str) -> str | None:
    best = None
    for prefix, desc in TIMESTAMP_DESC.items():
        if artifact_type.startswith(prefix) and (best is None or len(prefix) > len(best[0])):
            best = (prefix, desc)
    return best[1] if best else "Event Time"


def artifact_id(run_id: str, record_key: str) -> str:
    """Deterministic artifact id: same run + same source record → same id."""
    return uuid5(ARTIFACT_NAMESPACE, f"{run_id}|{record_key}").hex


def new_stats() -> dict:
    return {
        "rows_read": 0, "normalized": 0, "skipped": 0, "errors": 0,
        "timestamp_unparsed": 0, "reasons": {},
    }


def _reason(stats: dict, reason: str) -> None:
    stats["reasons"][reason] = stats["reasons"].get(reason, 0) + 1


def enrich(art: dict, run: dict, stats: dict, seen_keys: set[str]) -> dict:
    """Apply the common envelope, UTC timestamps, timeline fields and id."""
    provenance = {
        "tool": run["tool_name"],
        "tool_version": run.get("tool_version"),
        "run_id": run["id"],
        "run_number": run["run_number"],
        "evidence_id": art.get("evidence_id") or run.get("evidence_id"),
        "source_file": art.get("source_file", ""),
        **(art.get("provenance") or {}),
    }
    data = art.get("data") or {}
    for key in ("host_path", "channel", "record_number", "event_id"):
        if data.get(key) not in (None, ""):
            provenance.setdefault(key, data[key])

    for field in ("timestamp", "end_timestamp"):
        raw = art.get(field)
        iso, error = to_utc_iso(raw)
        if error:
            stats["timestamp_unparsed"] += 1
            _reason(stats, f"{field}: {error.split(':')[0]}")
            provenance[f"raw_{field}"] = str(raw)
        art[field] = iso

    artifact_type = art.get("artifact_type") or "unknown"
    art["artifact_type"] = artifact_type
    if art.get("timestamp"):
        art["timestamp_desc"] = art.get("timestamp_desc") or timestamp_desc_for(artifact_type)
    else:
        art["timestamp_desc"] = None
    if not art.get("message"):
        art["message"] = art.get("description") or artifact_type

    category = art.get("category", "other")
    art["category"] = getattr(category, "value", category)

    key = str(art.get("record_key") or f"auto#{stats['normalized']}")
    base_key, n = key, 1
    while key in seen_keys:  # several artifacts from one source record
        n += 1
        key = f"{base_key}~{n}"
    seen_keys.add(key)
    art["record_key"] = key
    art["provenance"] = provenance
    art["id"] = artifact_id(run["id"], key)
    art["run_id"] = run["id"]
    art["case_id"] = art.get("case_id") or run["case_id"]
    art.setdefault("created_at", datetime.now(UTC).isoformat())
    return art


def to_row(art: dict) -> tuple:
    """Artifact dict → tuple in ARTIFACT_COLUMNS order."""
    values = []
    for column in ARTIFACT_COLUMNS:
        value = art.get(column)
        if column in _JSON_COLUMNS:
            value = json.dumps(value if value is not None else ({} if column != "tags" else []))
        values.append(value)
    return tuple(values)


async def next_artifact_sequence(conn: aiosqlite.Connection) -> int:
    cursor = await conn.execute(
        "SELECT MAX(CAST(SUBSTR(artifact_number, 5) AS INTEGER)) FROM artifacts"
    )
    row = await cursor.fetchone()
    return (row[0] or 0) + 1


async def bulk_insert(
    conn: aiosqlite.Connection,
    artifacts: Iterable[dict],
    batch_size: int = BATCH_SIZE,
) -> int:
    """Insert (or replace, by id) artifacts in batches; one commit at the end."""
    sql = (
        f"INSERT OR REPLACE INTO artifacts ({', '.join(ARTIFACT_COLUMNS)}) "
        f"VALUES ({', '.join('?' * len(ARTIFACT_COLUMNS))})"
    )
    batch: list[tuple] = []
    count = 0
    for art in artifacts:
        batch.append(to_row(art))
        if len(batch) >= batch_size:
            await conn.executemany(sql, batch)
            count += len(batch)
            batch = []
    if batch:
        await conn.executemany(sql, batch)
        count += len(batch)
    await conn.commit()
    return count


def normalized_root(run_output_path: str) -> Path:
    """``<base>/<tool>/<RUN>`` → ``<parent of base>/normalized``."""
    return Path(run_output_path).parent.parent.parent / "normalized"


def _write_jsonl(path: Path, artifacts: list[dict]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    with path.open("w", encoding="utf-8") as fh:
        for art in artifacts:
            line = json.dumps(art, default=str, sort_keys=True) + "\n"
            fh.write(line)
            digest.update(line.encode("utf-8"))
    return digest.hexdigest()


async def normalize_run(
    conn: aiosqlite.Connection,
    run: dict,
    normalizer,
    keep_numbers: dict[str, str] | None = None,
) -> dict:
    """Normalize one tool run's output into the case database.

    Args:
        conn: Database connection.
        run: The tool run (dict with id, run_number, case_id, evidence_id,
            tool_name, tool_version, output_path).
        normalizer: The tool's normalizer instance.
        keep_numbers: ``{artifact id: ART-NNN}`` to reuse on a re-run, so an
            artifact keeps its number as well as its id.

    Returns:
        Normalization stats (also stored in ``tool_runs.normalization_stats``).
    """
    stats = new_stats()
    if run.get("input_path"):
        normalizer.input_path = run["input_path"]
    raw = normalizer.normalize_directory(
        run["output_path"],
        case_id=run["case_id"],
        evidence_id=run.get("evidence_id"),
        run_id=run["id"],
    )
    stats["rows_read"] = normalizer.stats.get("rows_read", 0)
    stats["skipped"] = normalizer.stats.get("skipped", 0)
    stats["errors"] = normalizer.stats.get("errors", 0)
    for reason, n in (normalizer.stats.get("error_reasons") or {}).items():
        stats["reasons"][reason] = stats["reasons"].get(reason, 0) + n
    for reason, n in (normalizer.stats.get("skip_reasons") or {}).items():
        stats["reasons"][f"skipped: {reason}"] = stats["reasons"].get(f"skipped: {reason}", 0) + n

    seen: set[str] = set()
    artifacts = []
    for art in raw:
        artifacts.append(enrich(art, run, stats, seen))
        stats["normalized"] += 1

    async with db_lock(conn):
        return await _store_run(conn, run, artifacts, stats, keep_numbers)


async def _store_run(conn, run: dict, artifacts: list[dict], stats: dict,
                     keep_numbers: dict[str, str] | None) -> dict:
    # Numbering computed once for the whole run (not a COUNT per row)
    sequence = await next_artifact_sequence(conn)
    keep_numbers = keep_numbers or {}
    for art in artifacts:
        if art["id"] in keep_numbers:
            art["artifact_number"] = keep_numbers[art["id"]]
        else:
            art["artifact_number"] = f"ART-{sequence:03d}"
            sequence += 1

    # JSONL per artifact type, recorded with its hash
    await conn.execute("DELETE FROM normalized_files WHERE run_id = ?", (run["id"],))
    by_type: dict[str, list[dict]] = {}
    for art in artifacts:
        by_type.setdefault(art["artifact_type"], []).append(art)
    root = normalized_root(run["output_path"])
    files = []
    for artifact_type, items in sorted(by_type.items()):
        path = root / artifact_type / f"{run['run_number']}.jsonl"
        sha = _write_jsonl(path, items)
        await conn.execute(
            """INSERT INTO normalized_files
            (id, run_id, case_id, artifact_type, path, sha256, records, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (uuid4().hex, run["id"], run["case_id"], artifact_type, str(path), sha,
             len(items), datetime.now(UTC).isoformat()),
        )
        files.append({"path": str(path), "records": len(items), "sha256": sha})

    await bulk_insert(conn, artifacts)
    stats["files"] = files
    await conn.execute(
        "UPDATE tool_runs SET normalization_stats = ? WHERE id = ?",
        (json.dumps(stats), run["id"]),
    )
    await conn.commit()
    log.info("normalization_completed", run=run["run_number"], tool=run["tool_name"],
             normalized=stats["normalized"], errors=stats["errors"],
             timestamp_unparsed=stats["timestamp_unparsed"])
    return stats


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


# ---------------------------------------------------------------------------
# Supertimeline events (Plaso, Sleuth Kit) — streamed into ``timeline_events``
# ---------------------------------------------------------------------------

TIMELINE_COLUMNS = (
    "id", "case_id", "evidence_id", "run_id", "timestamp", "timestamp_desc", "message",
    "source", "parser", "source_short", "source_long", "filename", "hostname", "username",
    "data", "provenance", "record_key",
)
_TIMELINE_JSON = {"data", "provenance"}
TIMELINE_ARTIFACT_PREFIX = "timeline."  # normalized_files.artifact_type of event files


def enrich_event(event: dict, run: dict, stats: dict, seen_keys: set[str]) -> dict:
    """Envelope of one timeline event: UTC time (never invented), id, provenance."""
    provenance = {
        "tool": run["tool_name"], "tool_version": run.get("tool_version"),
        "run_id": run["id"], "run_number": run["run_number"],
        "evidence_id": run.get("evidence_id"), **(event.get("provenance") or {}),
    }
    raw = event.get("timestamp")
    iso, error = to_utc_iso(raw)
    if error:
        stats["timestamp_unparsed"] += 1
        _reason(stats, f"timestamp: {error.split(':')[0]}")
        provenance["raw_timestamp"] = str(raw)
    event["timestamp"] = iso
    if not iso:
        event["timestamp_desc"] = None
    key = str(event.get("record_key") or f"auto#{stats['normalized']}")
    base_key, n = key, 1
    while key in seen_keys:
        n += 1
        key = f"{base_key}~{n}"
    seen_keys.add(key)
    event.update(record_key=key, provenance=provenance, id=artifact_id(run["id"], key),
                 run_id=run["id"], case_id=run["case_id"],
                 evidence_id=event.get("evidence_id") or run.get("evidence_id"))
    return event


def timeline_row(event: dict) -> tuple:
    return tuple(
        json.dumps(event.get(c) or {}) if c in _TIMELINE_JSON else event.get(c)
        for c in TIMELINE_COLUMNS
    )


async def insert_timeline_batch(conn: aiosqlite.Connection, events: list[dict]) -> None:
    sql = (f"INSERT OR IGNORE INTO timeline_events ({', '.join(TIMELINE_COLUMNS)}) "
           f"VALUES ({', '.join('?' * len(TIMELINE_COLUMNS))})")
    await conn.executemany(sql, [timeline_row(e) for e in events])


async def stream_timeline_events(
    conn: aiosqlite.Connection,
    run: dict,
    events: Iterable[dict],
    source: str,
    jsonl_path: Path,
    batch_size: int = BATCH_SIZE,
) -> dict:
    """Insert timeline events of one run in batches, writing the normalized JSONL.

    Memory stays bounded whatever the number of events: rows are enriched,
    written to the JSONL and inserted batch by batch. Events already stored
    for this run and source are replaced (re-import).
    """
    stats = new_stats()
    seen: set[str] = set()
    await conn.execute("PRAGMA synchronous = NORMAL")
    await conn.execute("DELETE FROM timeline_events WHERE run_id = ? AND source = ?", (run["id"], source))
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    batch: list[dict] = []
    with jsonl_path.open("w", encoding="utf-8") as fh:
        for event in events:
            stats["rows_read"] += 1
            if event is None:
                stats["skipped"] += 1
                continue
            event = enrich_event(event, run, stats, seen)
            line = json.dumps(event, default=str, sort_keys=True) + "\n"
            fh.write(line)
            digest.update(line.encode("utf-8"))
            batch.append(event)
            stats["normalized"] += 1
            if len(batch) >= batch_size:
                await insert_timeline_batch(conn, batch)
                batch = []
        if batch:
            await insert_timeline_batch(conn, batch)
    sha = digest.hexdigest()
    artifact_type = f"{TIMELINE_ARTIFACT_PREFIX}{source}"
    await conn.execute("DELETE FROM normalized_files WHERE run_id = ? AND artifact_type = ?",
                       (run["id"], artifact_type))
    await conn.execute(
        """INSERT INTO normalized_files
        (id, run_id, case_id, artifact_type, path, sha256, records, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (uuid4().hex, run["id"], run["case_id"], artifact_type, str(jsonl_path), sha,
         stats["normalized"], datetime.now(UTC).isoformat()),
    )
    await conn.commit()
    await conn.execute("PRAGMA synchronous = FULL")
    stats["files"] = [{"path": str(jsonl_path), "records": stats["normalized"], "sha256": sha}]
    log.info("timeline_events_imported", run=run["run_number"], source=source,
             events=stats["normalized"], timestamp_unparsed=stats["timestamp_unparsed"])
    return stats


def iter_jsonl(path: Path) -> Iterable[dict]:
    """Stream a JSONL file (for files too large to load at once)."""
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
