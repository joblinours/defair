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
