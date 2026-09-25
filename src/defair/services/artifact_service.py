"""Artifact service — search, deep inspection and match explanation.

``get_artifact`` gives everything known about one artifact: all fields, the
normalized data, provenance (tool, pinned version, run), the findings that
reference it, the evidence file it came from — resolved to a real path inside
the container — and, on demand, the raw source:

- the complete EVTX event (by record id, read with pyevtx-rs);
- a hex / ASCII dump around each YARA match offset.

``explain_match`` turns a YARA / Sigma / Hayabusa detection into what an
analyst needs to verify it by hand: the evidence file, the event or offset,
and the exact pattern / field values that hit the rule, plus the rule file.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path, PureWindowsPath

import aiosqlite
import structlog

log = structlog.get_logger(component="artifact_service")

HEX_CONTEXT = 64  # bytes shown before / after a YARA match
_SIGMA_HEADER = re.compile(r"(\w+)=(\S+)")
_YARA_MATCH = re.compile(r"^(?P<id>\$\w*): (?P<value>.*) @ (?P<offset>\d+)$")
_FOLDER_ARG = re.compile(r"--folder (.+?) --signatures ")


def _loads(value, default):
    if value in (None, ""):
        return default
    if isinstance(value, dict | list):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _row(row) -> dict:
    art = dict(row)
    art["data"] = _loads(art.get("data"), {})
    art["tags"] = _loads(art.get("tags"), [])
    art["provenance"] = _loads(art.get("provenance"), {})
    return art


# ---------------------------------------------------------------------------
# Lookup / search
# ---------------------------------------------------------------------------


async def find_artifact(conn: aiosqlite.Connection, ref: str) -> dict | None:
    """By artifact number (ART-NNN, case-insensitive) or id."""
    cursor = await conn.execute(
        "SELECT * FROM artifacts WHERE id = ? OR artifact_number = ?", (ref, ref.upper())
    )
    row = await cursor.fetchone()
    return _row(row) if row else None


async def search_artifacts(
    conn: aiosqlite.Connection,
    case_id: str | None = None,
    artifact_type: str | None = None,
    category: str | None = None,
    tool: str | None = None,
    contains: str | None = None,
    hostname: str | None = None,
    username: str | None = None,
    severity: str | None = None,
    since: str | None = None,
    until: str | None = None,
    run: str | None = None,
    order: str = "desc",
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Filtered, paginated artifact listing.

    ``contains`` searches description, message, source file and the whole
    normalized data (case-insensitive). ``since`` / ``until`` are ISO dates.
    """
    where, params = ["1=1"], []
    if case_id:
        from defair.services.case_service import resolve_case_id

        where.append("case_id = ?")
        params.append(await resolve_case_id(conn, case_id))
    if artifact_type:
        where.append("artifact_type LIKE ?")
        params.append(f"%{artifact_type}%")
    if category:
        where.append("category = ?")
        params.append(category)
    if tool:
        where.append("source_tool = ?")
        params.append(tool)
    if hostname:
        where.append("hostname LIKE ?")
        params.append(f"%{hostname}%")
    if username:
        where.append("username LIKE ?")
        params.append(f"%{username}%")
    if severity:
        where.append("severity = ?")
        params.append(severity)
    if since:
        where.append("timestamp >= ?")
        params.append(since)
    if until:
        where.append("timestamp <= ?")
        params.append(until)
    if run:
        where.append("run_id IN (SELECT id FROM tool_runs WHERE run_number = ? OR id = ?)")
        params.extend([run.upper(), run])
    if contains:
        where.append("(description LIKE ? OR message LIKE ? OR source_file LIKE ? OR data LIKE ?)")
        params.extend([f"%{contains}%"] * 4)
    clause = " AND ".join(where)
    direction = "ASC" if order.lower() == "asc" else "DESC"

    cursor = await conn.execute(f"SELECT COUNT(*) FROM artifacts WHERE {clause}", params)
    total = (await cursor.fetchone())[0]
    cursor = await conn.execute(
        f"SELECT * FROM artifacts WHERE {clause} "
        f"ORDER BY timestamp IS NULL, timestamp {direction}, artifact_number LIMIT ? OFFSET ?",
        [*params, limit, offset],
    )
    items = [_row(r) for r in await cursor.fetchall()]
    return {"total": total, "offset": offset, "limit": limit, "items": items}


async def context(conn: aiosqlite.Connection, art: dict, minutes: float = 5, limit: int = 40) -> list[dict]:
    """Artifacts of the same case within ± ``minutes`` of this one (timeline context)."""
    if not art.get("timestamp"):
        return []
    from datetime import datetime, timedelta

    try:  # stored as ISO 8601 UTC; seconds precision is enough for a window
        ts = datetime.strptime(art["timestamp"][:19].replace(" ", "T"), "%Y-%m-%dT%H:%M:%S")  # noqa: DTZ007
    except ValueError:
        return []
    fmt = "%Y-%m-%dT%H:%M:%S"
    low = (ts - timedelta(minutes=minutes)).strftime(fmt)
    high = (ts + timedelta(minutes=minutes)).strftime(fmt) + "~"  # '~' sorts after any fraction / Z
    cursor = await conn.execute(
        """SELECT artifact_number, timestamp, timestamp_desc, artifact_type, source_tool,
                  hostname, username, description
           FROM artifacts WHERE case_id = ? AND timestamp BETWEEN ? AND ?
           ORDER BY timestamp LIMIT ?""",
        (art["case_id"], low, high, limit),
    )
    return [dict(r) for r in await cursor.fetchall()]


# ---------------------------------------------------------------------------
# Evidence path resolution / raw source
# ---------------------------------------------------------------------------


async def _tool_run(conn: aiosqlite.Connection, run_id: str | None) -> dict | None:
    if not run_id:
        return None
    cursor = await conn.execute("SELECT * FROM tool_runs WHERE id = ?", (run_id,))
    row = await cursor.fetchone()
    if not row:
        return None
    run = dict(row)
    run["parameters"] = _loads(run.get("parameters"), {})
    return run


def scan_root(run: dict | None) -> str | None:
    """The input a tool run processed (recorded since v0.4, else parsed from the command)."""
    if not run:
        return None
    root = (run.get("parameters") or {}).get("input_path")
    if root:
        return root
    match = _FOLDER_ARG.search(run.get("command") or "")
    return match.group(1) if match else None


def resolve_evidence_path(root: str | None, reported: str | None) -> str | None:
    """Real path (inside the container) of a file a tool reported.

    Raijin reports paths relative to the scanned folder ("/sub/x.evtx") or,
    for KAPE / Velociraptor layouts, the original Windows path ("C:\\…").
    """
    if not reported:
        return None
    if os.path.isabs(reported) and os.path.exists(reported):
        return reported
    if not root:
        return None
    root_path = Path(root)
    candidate = root_path / reported.lstrip("/\\")
    if candidate.exists():
        return str(candidate)
    win = PureWindowsPath(reported)
    if win.drive:
        tail = [p for p in win.parts[1:]]
        for drive_dir in root_path.rglob(win.drive.rstrip(":")):
            if drive_dir.is_dir():
                probe = drive_dir.joinpath(*tail)
                if probe.exists():
                    return str(probe)
    return None


def evtx_record(path: str, record_id: int) -> dict | None:
    """The complete event ``record_id`` of an EVTX file (flattened + raw JSON)."""
    try:
        from evtx import PyEvtxParser
    except ImportError:
        return None
    from defair.normalizers.evtx_flatten import flatten_event

    for record in PyEvtxParser(path).records_json():
        if record.get("event_record_id") == record_id:
            raw = json.loads(record["data"])
            return {"record_id": record_id, "timestamp": record.get("timestamp"),
                    "fields": flatten_event(raw), "raw": raw}
    return None


def hex_dump(path: str, offset: int, length: int = 32, around: int = HEX_CONTEXT) -> list[str]:
    """``xxd``-style lines around ``offset`` (the match itself is bracketed)."""
    start = max(0, offset - around)
    with open(path, "rb") as fh:
        fh.seek(start)
        data = fh.read(around + length + around)
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        pos = start + i
        hexes = []
        for j, b in enumerate(chunk):
            inside = offset <= pos + j < offset + length
            hexes.append(f"[{b:02x}]" if inside else f"{b:02x}")
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{pos:08x}  {' '.join(hexes)}  {text}")
    return lines


# ---------------------------------------------------------------------------
# Match explanation (YARA / Sigma / Hayabusa)
# ---------------------------------------------------------------------------


def rule_path(rule: dict) -> str | None:
    """Where the rule file is inside the container."""
    from defair.tools.raijin import RULES_STORE

    file = rule.get("file")
    source = rule.get("source")
    if not file:
        return None
    if source == "custom" or file.startswith("/"):
        return file
    if source and rule.get("engine"):
        return str(RULES_STORE / rule["engine"] / source / file)
    return None


def explain_match(art: dict, root: str | None = None) -> dict:
    """The evidence location and the exact pattern / values behind a detection."""
    data = art.get("data") or {}
    tool = art.get("source_tool")
    info: dict = {
        "artifact": art.get("artifact_number"),
        "timestamp": art.get("timestamp"),
        "hostname": art.get("hostname"),
    }

    if tool == "raijin":
        rule = data.get("rule") or {}
        reported = data.get("host_path") or art.get("source_file")
        info.update({
            "engine": data.get("engine"),
            "rule": rule.get("name"),
            "rule_file": rule_path(rule),
            "reported_path": reported,
            "evidence_path": data.get("evidence_path") or resolve_evidence_path(root, reported),
            "file_sha256": data.get("sha256"),
        })
        strings = data.get("matched_strings") or []
        if data.get("engine") == "sigma":
            header = strings[0] if strings and "=" in strings[0] and ":" not in strings[0].split("=")[0] else ""
            event = dict(_SIGMA_HEADER.findall(header)) if header else {}
            info["event"] = event
            info["matched_fields"] = strings[1:] if header else strings
        else:
            matches = []
            for s in strings:
                m = _YARA_MATCH.match(s)
                matches.append({"identifier": m["id"], "value": m["value"], "offset": int(m["offset"])}
                               if m else {"raw": s})
            info["matched_patterns"] = matches
        return info

    if tool == "hayabusa":
        info.update({
            "engine": "sigma (hayabusa)",
            "rule": data.get("rule_title") or art.get("description"),
            "rule_file": data.get("rule_file"),
            "reported_path": data.get("evtx_file"),
            "evidence_path": resolve_evidence_path(root, data.get("evtx_file")),
            "event": {k: data.get(k) for k in ("channel", "event_id", "record_id") if data.get(k)},
            "matched_fields": [x for x in (data.get("details"), data.get("extra_field_info")) if x],
        })
        return info

    info.update({"engine": tool, "description": art.get("description")})
    return info


def raw_source(explained: dict) -> dict:
    """The raw evidence behind a detection: full EVTX event or YARA hex context."""
    path = explained.get("evidence_path")
    if not path or not os.path.exists(path):
        return {}
    event = explained.get("event") or {}
    record = event.get("RecordID") or event.get("record_id")
    if record and path.lower().endswith(".evtx"):
        try:
            found = evtx_record(path, int(record))
        except Exception as e:  # noqa: BLE001 — damaged EVTX: report, don't crash
            return {"error": f"cannot read EVTX record {record}: {e}"}
        return {"evtx_event": found} if found else {"error": f"record {record} not found in {path}"}
    dumps = []
    for match in explained.get("matched_patterns") or []:
        if "offset" in match:
            try:
                dumps.append({"identifier": match["identifier"], "offset": match["offset"],
                              "hex": hex_dump(path, match["offset"])})
            except OSError as e:
                dumps.append({"offset": match["offset"], "error": str(e)})
    return {"hex_context": dumps} if dumps else {}


# ---------------------------------------------------------------------------
# Deep inspection
# ---------------------------------------------------------------------------


async def get_artifact(
    conn: aiosqlite.Connection,
    ref: str,
    case_id: str | None = None,
    context_minutes: float | None = None,
    raw: bool = True,
) -> dict:
    """Everything about one artifact.

    Args:
        ref: ART-NNN or artifact id.
        case_id: If given, the artifact must belong to this case.
        context_minutes: Also return the case timeline ± this many minutes.
        raw: Read the raw source (full EVTX event / YARA hex context).
    """
    art = await find_artifact(conn, ref)
    if art is None:
        raise ValueError(f"Artifact not found: {ref}")
    if case_id:
        from defair.services.case_service import resolve_case_id

        if art["case_id"] != await resolve_case_id(conn, case_id):
            raise ValueError(f"{art['artifact_number']} does not belong to case {case_id}")

    run = await _tool_run(conn, art.get("run_id"))
    root = scan_root(run)
    result: dict = {"artifact": art}
    if run:
        result["tool_run"] = {k: run.get(k) for k in (
            "run_number", "tool_name", "tool_version", "command", "status", "output_path",
            "started_at", "duration_seconds")}
        result["tool_run"]["input_path"] = root
    cursor = await conn.execute(
        "SELECT path, sha256 FROM normalized_files WHERE run_id = ? AND artifact_type = ?",
        (art.get("run_id"), art.get("artifact_type")),
    )
    row = await cursor.fetchone()
    if row:
        result["normalized_file"] = dict(row)
    cursor = await conn.execute(
        "SELECT finding_number, title, severity FROM findings WHERE artifact_ids LIKE ?",
        (f'%"{art["id"]}"%',),
    )
    result["findings"] = [dict(r) for r in await cursor.fetchall()]

    if art.get("source_tool") in ("raijin", "hayabusa"):
        explained = explain_match(art, root)
        result["match"] = explained
        if raw:
            result["raw"] = raw_source(explained)
    elif raw and art.get("data", {}).get("record_number") and art.get("source_file", "").lower().endswith(".evtx"):
        path = resolve_evidence_path(root, art["source_file"]) or art["source_file"]
        if os.path.exists(path):
            try:
                result["raw"] = {"evtx_event": evtx_record(path, int(art["data"]["record_number"]))}
            except (ValueError, OSError) as e:
                result["raw"] = {"error": str(e)}

    if context_minutes:
        result["context"] = await context(conn, art, context_minutes)
    return result
