"""Plaso ``psort -o json_line`` → timeline events (streamed).

Each line is one Plaso event: ``data_type``, ``parser``, ``timestamp``
(microseconds, UTC), ``date_time`` (the source value at its own precision),
``timestamp_desc``, ``message``, the pathspec and the parser's attributes.

The event time comes from ``date_time`` when its class is known (FILETIME
keeps its 100 ns precision), else from ``timestamp``; a zero / missing time
stays ``None`` (Plaso's "Not a time") with the raw value kept — never
"now". The record key is a hash of the whole event line, so re-running psort
on the same storage yields the same ids.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
# date_time class → (epoch, ticks per second)
_DATE_TIME_CLASSES = {
    "Filetime": (_FILETIME_EPOCH, 10_000_000),
    "PosixTime": (_EPOCH, 1),
    "PosixTimeInMilliseconds": (_EPOCH, 1_000),
    "PosixTimeInMicroseconds": (_EPOCH, 1_000_000),
    "PosixTimeInNanoseconds": (_EPOCH, 1_000_000_000),
    "JavaTime": (_EPOCH, 1_000),
    "WebKitTime": (_FILETIME_EPOCH, 1_000_000),
}
# data_type prefix → short source label (l2tcsv style)
SOURCE_SHORT = (
    ("fs:", "FILE"), ("windows:evtx", "EVT"), ("windows:evt", "EVT"), ("windows:registry", "REG"),
    ("windows:prefetch", "LOG"), ("windows:lnk", "LNK"), ("windows:shell_item", "LNK"),
    ("windows:volume", "LOG"), ("windows:srum", "LOG"), ("windows:tasks", "LOG"),
    ("chrome:", "WEBHIST"), ("firefox:", "WEBHIST"), ("msie:", "WEBHIST"), ("safari:", "WEBHIST"),
    ("olecf:", "OLECF"), ("pe", "PE"), ("syslog", "LOG"), ("linux:", "LOG"),
)
_DROP = {"__container_type__", "__type__", "message", "timestamp", "timestamp_desc", "date_time",
         "parser", "data_type", "display_name", "filename", "hostname", "username"}
MAX_DATA = 16 * 1024


def _iso(epoch: datetime, ticks: int, per_second: int) -> str | None:
    if ticks <= 0:
        return None
    seconds, fraction = divmod(ticks, per_second)
    try:
        dt = epoch + timedelta(seconds=seconds)
    except OverflowError:
        return None
    digits = len(str(per_second)) - 1
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    return f"{base}.{fraction:0{digits}d}Z" if digits else f"{base}Z"


def event_time(event: dict) -> str | int | None:
    date_time = event.get("date_time") or {}
    known = _DATE_TIME_CLASSES.get(date_time.get("__class_name__", ""))
    if known and isinstance(date_time.get("timestamp"), int):
        return _iso(known[0], date_time["timestamp"], known[1])
    timestamp = event.get("timestamp")
    if isinstance(timestamp, int):
        return _iso(_EPOCH, timestamp, 1_000_000)
    return timestamp


def source_short(data_type: str) -> str:
    return next((short for prefix, short in SOURCE_SHORT if data_type.startswith(prefix)), "LOG")


def normalize_event(event: dict, line: str) -> dict:
    data_type = event.get("data_type") or ""
    data = {k: v for k, v in event.items() if k not in _DROP}
    encoded = json.dumps(data, default=str)
    if len(encoded) > MAX_DATA:
        data = {"truncated": True, "json": encoded[:MAX_DATA]}
    pathspec = event.get("pathspec") or {}
    time = event_time(event)
    return {
        "timestamp": time,
        "timestamp_desc": event.get("timestamp_desc"),
        "message": event.get("message"),
        "source": "plaso",
        "parser": event.get("parser"),
        "source_short": source_short(data_type),
        "source_long": data_type,
        "filename": event.get("filename") or pathspec.get("location") or event.get("display_name"),
        "hostname": event.get("hostname"),
        "username": event.get("username"),
        "data": data,
        "provenance": {"display_name": event.get("display_name"), "data_type": data_type,
                       **({"raw_timestamp": str(event.get("timestamp"))} if time is None else {})},
        "record_key": hashlib.sha1(line.encode("utf-8"), usedforsecurity=False).hexdigest(),
    }


def iter_plaso(path: Path, stats: dict | None = None) -> Iterator[dict | None]:
    """Timeline events of a ``json_line`` file (``None`` for an unreadable line)."""
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except ValueError:
                if stats is not None:
                    stats["errors"] = stats.get("errors", 0) + 1
                yield None
                continue
            if event.get("__container_type__") not in (None, "event"):
                yield None
                continue
            yield normalize_event(event, line)
