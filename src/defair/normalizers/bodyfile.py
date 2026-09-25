"""Sleuth Kit bodyfile (``fls -r -m``) → timeline events (streamed).

One event per distinct time of each file, like ``mactime``: the four
``$STANDARD_INFORMATION`` times (NTFS) or inode times, grouped when equal,
flagged ``m`` (modified), ``a`` (accessed), ``c`` (metadata changed), ``b``
(born). The bodyfile is parsed directly — no ``mactime`` round trip, no local
time zone conversion: epoch seconds are UTC.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from defair.workers.tsk import macb_events, parse_bodyfile_line

MACB_LABELS = {"m": "Modified", "a": "Accessed", "c": "Metadata Changed", "b": "Born"}


def describe(flags: str) -> str:
    return " / ".join(MACB_LABELS[f] for f in flags if f != ".") + f" ({flags})"


def iter_bodyfile(path: Path, partition: dict | None = None) -> Iterator[dict | None]:
    partition = partition or {}
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            entry = parse_bodyfile_line(line)
            if entry is None:
                yield None
                continue
            deleted = "(deleted" in entry["name"]
            for epoch, flags in macb_events(entry):
                yield {
                    "timestamp": epoch,
                    "timestamp_desc": describe(flags),
                    "message": f"{entry['name']} [{flags}] {entry['size']} bytes",
                    "source": "tsk",
                    "parser": "fls",
                    "source_short": "FILE",
                    "source_long": "Sleuth Kit bodyfile",
                    "filename": entry["name"],
                    "data": {"inode": entry["inode"], "mode": entry["mode"], "size": entry["size"],
                             "uid": entry["uid"], "gid": entry["gid"], "md5": entry["md5"],
                             "macb": flags, "deleted": deleted,
                             "partition": partition.get("index"), "offset": partition.get("offset")},
                    "provenance": {"bodyfile": path.name, "partition": partition.get("description")},
                    "record_key": f"{partition.get('index', 0)}:{entry['inode']}:{entry['name']}:{flags}",
                }
