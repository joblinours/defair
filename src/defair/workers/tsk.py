"""Sleuth Kit helpers: partition tables (``mmls``) and bodyfiles (``fls -m``)."""

from __future__ import annotations

import re
from collections.abc import Iterator

# 002:  000:000   0000002048   0001026047   0001024000   NTFS / exFAT (0x07)
_MMLS_ROW = re.compile(
    r"^\s*(?P<slot>\d+):\s+(?P<table>\S+)\s+(?P<start>\d+)\s+(?P<end>\d+)\s+(?P<length>\d+)\s+(?P<desc>.*)$")
_NOT_A_VOLUME = ("unallocated", "primary table", "safety table", "gpt header", "partition table",
                 "extended", "meta", "microsoft reserved", "efi system", "bios boot")


def parse_mmls(output: str) -> tuple[int, list[dict]]:
    """(sector size, partitions that may hold a filesystem) from ``mmls`` output."""
    sector = 512
    match = re.search(r"Units are in (\d+)-byte sectors", output)
    if match:
        sector = int(match.group(1))
    partitions = []
    for line in output.splitlines():
        row = _MMLS_ROW.match(line)
        if not row:
            continue
        desc = row.group("desc").strip()
        if row.group("table").lower() == "meta" or any(k in desc.lower() for k in _NOT_A_VOLUME):
            continue
        length = int(row.group("length"))
        if length < 2048:  # < 1 MiB with 512-byte sectors: no filesystem worth listing
            continue
        partitions.append({"slot": int(row.group("slot")), "offset": int(row.group("start")),
                           "length": length, "description": desc})
    for index, partition in enumerate(partitions):
        partition["index"] = index
    return sector, partitions


def parse_bodyfile_line(line: str) -> dict | None:
    """``MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime`` (TSK 3.x+)."""
    parts = line.rstrip("\r\n").split("|")
    if len(parts) < 11:
        return None
    # a file name may contain "|": the 10 other fields are fixed
    md5, name_parts, rest = parts[0], parts[1:-9], parts[-9:]
    inode, mode, uid, gid, size, atime, mtime, ctime, crtime = rest
    return {"md5": md5, "name": "|".join(name_parts), "inode": inode, "mode": mode, "uid": uid,
            "gid": gid, "size": size, "atime": atime, "mtime": mtime, "ctime": ctime, "crtime": crtime}


def macb_events(entry: dict) -> Iterator[tuple[float, str]]:
    """One (epoch, "macb" flags) per distinct time of a bodyfile entry, like mactime."""
    times: dict[float, list[str]] = {}
    for flag, field in (("m", "mtime"), ("a", "atime"), ("c", "ctime"), ("b", "crtime")):
        try:
            value = float(entry.get(field) or 0)
        except ValueError:
            continue
        if value > 0:
            times.setdefault(value, []).append(flag)
    for value, flags in sorted(times.items()):
        yield value, "".join(f if f in flags else "." for f in "macb")
