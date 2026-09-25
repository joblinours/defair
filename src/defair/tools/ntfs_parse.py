"""Low-level NTFS structures shared by the INDX slack and $LogFile parsers.

Pure functions over bytes (no filesystem access), so they work the same on
buffers read through Dissect from an image and on loose files from a
collection. Only the structures DEFAIR decodes are covered:

- ``$FILE_NAME`` attribute values (the key of every ``$I30`` index entry);
- ``$I30`` index entries and ``INDX`` index buffers (live + slack space);
- FILE records (MFT segments), for their ``$STANDARD_INFORMATION`` and
  ``$FILE_NAME`` attributes.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

SECTOR_SIZE = 512
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
# Plausible FILETIMEs for carving: 1995-01-01 → 2100-01-01
FILETIME_MIN = 124_860_384_000_000_000
FILETIME_MAX = 157_766_016_000_000_000

FILE_NAME_HEADER = struct.Struct("<QQQQQQQIIBB")  # 0x42 bytes before the name
INDEX_ENTRY_HEADER = struct.Struct("<QHHI")  # file ref, length, key length, flags
NAMESPACES = {0: "POSIX", 1: "Win32", 2: "DOS", 3: "Win32&DOS"}

ATTR_STANDARD_INFORMATION = 0x10
ATTR_FILE_NAME = 0x30


def filetime(value: int) -> str | None:
    """FILETIME (100 ns since 1601) → ISO 8601 UTC with 7 fractional digits."""
    if not value or value < 0:
        return None
    try:
        dt = FILETIME_EPOCH + timedelta(microseconds=value // 10)
    except OverflowError:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value % 10_000_000:07d}Z"


def _plausible_time(value: int) -> bool:
    return FILETIME_MIN <= value <= FILETIME_MAX


def split_ref(ref: int) -> tuple[int, int]:
    """MFT segment reference → (entry number, sequence number)."""
    return ref & 0xFFFFFFFFFFFF, ref >> 48


def parse_file_name(buf: bytes, offset: int = 0, strict: bool = False,
                    limit: int | None = None) -> dict | None:
    """Decode a ``$FILE_NAME`` value at ``offset``.

    With ``strict`` (carving), the value must look genuine: plausible
    timestamps, a valid namespace, a printable UTF-16 name.
    """
    limit = len(buf) if limit is None else limit
    end = offset + FILE_NAME_HEADER.size
    if end > limit:
        return None
    (parent, created, modified, mft_modified, accessed, allocated, real, flags,
     _reparse, name_length, namespace) = FILE_NAME_HEADER.unpack_from(buf, offset)
    if name_length == 0 or end + name_length * 2 > limit:
        return None
    if strict:
        if namespace > 3:
            return None
        if not all(_plausible_time(t) for t in (created, modified, mft_modified, accessed)):
            return None
        if real > allocated and allocated != 0:
            return None
    try:
        name = buf[end:end + name_length * 2].decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    if strict and (not name.isprintable() or any(c in name for c in '/\\:*?"<>|\x00')):
        return None
    parent_entry, parent_seq = split_ref(parent)
    return {
        "name": name,
        "namespace": NAMESPACES.get(namespace, str(namespace)),
        "parent_entry": parent_entry,
        "parent_sequence": parent_seq,
        "created": filetime(created),
        "modified": filetime(modified),
        "mft_modified": filetime(mft_modified),
        "accessed": filetime(accessed),
        "allocated_size": allocated,
        "real_size": real,
        "flags": flags,
        "_length": FILE_NAME_HEADER.size + name_length * 2,
    }


def parse_index_entry(buf: bytes, offset: int = 0) -> dict | None:
    """Decode a ``$I30`` index entry (header + ``$FILE_NAME`` key)."""
    if offset + INDEX_ENTRY_HEADER.size > len(buf):
        return None
    ref, length, key_length, flags = INDEX_ENTRY_HEADER.unpack_from(buf, offset)
    if flags & 0x02 or key_length < FILE_NAME_HEADER.size:  # last entry: no key
        return None
    fn = parse_file_name(buf, offset + INDEX_ENTRY_HEADER.size)
    if fn is None:
        return None
    entry, seq = split_ref(ref)
    return {**fn, "entry_number": entry, "sequence_number": seq, "_entry_length": length}


def apply_fixup(buf: bytes) -> bytes:
    """Apply the update sequence array of a multi-sector record (INDX / FILE / RCRD).

    A buffer whose fixups do not match is returned as is: slack carving and
    damaged records are still worth reading.
    """
    if len(buf) < SECTOR_SIZE:
        return buf
    usa_offset, usa_count = struct.unpack_from("<HH", buf, 4)
    if usa_count < 2 or usa_offset + usa_count * 2 > len(buf):
        return buf
    data = bytearray(buf)
    sample = data[usa_offset:usa_offset + 2]
    for i in range(1, usa_count):
        end = i * SECTOR_SIZE
        if end > len(data):
            break
        if data[end - 2:end] != sample:
            return buf
        data[end - 2:end] = data[usa_offset + i * 2:usa_offset + i * 2 + 2]
    return bytes(data)


def carve_file_names(buf: bytes, start: int, end: int, step: int = 2) -> Iterator[tuple[int, dict]]:
    """Find genuine-looking ``$FILE_NAME`` keys in ``buf[start:end]``.

    Slack space holds remnants of index entries that were removed or shifted:
    their 16-byte entry header may be overwritten, so the key is searched
    directly and the header, when still intact, gives the file reference.
    """
    offset = max(start, INDEX_ENTRY_HEADER.size)
    while offset + FILE_NAME_HEADER.size < end:
        fn = parse_file_name(buf, offset, strict=True, limit=end)
        if fn is None:
            offset += step
            continue
        header = offset - INDEX_ENTRY_HEADER.size
        ref, length, key_length, _ = INDEX_ENTRY_HEADER.unpack_from(buf, header)
        if key_length == fn["_length"] and length >= key_length + INDEX_ENTRY_HEADER.size:
            fn["entry_number"], fn["sequence_number"] = split_ref(ref)
            fn["header_intact"] = True
        else:
            fn["header_intact"] = False
        yield offset, fn
        offset += (fn["_length"] + 7) & ~7


def parse_indx_buffer(raw: bytes) -> tuple[list[dict], list[tuple[int, dict]]] | None:
    """Split an ``INDX`` buffer into live entries and carved slack entries.

    Returns:
        (live entries, [(offset in buffer, slack entry)]) or None when the
        buffer is not an index buffer.
    """
    if raw[:4] != b"INDX" or len(raw) < 0x40:
        return None
    buf = apply_fixup(raw)
    first, total, allocated = struct.unpack_from("<III", buf, 0x18)
    base = 0x18
    live_start, live_end = base + first, min(base + total, len(buf))
    slack_end = min(base + allocated, len(buf)) if allocated else len(buf)

    live = _live_entries(buf, live_start, live_end)
    slack = list(carve_file_names(buf, live_end, slack_end))
    return live, slack


def _live_entries(buf: bytes, start: int, end: int) -> list[dict]:
    entries = []
    offset = start
    while offset + INDEX_ENTRY_HEADER.size <= end:
        _, length, _, flags = INDEX_ENTRY_HEADER.unpack_from(buf, offset)
        if length < INDEX_ENTRY_HEADER.size:
            break
        entry = parse_index_entry(buf, offset)
        if entry:
            entries.append(entry)
        if flags & 0x02:
            break
        offset += length
    return entries


def parse_index_root(value: bytes) -> list[dict]:
    """Live entries of a resident ``$INDEX_ROOT`` value."""
    if len(value) < 0x20:
        return []
    first, total = struct.unpack_from("<II", value, 0x10)
    return _live_entries(value, 0x10 + first, min(0x10 + total, len(value)))


def iter_attributes(record: bytes) -> Iterator[tuple[int, bytes]]:
    """Yield (type, resident value) of each resident attribute of a FILE record."""
    if record[:4] != b"FILE" or len(record) < 0x30:
        return
    offset = struct.unpack_from("<H", record, 0x14)[0]
    while offset + 0x18 <= len(record):
        attr_type, length = struct.unpack_from("<II", record, offset)
        if attr_type == 0xFFFFFFFF or length < 0x18 or offset + length > len(record):
            return
        non_resident = record[offset + 8]
        if not non_resident:
            value_length, value_offset = struct.unpack_from("<IH", record, offset + 0x10)
            start = offset + value_offset
            yield attr_type, record[start:start + value_length]
        offset += length


def parse_standard_information(value: bytes) -> dict | None:
    if len(value) < 0x24:
        return None
    created, modified, mft_modified, accessed, attributes = struct.unpack_from("<QQQQI", value)
    return {
        "si_created": filetime(created),
        "si_modified": filetime(modified),
        "si_mft_modified": filetime(mft_modified),
        "si_accessed": filetime(accessed),
        "si_attributes": attributes,
    }


def parse_file_record(record: bytes) -> dict | None:
    """Names and timestamps of a FILE record (``$SI`` + every ``$FN``)."""
    if record[:4] != b"FILE":
        return None
    record = apply_fixup(record)
    flags = struct.unpack_from("<H", record, 0x16)[0]
    info: dict = {"in_use": bool(flags & 0x01), "is_directory": bool(flags & 0x02), "names": []}
    for attr_type, value in iter_attributes(record):
        if attr_type == ATTR_STANDARD_INFORMATION:
            info.update(parse_standard_information(value) or {})
        elif attr_type == ATTR_FILE_NAME:
            fn = parse_file_name(value)
            if fn:
                info["names"].append(fn)
    return info


def latest(*values: str | None) -> str | None:
    """Most recent of several ISO timestamps (same format → string order)."""
    present = [v for v in values if v]
    return max(present) if present else None
