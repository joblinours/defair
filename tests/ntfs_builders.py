"""Byte-level builders for synthetic NTFS structures (test fixtures)."""

from __future__ import annotations

import struct

FT = 132_000_000_000_000_000  # 2019-04-17


def file_name(name: str, parent: int = 5, ts: int = FT, size: int = 1234) -> bytes:
    n = name.encode("utf-16-le")
    return struct.pack("<QQQQQQQIIBB", parent | (5 << 48), ts, ts + 1, ts + 2, ts + 3,
                       4096, size, 0x20, 0, len(name), 1) + n


def index_entry(name: str, entry: int, last: bool = False, **kw) -> bytes:
    if last:
        return struct.pack("<QHHI", 0, 16, 0, 0x02)
    key = file_name(name, **kw)
    length = (16 + len(key) + 7) & ~7
    raw = struct.pack("<QHHI", entry | (1 << 48), length, len(key), 0) + key
    return raw + b"\0" * (length - len(raw))


def with_fixup(buf: bytearray, usa_offset: int) -> bytes:
    """Write an update sequence array (value 0x0001) over the sector ends."""
    count = len(buf) // 512 + 1
    struct.pack_into("<HH", buf, 4, usa_offset, count)
    buf[usa_offset:usa_offset + 2] = b"\x01\x00"
    for i in range(1, count):
        end = i * 512
        buf[usa_offset + i * 2:usa_offset + i * 2 + 2] = buf[end - 2:end]
        buf[end - 2:end] = b"\x01\x00"
    return bytes(buf)


def indx_buffer(live: list[bytes], slack: list[bytes], size: int = 4096) -> bytes:
    """INDX buffer: live entries (+ end marker) then remnants in the slack."""
    buf = bytearray(size)
    buf[0:4] = b"INDX"
    first = 0x40 - 0x18
    body = b"".join(live) + index_entry("", 0, last=True)
    buf[0x40:0x40 + len(body)] = body
    total = first + len(body)
    tail = b"".join(slack)
    buf[0x40 + len(body):0x40 + len(body) + len(tail)] = tail
    struct.pack_into("<III", buf, 0x18, first, total, size - 0x18)
    return with_fixup(buf, 0x28)


def lfs_record(lsn: int, redo_op: int, undo_op: int, redo: bytes, undo: bytes) -> bytes:
    client = bytearray(0x20)
    redo_off = 0x20
    undo_off = (redo_off + len(redo) + 7) & ~7
    struct.pack_into("<HHHHHH", client, 0, redo_op, undo_op, redo_off, len(redo), undo_off, len(undo))
    client = bytes(client) + redo + b"\0" * (undo_off - redo_off - len(redo)) + undo
    header = struct.pack("<QQQIHHIIH6x", lsn, lsn - 1, 0, len(client), 0, 0, 1, 7, 0)
    raw = header + client
    return raw + b"\0" * (((len(raw) + 7) & ~7) - len(raw))


def logfile(records: list[bytes], page: int = 4096) -> bytes:
    rstr = bytearray(page)
    rstr[0:4] = b"RSTR"
    struct.pack_into("<II", rstr, 0x10, page, page)
    rcrd = bytearray(page)
    rcrd[0:4] = b"RCRD"
    body = b"".join(records)
    rcrd[0x40:0x40 + len(body)] = body
    rcrd_bytes = with_fixup(rcrd, 0x28)
    return bytes(rstr) * 2 + rcrd_bytes


def file_record(name: str, in_use: bool = True) -> bytes:
    rec = bytearray(1024)
    rec[0:4] = b"FILE"
    struct.pack_into("<H", rec, 0x14, 0x38)
    struct.pack_into("<H", rec, 0x16, 1 if in_use else 0)
    si = struct.pack("<QQQQI", FT, FT + 10, FT + 20, FT + 30, 0x20) + b"\0" * 12
    fn = file_name(name)
    offset = 0x38
    for attr_type, value in ((0x10, si), (0x30, fn)):
        length = (0x18 + len(value) + 7) & ~7
        header = struct.pack("<IIBBHHH", attr_type, length, 0, 0, 0, 0, 0) + struct.pack("<IH2x", len(value), 0x18)
        rec[offset:offset + 0x18] = header
        rec[offset + 0x18:offset + 0x18 + len(value)] = value
        offset += length
    struct.pack_into("<I", rec, offset, 0xFFFFFFFF)
    return with_fixup(rec, 0x30)
