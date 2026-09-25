"""Native NTFS ``$LogFile`` parser — the operations DEFAIR can decode.

``$LogFile`` is NTFS's transaction journal (typically 64 MiB, minutes to
hours of activity). Each record carries a redo and an undo operation on
metadata. A subset reveals file activity even when the MFT record and the
USN journal have been overwritten:

==============================  =============================================
Redo operation                  Reported as
==============================  =============================================
AddIndexEntryRoot / Allocation  ``file_linked``   — name added to a folder
DeleteIndexEntryRoot / Alloc.   ``file_unlinked`` — name removed (undo data)
InitializeFileRecordSegment     ``record_initialized`` — new FILE record
DeallocateFileRecordSegment     ``record_deallocated`` — FILE record freed
CreateAttribute ($FILE_NAME)    ``file_name_created``
DeleteAttribute ($FILE_NAME)    ``file_name_deleted`` — rename / delete
==============================  =============================================

Everything else (resident value updates, bitmap changes, transaction
bookkeeping…) is counted per operation name in the run's ``skipped``
statistics — never guessed. ``$LogFile`` records have no time of their own:
the timestamp reported is the one embedded in the decoded ``$FILE_NAME`` /
``$STANDARD_INFORMATION`` (``timestamp_desc`` says which).
"""

from __future__ import annotations

import struct
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.native import NativeTool
from defair.tools.ntfs_parse import (
    ATTR_FILE_NAME,
    apply_fixup,
    latest,
    parse_file_name,
    parse_file_record,
    parse_index_entry,
)

LFS_RECORD_HEADER = struct.Struct("<QQQIHHIIH6x")  # 0x30 bytes
NTFS_LOG_HEADER = struct.Struct("<HHHHHHHHHHHHQ")  # 0x20 bytes
PAGE_HEADER_SIZE = 0x40
RESTART_PAGES = 2

OPERATIONS = {
    0x00: "Noop", 0x01: "CompensationLogRecord", 0x02: "InitializeFileRecordSegment",
    0x03: "DeallocateFileRecordSegment", 0x04: "WriteEndOfFileRecordSegment",
    0x05: "CreateAttribute", 0x06: "DeleteAttribute", 0x07: "UpdateResidentValue",
    0x08: "UpdateNonresidentValue", 0x09: "UpdateMappingPairs", 0x0A: "DeleteDirtyClusters",
    0x0B: "SetNewAttributeSizes", 0x0C: "AddIndexEntryRoot", 0x0D: "DeleteIndexEntryRoot",
    0x0E: "AddIndexEntryAllocation", 0x0F: "DeleteIndexEntryAllocation",
    0x10: "WriteEndOfIndexBuffer", 0x11: "SetIndexEntryVcnRoot",
    0x12: "SetIndexEntryVcnAllocation", 0x13: "UpdateFileNameRoot",
    0x14: "UpdateFileNameAllocation", 0x15: "SetBitsInNonresidentBitMap",
    0x16: "ClearBitsInNonresidentBitMap", 0x17: "HotFix", 0x18: "EndTopLevelAction",
    0x19: "PrepareTransaction", 0x1A: "CommitTransaction", 0x1B: "ForgetTransaction",
    0x1C: "OpenNonresidentAttribute", 0x1D: "OpenAttributeTableDump",
    0x1E: "AttributeNamesDump", 0x1F: "DirtyPageTableDump", 0x20: "TransactionTableDump",
    0x21: "UpdateRecordDataRoot", 0x22: "UpdateRecordDataAllocation",
}
ADD_INDEX = (0x0C, 0x0E)
DELETE_INDEX = (0x0D, 0x0F)


class LogFileNativeTool(NativeTool):
    """Decode file-level operations from an NTFS ``$LogFile``."""

    module = "struct"  # pure Python: always available

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="logfile_native",
            display_name="$LogFile (native)",
            allowed_options=[],
            vendor="DEFAIR",
            description="NTFS $LogFile parser: file names linked / unlinked and FILE records created / freed.",
            category=ToolCategory.FILESYSTEM,
            command="python-native",
            runtime="python",
            timeout=3600,
            capabilities=["ntfs", "logfile", "transaction_journal", "deleted_files"],
            input_types=["$LogFile"],
            output_formats=["jsonl"],
            artifact_types=["windows.ntfs.logfile_op"],
            sans_categories=["deleted_file", "file_folder_opening"],
        )

    def _inputs(self, input_path: str) -> list[Path]:
        path = Path(input_path)
        if path.is_dir():
            return sorted(p for p in path.rglob("*") if p.is_file() and p.name.lower() == "$logfile")
        return [path]

    def parse_file(self, path: Path) -> Iterator[dict]:
        undecoded: Counter = Counter()
        with path.open("rb") as fh:
            yield from parse_logfile(fh, undecoded)
        if undecoded:
            # One summary record: what was read but not decoded, by operation
            yield {"operation": "_undecoded", "counts": dict(undecoded)}


def page_size(fh) -> int:
    """Log page size from the first restart page (``RSTR``)."""
    fh.seek(0)
    head = fh.read(0x20)
    if head[:4] not in (b"RSTR", b"CHKD"):
        raise ValueError("not a $LogFile (no RSTR restart page)")
    _system_page, log_page = struct.unpack_from("<II", head, 0x10)
    return log_page if log_page in (4096, 8192, 16384, 65536) else 4096


def iter_records(fh) -> Iterator[tuple[dict, bytes]]:
    """Yield (LFS header, client data) of every record in the log pages."""
    size = page_size(fh)
    fh.seek(0, 2)
    total = fh.tell()
    carry = 0  # bytes of the next page already consumed by a spanning record
    index = RESTART_PAGES
    while index * size < total:
        fh.seek(index * size)
        page = fh.read(size)
        index += 1
        if page[:4] != b"RCRD":
            carry = 0
            continue
        page = apply_fixup(page)
        offset = PAGE_HEADER_SIZE + carry
        carry = 0
        while offset + LFS_RECORD_HEADER.size <= size:
            (lsn, prev_lsn, _undo_next, length, _client_seq, _client_index, record_type,
             transaction, _flags) = LFS_RECORD_HEADER.unpack_from(page, offset)
            if lsn == 0 or record_type not in (1, 2) or length > 0x10000:
                break
            start = offset + LFS_RECORD_HEADER.size
            data = page[start:start + length]
            if len(data) < length:  # record continues on the following page(s)
                need = length - len(data)
                pos = fh.tell()
                chunks = [data]
                while need > 0 and index * size < total:
                    fh.seek(index * size)
                    nxt = fh.read(size)
                    if nxt[:4] != b"RCRD":
                        break
                    nxt = apply_fixup(nxt)
                    piece = nxt[PAGE_HEADER_SIZE:PAGE_HEADER_SIZE + need]
                    chunks.append(piece)
                    need -= len(piece)
                    if need > 0:
                        index += 1
                    else:
                        carry = (len(piece) + 7) & ~7
                data = b"".join(chunks)
                fh.seek(pos)
                header = {"lsn": lsn, "previous_lsn": prev_lsn, "transaction_id": transaction,
                          "record_type": record_type}
                yield header, data
                break
            yield {"lsn": lsn, "previous_lsn": prev_lsn, "transaction_id": transaction,
                   "record_type": record_type}, data
            offset = (start + length + 7) & ~7


def parse_logfile(fh, undecoded: Counter | None = None) -> Iterator[dict]:
    undecoded = undecoded if undecoded is not None else Counter()
    seen: set[int] = set()
    for header, data in iter_records(fh):
        if header["lsn"] in seen:
            continue  # tail copies of the last pages repeat records
        seen.add(header["lsn"])
        if header["record_type"] != 1 or len(data) < NTFS_LOG_HEADER.size:
            continue
        (redo_op, undo_op, redo_offset, redo_length, undo_offset, undo_length, *_,
         target_vcn) = NTFS_LOG_HEADER.unpack_from(data)
        redo = data[redo_offset:redo_offset + redo_length]
        undo = data[undo_offset:undo_offset + undo_length]
        base = {**header, "redo_operation": OPERATIONS.get(redo_op, hex(redo_op)),
                "undo_operation": OPERATIONS.get(undo_op, hex(undo_op)),
                "target_vcn": target_vcn}
        decoded = list(_decode(redo_op, undo_op, redo, undo))
        if not decoded:
            undecoded[base["redo_operation"]] += 1
            continue
        for item in decoded:
            yield {**base, **item}


def _decode(redo_op: int, undo_op: int, redo: bytes, undo: bytes) -> Iterator[dict]:
    if redo_op in ADD_INDEX:
        entry = parse_index_entry(redo)
        if entry:
            yield {"operation": "file_linked", **_clean(entry),
                   "event_time": entry["created"], "event_time_desc": "Created ($FN, $LogFile)"}
    elif redo_op in DELETE_INDEX or undo_op in ADD_INDEX:
        entry = parse_index_entry(undo)
        if entry:
            yield {"operation": "file_unlinked", **_clean(entry),
                   "event_time": latest(entry["created"], entry["modified"],
                                        entry["mft_modified"], entry["accessed"]),
                   "event_time_desc": "Latest $FN time before unlink ($LogFile)"}
    elif redo_op == 0x02:
        info = parse_file_record(redo)
        if info:
            yield from _record_items("record_initialized", info, "Created ($SI, $LogFile)",
                                     lambda i: i.get("si_created"))
    elif redo_op == 0x03:
        info = parse_file_record(undo)
        if info:
            yield from _record_items(
                "record_deallocated", info, "Latest $SI time before deallocation ($LogFile)",
                lambda i: latest(i.get("si_created"), i.get("si_modified"),
                                 i.get("si_mft_modified"), i.get("si_accessed")))
    elif redo_op == 0x05:
        fn = _file_name_attribute(redo)
        if fn:
            yield {"operation": "file_name_created", **_clean(fn),
                   "event_time": fn["created"], "event_time_desc": "Created ($FN, $LogFile)"}
    elif redo_op == 0x06:
        fn = _file_name_attribute(undo)  # the undo re-creates the removed attribute
        if fn:
            yield {"operation": "file_name_deleted", **_clean(fn),
                   "event_time": latest(fn["created"], fn["modified"], fn["mft_modified"],
                                        fn["accessed"]),
                   "event_time_desc": "Latest $FN time before removal ($LogFile)"}


def _file_name_attribute(attribute: bytes) -> dict | None:
    """A resident ``$FILE_NAME`` attribute record → its decoded value."""
    if len(attribute) < 0x18 or struct.unpack_from("<I", attribute)[0] != ATTR_FILE_NAME:
        return None
    value_length, value_offset = struct.unpack_from("<IH", attribute, 0x10)
    return parse_file_name(attribute[value_offset:value_offset + value_length])


def _record_items(operation: str, info: dict, desc: str, when) -> Iterator[dict]:
    names = info.pop("names", [])
    base = {"operation": operation, **info, "event_time": when(info), "event_time_desc": desc}
    if not names:
        yield base
        return
    # Prefer the Win32 name over its DOS 8.3 alias
    names.sort(key=lambda n: n["namespace"] == "DOS")
    yield {**base, **_clean(names[0]), "other_names": [n["name"] for n in names[1:]]}


def _clean(entry: dict) -> dict:
    return {k: v for k, v in entry.items() if not k.startswith("_")}
