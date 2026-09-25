"""Native ``$I30`` INDX slack parser (INDXRipper approach, on Dissect).

Directory indexes (``$I30``) keep a ``$FILE_NAME`` copy of every entry. When
a file is deleted or renamed, its entry is removed from the index but the
bytes often stay in the unused part of the index buffer — the slack. Those
remnants prove a file existed in a folder, with its four ``$FN`` timestamps
and size, long after its MFT record was reused.

Input:
- a disk image or a collection DEFAIR can open with Dissect (the profile
  passes the original ``target``): every directory of every NTFS volume is
  read through Dissect — no mount, no raw device;
- or a loose file of ``INDX`` buffers (an extracted ``$I30`` stream).

Only slack entries are reported; remnants identical to a live entry of the
same directory (shifted, not removed) are dropped.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import structlog

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.native import NativeTool
from defair.tools.ntfs_parse import parse_index_root, parse_indx_buffer

log = structlog.get_logger(component="tools.indx_native")

DEFAULT_BUFFER_SIZE = 4096


class IndxNativeTool(NativeTool):
    """Carve deleted / renamed file names from ``$I30`` index slack."""

    module = "dissect.ntfs"

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="indx_native",
            display_name="INDX slack (native)",
            allowed_options=[],
            vendor="DEFAIR (dissect.ntfs)",
            description="Carves $FILE_NAME entries of deleted / renamed files from $I30 index slack space.",
            category=ToolCategory.FILESYSTEM,
            command="python-native",
            runtime="python",
            timeout=7200,
            capabilities=["ntfs", "i30", "indx_slack", "deleted_files"],
            input_types=["disk image", "collection", "$I30 stream"],
            output_formats=["jsonl"],
            artifact_types=["windows.ntfs.indx_slack"],
            sans_categories=["deleted_file", "file_folder_opening"],
        )

    def _inputs(self, input_path: str) -> list[Path]:
        return [Path(input_path)]

    def parse_file(self, path: Path) -> Iterator[dict]:
        if path.is_file():
            with path.open("rb") as fh:
                magic = fh.read(4)
            if magic == b"INDX":
                with path.open("rb") as fh:
                    yield from scan_stream(fh, str(path), DEFAULT_BUFFER_SIZE)
                return
        yield from scan_target(path)


def scan_stream(fh, directory: str, buffer_size: int, directory_entry: int | None = None,
                root_entries: list[dict] | None = None) -> Iterator[dict]:
    """Slack entries of one index allocation stream.

    ``root_entries``: live entries of the resident ``$INDEX_ROOT`` — a name
    moved there from a buffer is not a deleted file.
    """
    buffers = []
    offset = 0
    while True:
        raw = fh.read(buffer_size)
        if len(raw) < 0x40:
            break
        parsed = parse_indx_buffer(raw)
        if parsed is not None:
            buffers.append((offset, parsed))
        offset += len(raw)

    live_entries = [e for _, (live, _) in buffers for e in live] + list(root_entries or [])
    live_refs = {(e["entry_number"], e["name"]) for e in live_entries}
    # Index copies of one file do not share their $FN times, and a remnant
    # whose header was overwritten has no file reference left: those are
    # matched by name (a same-named file recreated since is then not reported)
    live_names = {e["name"] for e in live_entries}
    seen = set()
    for buffer_offset, (_, slack) in buffers:
        for slot, entry in slack:
            key = (entry.get("entry_number"), entry["name"], entry["created"])
            if key in seen or (entry.get("entry_number"), entry["name"]) in live_refs:
                continue
            if not entry["header_intact"] and entry["name"] in live_names:
                continue
            seen.add(key)
            entry.pop("_length", None)
            yield {
                **entry,
                "directory": directory,
                "directory_entry": directory_entry,
                "stream_offset": buffer_offset + slot,
            }


def scan_target(path: Path) -> Iterator[dict]:
    from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE
    from dissect.ntfs.index import Index
    from dissect.target import Target

    target = Target.open(str(path))
    volumes = [fs for fs in target.filesystems if getattr(fs, "__type__", "") == "ntfs"]
    if not volumes:
        raise ValueError(f"{path}: no NTFS volume readable by Dissect (a KAPE copy has no $I30)")
    for number, fs in enumerate(volumes):
        ntfs = fs.ntfs
        for record in ntfs.mft.segments():
            try:
                if not record.is_dir():
                    continue
                stream = record.open("$I30", ATTRIBUTE_TYPE_CODE.INDEX_ALLOCATION, allocated=True)
            except Exception:  # no allocation (small directory) or damaged record
                continue
            try:
                buffer_size = Index(record, "$I30").root.bytes_per_index_buffer or DEFAULT_BUFFER_SIZE
            except Exception:
                buffer_size = DEFAULT_BUFFER_SIZE
            try:
                directory = record.full_path() or f"<entry {record.segment}>"
            except Exception:
                directory = f"<entry {record.segment}>"
            try:
                root = parse_index_root(record.open("$I30", ATTRIBUTE_TYPE_CODE.INDEX_ROOT).read())
            except Exception:
                root = []
            try:
                for entry in scan_stream(stream, directory, buffer_size, record.segment, root):
                    entry["volume"] = number
                    yield entry
            except Exception as e:
                log.warning("indx_directory_failed", directory=directory, error=str(e))
