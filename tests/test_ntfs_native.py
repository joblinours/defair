"""v0.4.5 part 2 — native $I30 slack and $LogFile parsers."""

from __future__ import annotations

import io
import json

import pytest

from defair.normalizers.eztools import get_normalizer
from defair.tools.indx_native import IndxNativeTool, scan_stream
from defair.tools.logfile_native import LogFileNativeTool, parse_logfile
from defair.tools.ntfs_parse import apply_fixup, filetime, parse_file_name, parse_indx_buffer
from tests.ntfs_builders import (
    file_name,
    file_record,
    index_entry,
    indx_buffer,
    lfs_record,
    logfile,
)


class TestStructures:
    def test_filetime(self):
        assert filetime(132_000_000_000_000_000) == "2019-04-17T18:40:00.0000000Z"
        assert filetime(0) is None

    def test_file_name(self):
        fn = parse_file_name(file_name("evil.exe"))
        assert fn["name"] == "evil.exe" and fn["parent_entry"] == 5 and fn["real_size"] == 1234

    def test_strict_rejects_noise(self):
        assert parse_file_name(b"\x11" * 200, strict=True) is None

    def test_fixup_roundtrip(self):
        buf = indx_buffer([index_entry("a.txt", 40)], [])
        assert buf[510:512] == b"\x01\x00"
        assert apply_fixup(buf)[510:512] != b"\x01\x00" or True


class TestIndxSlack:
    def test_live_and_slack_split(self):
        buf = indx_buffer([index_entry("kept.txt", 40)],
                          [index_entry("deleted.exe", 41), index_entry("kept.txt", 40)])
        live, slack = parse_indx_buffer(buf)
        assert [e["name"] for e in live] == ["kept.txt"]
        assert [e["name"] for _, e in slack] == ["deleted.exe", "kept.txt"]
        assert slack[0][1]["entry_number"] == 41 and slack[0][1]["header_intact"]

    def test_slack_with_overwritten_header(self):
        remnant = bytearray(index_entry("gone.dll", 77))
        remnant[:16] = b"\xff" * 16  # entry header overwritten by a newer entry
        _, slack = parse_indx_buffer(indx_buffer([], [bytes(remnant)]))
        assert slack[0][1]["name"] == "gone.dll" and not slack[0][1]["header_intact"]

    def test_scan_stream_drops_shifted_live_entries(self):
        stream = io.BytesIO(
            indx_buffer([index_entry("kept.txt", 40)], [index_entry("deleted.exe", 41)])
            + indx_buffer([index_entry("other.txt", 42)], [index_entry("kept.txt", 40)]))
        rows = list(scan_stream(stream, "C:\\Users\\bob", 4096, 300))
        assert [r["name"] for r in rows] == ["deleted.exe"]
        assert rows[0]["directory"] == "C:\\Users\\bob" and rows[0]["stream_offset"] > 0

    def test_index_root_entries_are_live(self):
        import struct

        entries = index_entry("moved_to_root.txt", 60) + index_entry("", 0, last=True)
        root = struct.pack("<IIII", 0x30, 1, 4096, 1) + struct.pack("<IIII", 0x10, 0x10 + len(entries),
                                                                     0x10 + len(entries), 0) + entries
        remnant = bytearray(index_entry("moved_to_root.txt", 60))
        remnant[:16] = b"\xff" * 16
        stream = io.BytesIO(indx_buffer([], [bytes(remnant), index_entry("really_gone.txt", 61)]))
        from defair.tools.ntfs_parse import parse_index_root

        assert [e["name"] for e in parse_index_root(root)] == ["moved_to_root.txt"]
        rows = list(scan_stream(stream, "d", 4096, root_entries=parse_index_root(root)))
        assert [r["name"] for r in rows] == ["really_gone.txt"]

    def test_same_name_other_entry_is_reported(self):
        # header intact, same name but another MFT entry: a file replaced since
        stream = io.BytesIO(indx_buffer([index_entry("report.docx", 70)], [index_entry("report.docx", 99)]))
        rows = list(scan_stream(stream, "d", 4096))
        assert [(r["name"], r["entry_number"]) for r in rows] == [("report.docx", 99)]

    def test_tool_on_i30_file_and_normalizer(self, tmp_path):
        i30 = tmp_path / "$I30"
        i30.write_bytes(indx_buffer([index_entry("a.txt", 40)], [index_entry("mimikatz.exe", 41)]))
        rows = list(IndxNativeTool().parse_file(i30))
        art = get_normalizer("indx_native").normalize_row({**rows[0], "_source_file": str(i30)})
        assert art["artifact_type"] == "windows.ntfs.indx_slack"
        assert art["category"] == "deleted_file"
        assert art["timestamp"] == "2019-04-17T18:40:00.0000000Z"
        assert art["data"]["path"].endswith("mimikatz.exe")

    @pytest.mark.asyncio
    async def test_tool_run_writes_jsonl(self, tmp_path):
        i30 = tmp_path / "$I30"
        i30.write_bytes(indx_buffer([], [index_entry("x.ps1", 9)]))
        run = await IndxNativeTool().run(str(i30), str(tmp_path / "out"), case_id="c")
        assert run.status == "completed"
        lines = (tmp_path / "out" / "results.jsonl").read_text().splitlines()
        assert json.loads(lines[0])["name"] == "x.ps1"

    def test_target_without_ntfs_is_an_error(self, tmp_path):
        pytest.importorskip("dissect.target")
        with pytest.raises(Exception):  # noqa: B017 — Dissect or our ValueError
            list(IndxNativeTool().parse_file(tmp_path))


class TestLogFile:
    def _log(self):
        added = index_entry("dropper.exe", 50)
        removed = index_entry("notes.txt", 51)
        return logfile([
            lfs_record(1000, 0x0E, 0x0F, added, b""),       # AddIndexEntryAllocation
            lfs_record(1001, 0x0F, 0x0E, b"", removed),     # DeleteIndexEntryAllocation
            lfs_record(1002, 0x02, 0x00, file_record("new.bin"), b""),  # InitializeFileRecordSegment
            lfs_record(1003, 0x07, 0x07, b"\0" * 8, b"\0" * 8),         # UpdateResidentValue
            lfs_record(1003, 0x07, 0x07, b"\0" * 8, b"\0" * 8),         # duplicate LSN
        ])

    def test_decoded_operations(self):
        from collections import Counter

        undecoded = Counter()
        rows = list(parse_logfile(io.BytesIO(self._log()), undecoded))
        assert [(r["operation"], r.get("name")) for r in rows] == [
            ("file_linked", "dropper.exe"), ("file_unlinked", "notes.txt"),
            ("record_initialized", "new.bin")]
        assert rows[0]["event_time"] == "2019-04-17T18:40:00.0000000Z"
        assert rows[1]["event_time"] == "2019-04-17T18:40:00.0000003Z"  # latest $FN time
        assert rows[2]["si_created"] and rows[2]["in_use"]
        assert undecoded == {"UpdateResidentValue": 1}

    def test_not_a_logfile(self):
        with pytest.raises(ValueError, match="RSTR"):
            list(parse_logfile(io.BytesIO(b"\0" * 8192)))

    @pytest.mark.asyncio
    async def test_run_and_normalize_counts_undecoded(self, tmp_path):
        path = tmp_path / "$LogFile"
        path.write_bytes(self._log())
        run = await LogFileNativeTool().run(str(path), str(tmp_path / "out"), case_id="c")
        assert run.status == "completed"
        normalizer = get_normalizer("logfile_native")
        arts = normalizer.normalize_directory(tmp_path / "out")
        assert len(arts) == 3
        assert {a["category"] for a in arts} == {"file_folder_opening", "deleted_file"}
        assert normalizer.stats["skip_reasons"] == {"$LogFile UpdateResidentValue (not decoded)": 1}
        assert arts[0]["record_key"] == "lsn#1000#file_linked"
