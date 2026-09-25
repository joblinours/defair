"""Tests for the normalization pipeline (v0.3.8)."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from unittest.mock import patch

import aiosqlite
import pytest
import pytest_asyncio

from defair.database import SCHEMA_SQL, SCHEMA_VERSION, get_initialized_connection
from defair.normalizers.evtx_flatten import flatten_event, lookup_event
from defair.normalizers.eztools import EvtxECmdNormalizer, MFTECmdNormalizer, classify_evtx
from defair.normalizers.native import EvtxNativeNormalizer
from defair.normalizers.pipeline import (
    artifact_id,
    enrich,
    new_stats,
    normalize_run,
    timestamp_desc_for,
)
from defair.normalizers.timestamps import parse_timestamp, to_utc_iso
from defair.services import case_service, finding_service, normalization_service, timeline_service

# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------


class TestTimestamps:
    @pytest.mark.parametrize("raw, expected", [
        ("2026-01-15 14:30:00", "2026-01-15T14:30:00Z"),
        ("2024-03-01 10:00:00.1234567", "2024-03-01T10:00:00.1234567Z"),  # 7 digits kept
        ("2024-03-01T10:00:00+02:00", "2024-03-01T08:00:00Z"),
        ("2024-03-01T10:00:00.5-0130", "2024-03-01T11:30:00.5Z"),
        ("2024-03-01T10:00:00Z", "2024-03-01T10:00:00Z"),
        ("2024/03/01 10:00:00", "2024-03-01T10:00:00Z"),
        (1700000000, "2023-11-14T22:13:20Z"),
        (1700000000123, "2023-11-14T22:13:20.123Z"),
        (133500000000000000, "2024-01-17T21:20:00Z"),  # FILETIME
    ])
    def test_valid(self, raw, expected):
        assert to_utc_iso(raw) == (expected, None)

    @pytest.mark.parametrize("raw", [None, "", "N/A", "0", "1601-01-01 00:00:00",
                                     "1601-01-01T00:00:00+00:00", "1970-01-01T00:00:00Z"])
    def test_empty(self, raw):
        assert to_utc_iso(raw) == (None, None)

    @pytest.mark.parametrize("raw", ["01/02/2024 10:00:00", "garbage", "2024-13-45 10:00:00", 99])
    def test_invalid_is_never_invented(self, raw):
        iso, reason = to_utc_iso(raw)
        assert iso is None and reason

    def test_parse_timestamp_keeps_unparseable_raw(self):
        assert parse_timestamp("01/02/2024 10:00") == "01/02/2024 10:00"
        assert parse_timestamp("2026-01-15 14:30:00") == "2026-01-15T14:30:00Z"
        assert parse_timestamp("") is None


# ---------------------------------------------------------------------------
# EVTX flattening + catalog
# ---------------------------------------------------------------------------


class TestEvtxFlatten:
    def test_pyevtx_shape(self):
        record = {"Event": {
            "System": {
                "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                "EventID": 4624, "EventRecordID": 42, "Channel": "Security",
                "Computer": "PC01", "TimeCreated": {"#attributes": {"SystemTime": "2024-01-01T10:00:00Z"}},
                "Execution": {"#attributes": {"ProcessID": 4, "ThreadID": 8}},
            },
            "EventData": {"TargetUserName": "alice", "LogonType": 10},
        }}
        flat = flatten_event(record)
        assert flat["EventID"] == 4624
        assert flat["Provider"] == "Microsoft-Windows-Security-Auditing"
        assert flat["TimeCreated"] == "2024-01-01T10:00:00Z"
        assert flat["TargetUserName"] == "alice" and flat["LogonType"] == 10
        assert flat["ProcessID"] == 4

    def test_evtxecmd_payload_shape(self):
        payload = {"EventData": {"Data": [
            {"@Name": "SubjectUserName", "#text": "bob"},
            {"@Name": "NewProcessName", "#text": "C:\\cmd.exe"},
        ]}}
        assert flatten_event(payload) == {"SubjectUserName": "bob", "NewProcessName": "C:\\cmd.exe"}

    def test_unnamed_data_and_userdata(self):
        record = {"Event": {
            "System": {"EventID": 1102, "Channel": "Security"},
            "EventData": {"Data": ["a", "b"]},
            "UserData": {"LogFileCleared": {"SubjectUserName": "eve"}},
        }}
        flat = flatten_event(record)
        assert flat["Data_0"] == "a" and flat["Data_1"] == "b"
        assert flat["SubjectUserName"] == "eve"

    def test_catalog_lookup(self):
        entry = lookup_event("Microsoft-Windows-Sysmon/Operational", "10")
        assert entry["type"] == "windows.evtx.sysmon_process_access"
        assert "T1003.001" in entry["mitre"]
        # Channel matters: EventID 1 in Security is not Sysmon process creation
        assert lookup_event("Security", 1) is None

    def test_classify_unknown(self):
        info = classify_evtx(99999, "Nope")
        assert info["artifact_type"] == "windows.evtx.generic"
        assert info["category"] == "other"

    def test_evtxecmd_uses_payload(self):
        row = {
            "EventId": "4688", "Channel": "Security", "TimeCreated": "2024-01-01 10:00:00.1234567",
            "RecordNumber": "77", "SourceFile": "Security.evtx",
            "Payload": json.dumps({"EventData": {"Data": [{"@Name": "CommandLine", "#text": "whoami"}]}}),
        }
        art = EvtxECmdNormalizer().normalize_row(row)
        assert art["data"]["event_data"] == {"CommandLine": "whoami"}
        assert art["record_key"] == "Security.evtx#77"
        assert "mitre:T1059" in art["tags"]

    def test_native_normalizer(self):
        art = EvtxNativeNormalizer().normalize_row({
            "EventID": 4625, "Channel": "Security", "Computer": "PC01",
            "TimeCreated": "2024-01-01T10:00:00Z", "EventRecordID": 5,
            "TargetUserName": "admin", "_source_file": "/e/Security.evtx",
        })
        assert art["artifact_type"] == "windows.evtx.logon_failed"
        assert art["username"] == "admin"
        assert art["record_key"] == "/e/Security.evtx#5"


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------

RUN = {"id": "run-1", "run_number": "RUN-001", "case_id": "case-1",
       "tool_name": "mftecmd", "tool_version": "sha256:abc", "evidence_id": "ev-1"}


class TestEnrich:
    def test_envelope_and_timeline_fields(self):
        art = {"artifact_type": "windows.prefetch.execution", "timestamp": "2024-01-01 10:00:00",
               "description": "POWERSHELL.EXE", "source_file": "/e/x.pf", "record_key": "x.pf#0"}
        out = enrich(art, RUN, new_stats(), set())
        assert out["timestamp"] == "2024-01-01T10:00:00Z"
        assert out["timestamp_desc"] == "Last Executed"
        assert out["message"] == "POWERSHELL.EXE"
        assert out["provenance"]["tool"] == "mftecmd"
        assert out["provenance"]["tool_version"] == "sha256:abc"
        assert out["provenance"]["evidence_id"] == "ev-1"
        assert out["id"] == artifact_id("run-1", "x.pf#0")

    def test_unparseable_timestamp_nulled_with_reason(self):
        stats = new_stats()
        out = enrich({"artifact_type": "windows.lnk.shortcut", "timestamp": "32/13/2024 25:00"},
                     RUN, stats, set())
        assert out["timestamp"] is None
        assert out["timestamp_desc"] is None
        assert out["provenance"]["raw_timestamp"] == "32/13/2024 25:00"
        assert stats["timestamp_unparsed"] == 1 and stats["reasons"]

    def test_duplicate_record_keys_made_unique(self):
        seen: set[str] = set()
        a = enrich({"artifact_type": "t", "record_key": "k"}, RUN, new_stats(), seen)
        b = enrich({"artifact_type": "t", "record_key": "k"}, RUN, new_stats(), seen)
        assert a["id"] != b["id"] and b["record_key"] == "k~2"

    def test_timestamp_desc_longest_prefix(self):
        assert timestamp_desc_for("windows.evtx.logon") == "Event Logged"
        assert timestamp_desc_for("something.else") == "Event Time"


# ---------------------------------------------------------------------------
# Pipeline end-to-end (normalize → JSONL → DB → replay / rerun / stats)
# ---------------------------------------------------------------------------


def _write_mft_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


@pytest_asyncio.fixture
async def mft_run(db_conn, tmp_path):
    case = await case_service.create_case(db_conn, "pipeline")
    output = tmp_path / "workspace" / "analysis" / "mftecmd" / "RUN-001"
    _write_mft_csv(output / "mft.csv", [
        {"EntryNumber": "10", "FileName": "evil.exe", "Created0x10": "2024-01-01 10:00:00.1234567",
         "SourceFile": "$MFT"},
        {"EntryNumber": "11", "FileName": "notes.txt", "Created0x10": "not a date", "SourceFile": "$MFT"},
        {"EntryNumber": "12", "FileName": "a.dll", "Created0x10": "", "SourceFile": "$MFT"},
    ])
    run = {"id": "run-mft", "run_number": "RUN-001", "case_id": case.id, "evidence_id": None,
           "tool_name": "mftecmd", "tool_version": "sha256:1", "output_path": str(output)}
    await db_conn.execute(
        """INSERT INTO tool_runs (id, run_number, case_id, tool_name, output_path, status, created_at)
        VALUES (?, ?, ?, ?, ?, 'completed', '2024-01-01T00:00:00Z')""",
        (run["id"], run["run_number"], case.id, "mftecmd", str(output)),
    )
    await db_conn.commit()
    return {"case": case, "run": run, "workspace": tmp_path / "workspace"}


class TestNormalizeRun:
    @pytest.mark.asyncio
    async def test_jsonl_db_and_stats(self, db_conn, mft_run):
        stats = await normalize_run(db_conn, mft_run["run"], MFTECmdNormalizer())
        assert stats["rows_read"] == 3 and stats["normalized"] == 3
        assert stats["timestamp_unparsed"] == 1

        jsonl = mft_run["workspace"] / "normalized" / "windows.mft.file_entry" / "RUN-001.jsonl"
        assert jsonl.exists() and len(jsonl.read_text().splitlines()) == 3

        rows = [dict(r) for r in await (await db_conn.execute(
            "SELECT * FROM artifacts WHERE run_id = 'run-mft' ORDER BY artifact_number")).fetchall()]
        assert [r["artifact_number"] for r in rows] == ["ART-001", "ART-002", "ART-003"]
        evil = next(r for r in rows if r["description"] == "evil.exe")
        assert evil["timestamp"] == "2024-01-01T10:00:00.1234567Z"
        assert evil["timestamp_desc"] == "Created ($SI)"
        assert json.loads(evil["provenance"])["run_number"] == "RUN-001"

        stored = await normalization_service.stats(db_conn, "RUN-001")
        assert stored["stats"]["normalized"] == 3
        assert stored["files"][0]["records"] == 3

    @pytest.mark.asyncio
    async def test_replay_after_db_loss(self, db_conn, mft_run):
        await normalize_run(db_conn, mft_run["run"], MFTECmdNormalizer())
        ids = {r[0] for r in await (await db_conn.execute("SELECT id FROM artifacts")).fetchall()}
        await db_conn.execute("DELETE FROM artifacts")
        await db_conn.commit()

        result = await normalization_service.replay(db_conn, mft_run["case"].case_number)
        assert result["artifacts_restored"] == 3 and not result["refused"]
        restored = {r[0] for r in await (await db_conn.execute("SELECT id FROM artifacts")).fetchall()}
        assert restored == ids

    @pytest.mark.asyncio
    async def test_replay_refuses_tampered_jsonl(self, db_conn, mft_run):
        await normalize_run(db_conn, mft_run["run"], MFTECmdNormalizer())
        jsonl = mft_run["workspace"] / "normalized" / "windows.mft.file_entry" / "RUN-001.jsonl"
        jsonl.write_text(jsonl.read_text().replace("evil.exe", "benign.exe"))
        result = await normalization_service.replay(db_conn, mft_run["case"].id)
        assert result["refused"] == [{"path": str(jsonl), "reason": "sha256 mismatch"}]

    @pytest.mark.asyncio
    async def test_rerun_keeps_ids_numbers_and_findings(self, db_conn, mft_run):
        await normalize_run(db_conn, mft_run["run"], MFTECmdNormalizer())
        before = {r[0]: r[1] for r in await (await db_conn.execute(
            "SELECT id, artifact_number FROM artifacts")).fetchall()}
        await finding_service.create_finding(
            db_conn, mft_run["case"].id, "evil", artifact_ids=list(before)[:1],
        )

        result = await normalization_service.rerun(db_conn, "RUN-001")
        assert result["artifacts_before"] == result["artifacts_after"] == 3
        after = {r[0]: r[1] for r in await (await db_conn.execute(
            "SELECT id, artifact_number FROM artifacts")).fetchall()}
        assert after == before
        stored = await finding_service.list_findings(db_conn, mft_run["case"].id)
        linked = json.loads(stored[0]["artifact_ids"])
        assert linked[0] in after

    @pytest.mark.asyncio
    async def test_timesketch_export(self, db_conn, mft_run, tmp_path):
        await normalize_run(db_conn, mft_run["run"], MFTECmdNormalizer())
        out = tmp_path / "ts.jsonl"
        result = await timeline_service.export_timeline(
            db_conn, mft_run["case"].id, format="timesketch", output_path=str(out),
        )
        lines = [json.loads(line) for line in out.read_text().splitlines()]
        assert result["count"] == len(lines) == 1  # only the event with a valid time
        assert lines[0]["datetime"] == "2024-01-01T10:00:00.1234567Z"
        assert lines[0]["timestamp_desc"] == "Created ($SI)"
        assert lines[0]["message"] == "evil.exe"


# ---------------------------------------------------------------------------
# Fallback + migration
# ---------------------------------------------------------------------------


class TestFallback:
    @pytest.mark.asyncio
    async def test_failed_tool_runs_fallback(self, db_conn, tmp_path):
        from defair.models.tool_run import ToolRun, ToolRunStatus
        from defair.services import analysis_service

        case = await case_service.create_case(db_conn, "fallback")
        calls = []

        async def fake_run_tool(conn, tool_name, input_path, case_id, **kwargs):
            calls.append((tool_name, kwargs.get("fallback_of")))
            status = ToolRunStatus.FAILED if tool_name == "evtxecmd" else ToolRunStatus.COMPLETED
            return ToolRun(run_number=f"RUN-{len(calls):03d}", case_id=case_id,
                           tool_name=tool_name, status=status)

        with patch.object(analysis_service, "run_tool", side_effect=fake_run_tool), \
             patch("defair.tools.evtx_native.EvtxNativeTool.is_available", return_value=True):
            result = await analysis_service.run_tool_and_normalize(
                db_conn, "evtxecmd", "/evidence/logs", case.id,
            )

        assert [c[0] for c in calls] == ["evtxecmd", "evtx_native"]
        assert calls[1][1] is not None  # fallback_of = failed run id
        assert result["tool"] == "evtx_native"
        assert result["fallback_of"]["tool"] == "evtxecmd"


class TestMigration:
    @pytest.mark.asyncio
    async def test_upgrade_v035_database(self, tmp_path):
        db = tmp_path / "old.db"
        conn = await aiosqlite.connect(db)
        await conn.executescript(SCHEMA_SQL)  # v0.3.5 schema, user_version 0
        await conn.commit()
        await conn.close()

        conn = await get_initialized_connection(db)
        try:
            version = (await (await conn.execute("PRAGMA user_version")).fetchone())[0]
            cols = {r[1] for r in await (await conn.execute("PRAGMA table_info(artifacts)")).fetchall()}
            tables = {r[0] for r in await (await conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")).fetchall()}
        finally:
            await conn.close()
        assert version == SCHEMA_VERSION
        assert {"timestamp_desc", "message", "provenance", "record_key"} <= cols
        assert "normalized_files" in tables

    @pytest.mark.asyncio
    async def test_migration_idempotent(self, tmp_path):
        db = tmp_path / "db.db"
        for _ in range(2):
            conn = await get_initialized_connection(db)
            await conn.close()
