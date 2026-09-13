"""Tests for the timeline service."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
import pytest_asyncio

from defair.services import timeline_service


@pytest_asyncio.fixture
async def case_with_artifacts(db_conn):
    """Create a test case with sample artifacts."""
    cid = uuid4().hex
    now = datetime.now(UTC).isoformat()
    await db_conn.execute(
        "INSERT INTO cases (id, case_number, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (cid, "CASE-2026-002", "Timeline Test", now, now),
    )

    # Insert artifacts with timestamps
    artifacts = [
        ("ART-001", "2023-03-27T14:00:00Z", "windows.evtx.logon", "account_usage", "evtxecmd", "User logon", None),
        ("ART-002", "2023-03-27T14:30:00Z", "windows.evtx.process_creation", "program_execution", "evtxecmd", "Process: cmd.exe", None),
        ("ART-003", "2023-03-27T14:45:00Z", "windows.hayabusa.alert", "persistence", "hayabusa", "Mimikatz Detected", "critical"),
        ("ART-004", "2023-03-27T15:00:00Z", "windows.prefetch.execution", "program_execution", "pecmd", "Prefetch: powershell.exe", None),
        ("ART-005", None, "windows.registry.generic", "other", "recmd", "Registry key", None),
    ]

    for art_num, ts, art_type, cat, tool, desc, sev in artifacts:
        await db_conn.execute(
            """INSERT INTO artifacts
            (id, artifact_number, case_id, artifact_type, category,
             source_tool, timestamp, description, severity, hostname,
             username, data, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (uuid4().hex, art_num, cid, art_type, cat, tool, ts, desc, sev,
             "DESKTOP-01", "cyberjunkie", "{}", now),
        )
    await db_conn.commit()
    return cid


class TestTimelineService:
    @pytest.mark.asyncio
    async def test_build_timeline(self, db_conn, case_with_artifacts):
        cid = case_with_artifacts
        result = await timeline_service.build_timeline(db_conn, cid)

        assert result["total_events"] == 4  # One artifact has no timestamp
        assert result["earliest"] == "2023-03-27T14:00:00Z"
        assert result["latest"] == "2023-03-27T15:00:00Z"
        assert "evtxecmd" in result["by_tool"]
        assert "program_execution" in result["by_category"]
        assert result["by_severity"].get("critical") == 1

    @pytest.mark.asyncio
    async def test_search_timeline_all(self, db_conn, case_with_artifacts):
        cid = case_with_artifacts
        results = await timeline_service.search_timeline(db_conn, cid)

        assert len(results) == 4
        # Should be ordered by timestamp ASC
        assert results[0]["description"] == "User logon"
        assert results[-1]["description"] == "Prefetch: powershell.exe"

    @pytest.mark.asyncio
    async def test_search_timeline_query(self, db_conn, case_with_artifacts):
        cid = case_with_artifacts
        results = await timeline_service.search_timeline(db_conn, cid, query="Mimikatz")

        assert len(results) == 1
        assert results[0]["description"] == "Mimikatz Detected"

    @pytest.mark.asyncio
    async def test_search_timeline_time_range(self, db_conn, case_with_artifacts):
        cid = case_with_artifacts
        results = await timeline_service.search_timeline(
            db_conn, cid,
            from_time="2023-03-27T14:30:00Z",
            to_time="2023-03-27T14:50:00Z",
        )

        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_search_timeline_severity(self, db_conn, case_with_artifacts):
        cid = case_with_artifacts
        results = await timeline_service.search_timeline(db_conn, cid, severity="critical")

        assert len(results) == 1
        assert results[0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_search_timeline_hostname(self, db_conn, case_with_artifacts):
        cid = case_with_artifacts
        results = await timeline_service.search_timeline(db_conn, cid, hostname="DESKTOP")

        assert len(results) == 4

    @pytest.mark.asyncio
    async def test_search_timeline_source_tool(self, db_conn, case_with_artifacts):
        cid = case_with_artifacts
        results = await timeline_service.search_timeline(db_conn, cid, source_tool="hayabusa")

        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_export_csv(self, db_conn, case_with_artifacts, tmp_path):
        cid = case_with_artifacts
        output = str(tmp_path / "timeline.csv")
        result = await timeline_service.export_timeline(
            db_conn, cid, format="csv", output_path=output,
        )

        assert result["count"] == 4
        assert result["format"] == "csv"

        import csv as _csv
        from pathlib import Path

        content = Path(output).read_text()
        reader = _csv.DictReader(content.splitlines())
        rows = list(reader)
        assert len(rows) == 4

    @pytest.mark.asyncio
    async def test_export_jsonl(self, db_conn, case_with_artifacts, tmp_path):
        cid = case_with_artifacts
        output = str(tmp_path / "timeline.jsonl")
        result = await timeline_service.export_timeline(
            db_conn, cid, format="jsonl", output_path=output,
        )

        assert result["count"] == 4
        assert result["format"] == "jsonl"

        import json as _json
        from pathlib import Path

        lines = Path(output).read_text().strip().split("\n")
        assert len(lines) == 4
        first = _json.loads(lines[0])
        assert "timestamp" in first
