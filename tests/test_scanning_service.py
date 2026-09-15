"""Tests for the scanning service (YARA + Sigma orchestration)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest
import pytest_asyncio

from defair.services import finding_service, scanning_service


@pytest_asyncio.fixture
async def case_for_scanning(db_conn):
    """Create a test case for scanning tests."""
    cid = uuid4().hex
    now = datetime.now(UTC).isoformat()
    await db_conn.execute(
        "INSERT INTO cases (id, case_number, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (cid, "CASE-2026-004", "Scanning Test", now, now),
    )
    await db_conn.commit()
    return cid


class TestAutoCreateFindingsFromYara:
    @pytest.mark.asyncio
    async def test_create_findings_from_yara_artifacts(self, db_conn, case_for_scanning):
        """Should group YARA artifacts by rule and create findings."""
        cid = case_for_scanning
        now = datetime.now(UTC).isoformat()
        run_id = "run-yara-001"

        # Insert some YARA match artifacts
        for i, (rule, file_name, severity) in enumerate([
            ("RANSOM_WannaCry", "file1.exe", "critical"),
            ("RANSOM_WannaCry", "file2.dll", "critical"),
            ("SUSP_PowerShell_Encoded", "script.ps1", "high"),
        ]):
            await db_conn.execute(
                """INSERT INTO artifacts
                (id, artifact_number, case_id, artifact_type, source_tool,
                 timestamp, description, severity, data, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    uuid4().hex,
                    f"ART-Y{i:03d}",
                    cid,
                    "detection.yara.match",
                    "yara",
                    now,
                    f"YARA match: {rule} on {file_name}",
                    severity,
                    json.dumps({
                        "rule_name": rule,
                        "file_name": file_name,
                        "author": "Test Author",
                        "reference": "https://example.com",
                        "run_id": run_id,
                    }),
                    now,
                ),
            )
        await db_conn.commit()

        count = await scanning_service._auto_create_findings_from_yara(
            db_conn, cid, run_id,
        )

        assert count == 2  # Two distinct rules

        # Verify findings were created
        findings = await finding_service.list_findings(db_conn, cid)
        assert len(findings) >= 2

        # Check the WannaCry finding
        wannacry = [f for f in findings if "WannaCry" in f["title"]]
        assert len(wannacry) == 1
        assert wannacry[0]["severity"] == "critical"
        artifact_ids = json.loads(wannacry[0]["artifact_ids"])
        assert len(artifact_ids) == 2  # Two files matched

    @pytest.mark.asyncio
    async def test_no_findings_when_no_yara_artifacts(self, db_conn, case_for_scanning):
        """Should return 0 when no YARA artifacts exist."""
        cid = case_for_scanning
        count = await scanning_service._auto_create_findings_from_yara(
            db_conn, cid, "nonexistent-run",
        )
        assert count == 0
