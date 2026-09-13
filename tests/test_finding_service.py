"""Tests for the finding service."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest
import pytest_asyncio

from defair.services import finding_service


@pytest_asyncio.fixture
async def case_id(db_conn):
    """Create a test case and return its ID."""
    cid = uuid4().hex
    now = datetime.now(UTC).isoformat()
    await db_conn.execute(
        "INSERT INTO cases (id, case_number, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (cid, "CASE-2026-001", "Test Case", now, now),
    )
    await db_conn.commit()
    return cid


class TestFindingService:
    @pytest.mark.asyncio
    async def test_create_finding(self, db_conn, case_id):
        cid = case_id
        result = await finding_service.create_finding(
            db_conn, case_id=cid, title="Test Finding", severity="high",
        )
        assert result["finding_number"] == "FND-001"
        assert result["title"] == "Test Finding"
        assert result["severity"] == "high"
        assert result["status"] == "open"

    @pytest.mark.asyncio
    async def test_list_findings_empty(self, db_conn, case_id):
        cid = case_id
        results = await finding_service.list_findings(db_conn, case_id=cid)
        assert results == []

    @pytest.mark.asyncio
    async def test_list_findings(self, db_conn, case_id):
        cid = case_id
        await finding_service.create_finding(db_conn, case_id=cid, title="F1", severity="high")
        await finding_service.create_finding(db_conn, case_id=cid, title="F2", severity="low")

        results = await finding_service.list_findings(db_conn, case_id=cid)
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_list_findings_filter_severity(self, db_conn, case_id):
        cid = case_id
        await finding_service.create_finding(db_conn, case_id=cid, title="F1", severity="high")
        await finding_service.create_finding(db_conn, case_id=cid, title="F2", severity="low")

        results = await finding_service.list_findings(db_conn, case_id=cid, severity="high")
        assert len(results) == 1
        assert results[0]["title"] == "F1"

    @pytest.mark.asyncio
    async def test_get_finding(self, db_conn, case_id):
        cid = case_id
        created = await finding_service.create_finding(
            db_conn, case_id=cid, title="Detail Test",
            mitre_tactics=["Execution"],
            mitre_techniques=["T1059"],
        )

        result = await finding_service.get_finding(db_conn, created["finding_number"])
        assert result is not None
        assert result["title"] == "Detail Test"
        assert "Execution" in json.loads(result["mitre_tactics"])

    @pytest.mark.asyncio
    async def test_get_finding_not_found(self, db_conn):
        result = await finding_service.get_finding(db_conn, "FND-999")
        assert result is None

    @pytest.mark.asyncio
    async def test_update_finding_status(self, db_conn, case_id):
        cid = case_id
        created = await finding_service.create_finding(
            db_conn, case_id=cid, title="Status Test",
        )

        updated = await finding_service.update_finding_status(
            db_conn, created["finding_number"], "confirmed",
        )
        assert updated is not None
        assert updated["status"] == "confirmed"

    @pytest.mark.asyncio
    async def test_correlate_artifact(self, db_conn, case_id):
        cid = case_id
        created = await finding_service.create_finding(
            db_conn, case_id=cid, title="Correlate Test",
        )

        result = await finding_service.correlate_artifact(
            db_conn, created["finding_number"], "art-123",
        )
        assert result is not None
        art_ids = json.loads(result["artifact_ids"])
        assert "art-123" in art_ids

    @pytest.mark.asyncio
    async def test_auto_create_findings_no_detections(self, db_conn, case_id):
        cid = case_id
        findings = await finding_service.auto_create_findings_from_hayabusa(
            db_conn, cid, "nonexistent-run",
        )
        assert findings == []

    @pytest.mark.asyncio
    async def test_auto_create_findings(self, db_conn, case_id):
        """Test auto-creation of findings from Hayabusa artifacts."""
        cid = case_id
        run_id = uuid4().hex
        now = datetime.now(UTC).isoformat()

        # Insert a tool run
        await db_conn.execute(
            """INSERT INTO tool_runs
            (id, run_number, case_id, tool_name, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (run_id, "RUN-001", cid, "hayabusa", "completed", now),
        )

        # Insert Hayabusa artifacts
        for i, (title, sev) in enumerate([
            ("Mimikatz Usage", "critical"),
            ("Mimikatz Usage", "critical"),
            ("Suspicious Service", "high"),
        ], start=1):
            art_id = uuid4().hex
            await db_conn.execute(
                """INSERT INTO artifacts
                (id, artifact_number, case_id, run_id, artifact_type,
                 source_tool, severity, data, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    art_id, f"ART-{i:03d}", cid, run_id,
                    "windows.hayabusa.alert", "hayabusa", sev,
                    json.dumps({
                        "rule_title": title,
                        "mitre_tactics": "Credential Access",
                        "mitre_tags": "T1003",
                        "rule_file": f"sigma/rule_{i}.yml",
                    }),
                    now,
                ),
            )
        await db_conn.commit()

        findings = await finding_service.auto_create_findings_from_hayabusa(
            db_conn, cid, run_id,
        )

        assert len(findings) == 2  # Two groups: Mimikatz (2), Service (1)

        # Find the Mimikatz finding
        mimi = next(f for f in findings if f["title"] == "Mimikatz Usage")
        assert mimi["severity"] == "critical"
