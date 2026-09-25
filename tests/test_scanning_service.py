"""Tests for the scanning service (Raijin YARA + Sigma orchestration)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
import pytest_asyncio

from defair.normalizers.raijin import RaijinNormalizer
from defair.services import finding_service, scanning_service

FIXTURE = Path(__file__).parent / "fixtures" / "raijin_sample.jsonl"


@pytest_asyncio.fixture
async def case_for_scanning(db_conn):
    cid = uuid4().hex
    now = datetime.now(UTC).isoformat()
    await db_conn.execute(
        "INSERT INTO cases (id, case_number, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (cid, "CASE-2026-004", "Scanning Test", now, now),
    )
    await db_conn.execute(
        """INSERT INTO tool_runs (id, run_number, case_id, tool_name, created_at)
        VALUES (?, ?, ?, ?, ?)""",
        ("run-raijin-1", "RUN-001", cid, "raijin", now),
    )
    await db_conn.commit()
    return cid


async def _insert_fixture_artifacts(conn, case_id: str, run_id: str) -> int:
    from defair.services.analysis_service import _save_artifact

    artifacts = RaijinNormalizer(Path("/nonexistent")).normalize_file(
        FIXTURE, case_id=case_id, run_id=run_id,
    )
    for art in artifacts:
        await _save_artifact(conn, art)
    return len(artifacts)


class TestAutoCreateFindings:
    @pytest.mark.asyncio
    async def test_one_finding_per_rule(self, db_conn, case_for_scanning):
        cid = case_for_scanning
        n = await _insert_fixture_artifacts(db_conn, cid, "run-raijin-1")
        assert n > 0

        count = await scanning_service.auto_create_findings(
            db_conn, cid, "run-raijin-1", min_severity="informational",
        )
        findings = await finding_service.list_findings(db_conn, cid)
        assert count == len(findings) > 0

        titles = {f["title"] for f in findings}
        assert "Sigma: LSASS dump via process access" in titles
        assert "YARA: BINARYALERT_Eicar_Av_Test" in titles

        lsass = next(f for f in findings if "LSASS" in f["title"])
        ref = json.loads(lsass["detection_refs"])[0]
        assert ref["engine"] == "sigma"
        assert ref["source"] == "mdecrevoisier"
        assert ref["license"] == "CC0-1.0"
        assert "T1003.001" in json.loads(lsass["mitre_techniques"])

    @pytest.mark.asyncio
    async def test_min_severity_filters(self, db_conn, case_for_scanning):
        cid = case_for_scanning
        await _insert_fixture_artifacts(db_conn, cid, "run-raijin-1")
        count = await scanning_service.auto_create_findings(
            db_conn, cid, "run-raijin-1", min_severity="critical",
        )
        findings = await finding_service.list_findings(db_conn, cid)
        assert count == len(findings)
        assert all(f["severity"] == "critical" for f in findings)

    @pytest.mark.asyncio
    async def test_no_artifacts(self, db_conn, case_for_scanning):
        assert await scanning_service.auto_create_findings(
            db_conn, case_for_scanning, "nonexistent-run",
        ) == 0


class TestScan:
    @pytest.mark.asyncio
    async def test_scan_creates_findings(self, db_conn, case_for_scanning):
        """Regression: findings were never created (artifact_count vs artifacts_produced)."""
        cid = case_for_scanning

        async def fake_run(conn, **kwargs):
            await _insert_fixture_artifacts(conn, cid, "run-raijin-1")
            return {"run_id": "run-raijin-1", "run_number": "RUN-001", "case_id": cid,
                    "tool": "raijin", "status": "completed", "artifacts_produced": 5}

        with patch.object(scanning_service.analysis_service, "run_tool_and_normalize",
                          AsyncMock(side_effect=fake_run)) as mock_run:
            result = await scanning_service.scan_sigma(
                db_conn, "/evidence", cid, profile="precise", min_severity="low",
            )

        kwargs = mock_run.call_args.kwargs
        assert kwargs["tool_name"] == "raijin"
        assert kwargs["mode"] == "sigma" and kwargs["profile"] == "precise"
        assert result["findings_created"] > 0
