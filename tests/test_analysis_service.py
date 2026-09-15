"""Tests for the analysis service."""

from __future__ import annotations

import pytest

from defair.services import analysis_service


class TestAnalysisServiceDB:
    """Test analysis service database operations (no actual tool execution)."""

    @pytest.mark.asyncio
    async def test_list_tool_runs_empty(self, db_conn):
        runs = await analysis_service.list_tool_runs(db_conn)
        assert runs == []

    @pytest.mark.asyncio
    async def test_get_tool_run_not_found(self, db_conn):
        result = await analysis_service.get_tool_run(db_conn, "RUN-999")
        assert result is None

    @pytest.mark.asyncio
    async def test_list_artifacts_empty(self, db_conn):
        arts = await analysis_service.list_artifacts(db_conn)
        assert arts == []

    @pytest.mark.asyncio
    async def test_run_unknown_case(self, db_conn):
        with pytest.raises(ValueError, match="Case not found"):
            await analysis_service.run_tool(
                db_conn, "nonexistent_tool", "/input", "CASE-9999-999"
            )

    @pytest.mark.asyncio
    async def test_run_unknown_tool(self, db_conn):
        # Create a case first so resolution passes
        from datetime import UTC, datetime
        from uuid import uuid4

        cid = uuid4().hex
        now = datetime.now(UTC).isoformat()
        await db_conn.execute(
            "INSERT INTO cases (id, case_number, name, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (cid, "CASE-2026-099", "Test", now, now),
        )
        await db_conn.commit()

        with pytest.raises(ValueError, match="Unknown tool"):
            await analysis_service.run_tool(
                db_conn, "nonexistent_tool", "/input", cid
            )

    @pytest.mark.asyncio
    async def test_run_tool_and_normalize_resolves_case_number(self, db_conn, tmp_path):
        """run_tool_and_normalize must pass the resolved UUID (not the case_number)
        to the normalizer so artifacts get the correct case_id FK."""
        from datetime import UTC, datetime
        from uuid import uuid4

        cid = uuid4().hex
        now = datetime.now(UTC).isoformat()
        await db_conn.execute(
            "INSERT INTO cases (id, case_number, name, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (cid, "CASE-2026-050", "FK Test", now, now),
        )
        await db_conn.commit()

        # Create a dummy .pf directory (prefetch tool handles empty dirs gracefully)
        input_dir = tmp_path / "evidence"
        input_dir.mkdir()

        result = await analysis_service.run_tool_and_normalize(
            db_conn,
            tool_name="prefetch",
            input_path=str(input_dir),
            case_id="CASE-2026-050",
            output_base=str(tmp_path / "output"),
        )

        # The returned case_id must be the UUID, not the case_number
        assert result["case_id"] == cid
        assert result["status"] == "completed"
