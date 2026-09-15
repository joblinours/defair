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
