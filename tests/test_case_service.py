"""Tests for the case service layer."""

import pytest

from defair.models.case import CaseStatus
from defair.services import case_service


class TestCaseService:
    @pytest.mark.asyncio
    async def test_create_case(self, db_conn):
        case = await case_service.create_case(db_conn, "Test Incident")
        assert case.name == "Test Incident"
        assert case.case_number.startswith("CASE-")
        assert case.status == CaseStatus.ACTIVE
        assert case.id

    @pytest.mark.asyncio
    async def test_create_case_with_description(self, db_conn):
        case = await case_service.create_case(db_conn, "IR-42", description="Ransomware attack")
        assert case.description == "Ransomware attack"

    @pytest.mark.asyncio
    async def test_case_number_auto_increment(self, db_conn):
        c1 = await case_service.create_case(db_conn, "First")
        c2 = await case_service.create_case(db_conn, "Second")
        # Both should be in the same year, sequential
        seq1 = int(c1.case_number.split("-")[-1])
        seq2 = int(c2.case_number.split("-")[-1])
        assert seq2 == seq1 + 1

    @pytest.mark.asyncio
    async def test_list_cases(self, db_conn):
        await case_service.create_case(db_conn, "Case A")
        await case_service.create_case(db_conn, "Case B")
        cases = await case_service.list_cases(db_conn)
        assert len(cases) >= 2
        names = [c.name for c in cases]
        assert "Case A" in names
        assert "Case B" in names

    @pytest.mark.asyncio
    async def test_get_case_by_number(self, db_conn):
        created = await case_service.create_case(db_conn, "Findable")
        found = await case_service.get_case(db_conn, created.case_number)
        assert found is not None
        assert found.id == created.id
        assert found.name == "Findable"

    @pytest.mark.asyncio
    async def test_get_case_by_id(self, db_conn):
        created = await case_service.create_case(db_conn, "By ID")
        found = await case_service.get_case(db_conn, created.id)
        assert found is not None
        assert found.case_number == created.case_number

    @pytest.mark.asyncio
    async def test_get_case_not_found(self, db_conn):
        result = await case_service.get_case(db_conn, "CASE-9999-999")
        assert result is None
