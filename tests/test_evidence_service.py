"""Tests for the evidence service layer."""

from __future__ import annotations

import pytest

from defair.services import evidence_service


class TestEvidenceService:
    @pytest.mark.asyncio
    async def test_add_evidence(self, db_conn, sample_file):
        from defair.services import case_service

        case = await case_service.create_case(db_conn, "Evidence Case")
        evidence = await evidence_service.add_evidence(db_conn, case.id, sample_file)

        assert evidence.evidence_number == "EVD-001"
        assert evidence.filename == "sample.txt"
        assert evidence.sha256 is not None
        assert len(evidence.sha256) == 64  # SHA-256 hex length
        assert evidence.case_id == case.id
        assert evidence.size_bytes > 0

    @pytest.mark.asyncio
    async def test_list_evidence_empty(self, db_conn):
        items = await evidence_service.list_evidence(db_conn)
        assert items == []

    @pytest.mark.asyncio
    async def test_list_evidence(self, db_conn, sample_file):
        from defair.services import case_service

        case = await case_service.create_case(db_conn, "List Case")
        await evidence_service.add_evidence(db_conn, case.id, sample_file)

        items = await evidence_service.list_evidence(db_conn)
        assert len(items) == 1
        assert items[0].filename == "sample.txt"

    @pytest.mark.asyncio
    async def test_list_evidence_filter_by_case(self, db_conn, tmp_path):
        from defair.services import case_service

        case1 = await case_service.create_case(db_conn, "Case A")
        case2 = await case_service.create_case(db_conn, "Case B")

        f1 = tmp_path / "file1.txt"
        f1.write_text("file one")
        f2 = tmp_path / "file2.txt"
        f2.write_text("file two")

        await evidence_service.add_evidence(db_conn, case1.id, f1)
        await evidence_service.add_evidence(db_conn, case2.id, f2)

        items_case1 = await evidence_service.list_evidence(db_conn, case1.case_number)
        assert len(items_case1) == 1
        assert items_case1[0].filename == "file1.txt"

        items_case2 = await evidence_service.list_evidence(db_conn, case2.case_number)
        assert len(items_case2) == 1
        assert items_case2[0].filename == "file2.txt"

    @pytest.mark.asyncio
    async def test_get_evidence_by_number(self, db_conn, sample_file):
        from defair.services import case_service

        case = await case_service.create_case(db_conn, "Get Case")
        added = await evidence_service.add_evidence(db_conn, case.id, sample_file)

        found = await evidence_service.get_evidence(db_conn, added.evidence_number)
        assert found is not None
        assert found.id == added.id
        assert found.sha256 == added.sha256

    @pytest.mark.asyncio
    async def test_get_evidence_by_id(self, db_conn, sample_file):
        from defair.services import case_service

        case = await case_service.create_case(db_conn, "ID Case")
        added = await evidence_service.add_evidence(db_conn, case.id, sample_file)

        found = await evidence_service.get_evidence(db_conn, added.id)
        assert found is not None
        assert found.evidence_number == added.evidence_number

    @pytest.mark.asyncio
    async def test_get_evidence_not_found(self, db_conn):
        result = await evidence_service.get_evidence(db_conn, "EVD-999")
        assert result is None

    @pytest.mark.asyncio
    async def test_verify_evidence_ok(self, db_conn, sample_file):
        from defair.services import case_service

        case = await case_service.create_case(db_conn, "Verify Case")
        added = await evidence_service.add_evidence(db_conn, case.id, sample_file)

        result = await evidence_service.verify_evidence(db_conn, added.evidence_number)
        assert result["status"] == "ok"
        assert result["verified"] is True
        assert result["original_sha256"] == result["current_sha256"]

    @pytest.mark.asyncio
    async def test_verify_evidence_mismatch(self, db_conn, sample_file):
        from defair.services import case_service

        case = await case_service.create_case(db_conn, "Tampered Case")
        added = await evidence_service.add_evidence(db_conn, case.id, sample_file)

        # Modify the file after registration (tampering)
        sample_file.write_text("This content has been tampered with!")

        result = await evidence_service.verify_evidence(db_conn, added.evidence_number)
        assert result["status"] == "mismatch"
        assert result["verified"] is False
        assert result["original_sha256"] != result["current_sha256"]

    @pytest.mark.asyncio
    async def test_verify_evidence_missing(self, db_conn, sample_file):
        from defair.services import case_service

        case = await case_service.create_case(db_conn, "Missing Case")
        added = await evidence_service.add_evidence(db_conn, case.id, sample_file)

        # Delete the file
        sample_file.unlink()

        result = await evidence_service.verify_evidence(db_conn, added.evidence_number)
        assert result["status"] == "missing"
        assert result["verified"] is False

    @pytest.mark.asyncio
    async def test_verify_evidence_not_found(self, db_conn):
        with pytest.raises(ValueError, match="Evidence not found"):
            await evidence_service.verify_evidence(db_conn, "EVD-999")
