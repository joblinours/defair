"""Tests for DEFAIR data models."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from defair.models.case import Case, CaseStatus, generate_case_number
from defair.models.evidence import Evidence, EvidenceType, generate_evidence_number


class TestCase:
    def test_create_case(self):
        case = Case(case_number="CASE-2026-001", name="Test")
        assert case.case_number == "CASE-2026-001"
        assert case.name == "Test"
        assert case.status == CaseStatus.ACTIVE
        assert case.id  # UUID generated
        assert case.created_at  # datetime generated

    def test_case_requires_name(self):
        with pytest.raises(ValidationError):
            Case(case_number="CASE-2026-001")  # missing name

    def test_case_requires_case_number(self):
        with pytest.raises(ValidationError):
            Case(name="Test")  # missing case_number

    def test_case_status_enum(self):
        case = Case(case_number="CASE-2026-001", name="Test", status="closed")
        assert case.status == CaseStatus.CLOSED

    def test_case_serialization(self):
        case = Case(case_number="CASE-2026-001", name="Test", description="A test case")
        data = case.model_dump(mode="json")
        assert data["case_number"] == "CASE-2026-001"
        assert data["name"] == "Test"
        assert isinstance(data["created_at"], str)  # ISO format


class TestEvidence:
    def test_create_evidence(self):
        ev = Evidence(
            evidence_number="EVD-001",
            case_id="abc123",
            original_path="/evidence/disk.E01",
            filename="disk.E01",
        )
        assert ev.evidence_number == "EVD-001"
        assert ev.type == EvidenceType.OTHER
        assert ev.read_only is True

    def test_evidence_type_enum(self):
        ev = Evidence(
            evidence_number="EVD-001",
            case_id="abc123",
            type="disk_image",
            original_path="/evidence/disk.E01",
            filename="disk.E01",
        )
        assert ev.type == EvidenceType.DISK_IMAGE

    def test_evidence_requires_fields(self):
        with pytest.raises(ValidationError):
            Evidence(evidence_number="EVD-001")  # missing required fields


class TestIdGeneration:
    def test_case_number_format(self):
        assert generate_case_number(2026, 1) == "CASE-2026-001"
        assert generate_case_number(2026, 42) == "CASE-2026-042"
        assert generate_case_number(2026, 999) == "CASE-2026-999"

    def test_evidence_number_format(self):
        assert generate_evidence_number(1) == "EVD-001"
        assert generate_evidence_number(42) == "EVD-042"
