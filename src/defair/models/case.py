"""Case model — the top-level container for a forensic investigation."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class CaseStatus(StrEnum):
    """Lifecycle status of a forensic case."""

    ACTIVE = "active"
    CLOSED = "closed"
    ARCHIVED = "archived"


class Case(BaseModel):
    """A forensic investigation case.

    Each case groups evidence, artifacts, timeline events, and findings
    under a single identifiable unit.
    """

    id: str = Field(default_factory=lambda: uuid4().hex)
    case_number: str  # Human-readable: CASE-YYYY-NNN
    name: str
    description: str = ""
    status: CaseStatus = CaseStatus.ACTIVE
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


def generate_case_number(year: int, sequence: int) -> str:
    """Generate a human-readable case number.

    Format: CASE-YYYY-NNN (e.g. CASE-2026-001)
    """
    return f"CASE-{year:04d}-{sequence:03d}"
