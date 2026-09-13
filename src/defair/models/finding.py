"""Finding model — investigation findings from detection and analysis.

A Finding groups related detections/artifacts into an actionable
conclusion: "this host shows signs of lateral movement" backed
by the specific alerts and artifacts that led to that conclusion.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class FindingSeverity(StrEnum):
    """Severity of a finding."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    """Status of a finding in the investigation workflow."""

    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"


class Finding(BaseModel):
    """An investigation finding linking detections to conclusions.

    Findings are the output of the hunting process. Each finding
    is linked to the case and references the artifacts that support it.
    """

    id: str = Field(default_factory=lambda: uuid4().hex)
    finding_number: str  # Human-readable: FND-NNN
    case_id: str

    title: str
    description: str = ""
    severity: FindingSeverity = FindingSeverity.MEDIUM
    confidence: str = "medium"  # low, medium, high
    status: FindingStatus = FindingStatus.OPEN

    # Source tracking
    source: str = ""  # Tool or method that produced this finding

    # MITRE ATT&CK mapping
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)

    # Linked artifacts
    artifact_ids: list[str] = Field(default_factory=list)

    # Additional references (rule names, detection IDs, etc.)
    detection_refs: list[str] = Field(default_factory=list)

    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


def generate_finding_number(sequence: int) -> str:
    """Generate a human-readable finding number.

    Format: FND-NNN (e.g. FND-001)
    """
    return f"FND-{sequence:03d}"
