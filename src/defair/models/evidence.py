"""Evidence model — a source of forensic data attached to a case."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class EvidenceType(StrEnum):
    """Type of forensic evidence."""

    DISK_IMAGE = "disk_image"
    MEMORY_DUMP = "memory_dump"
    LOGS = "logs"
    TRIAGE_ARCHIVE = "triage_archive"
    COLLECTION = "collection"  # triage collection folder (KAPE, Velociraptor…)
    PCAP = "pcap"
    OTHER = "other"


class Evidence(BaseModel):
    """A piece of forensic evidence registered in a case.

    Evidence is always treated as read-only. The original file is never
    modified — only its metadata and hash are stored.
    """

    id: str = Field(default_factory=lambda: uuid4().hex)
    evidence_number: str  # Human-readable: EVD-NNN
    case_id: str
    type: EvidenceType = EvidenceType.OTHER
    original_path: str
    filename: str
    size_bytes: int | None = None
    sha256: str | None = None
    read_only: bool = True
    # Detected source (defair.sources.detect): kind + details
    source_kind: str | None = None
    source_info: dict = Field(default_factory=dict)
    # Result of prepare_evidence (root, manifest…), empty until prepared
    prepared: dict = Field(default_factory=dict)
    registered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


def generate_evidence_number(sequence: int) -> str:
    """Generate a human-readable evidence number.

    Format: EVD-NNN (e.g. EVD-001)
    """
    return f"EVD-{sequence:03d}"
