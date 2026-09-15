"""Artifact model — normalized forensic artifacts extracted by tools."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class ArtifactCategory(StrEnum):
    """High-level artifact category based on SANS FOR500 poster."""

    PROGRAM_EXECUTION = "program_execution"
    FILE_DOWNLOAD = "file_download"
    FILE_FOLDER_OPENING = "file_folder_opening"
    DELETED_FILE = "deleted_file"
    NETWORK_ACTIVITY = "network_activity"
    EXTERNAL_DEVICE = "external_device"
    ACCOUNT_USAGE = "account_usage"
    BROWSER_USAGE = "browser_usage"
    PERSISTENCE = "persistence"
    SYSTEM_INFO = "system_info"
    MALWARE = "malware"
    OTHER = "other"


class Artifact(BaseModel):
    """A normalized forensic artifact extracted from evidence.

    Artifacts are the core output of forensic analysis. Each artifact
    is linked to its source evidence and the tool run that produced it,
    enabling full provenance tracking.

    The artifact_type follows a dotted naming convention:
        windows.evtx.logon
        windows.prefetch.execution
        windows.registry.userassist
        windows.mft.file_entry
        windows.lnk.shortcut
        windows.recyclebin.deleted_item
        windows.shellbags.folder_access
        windows.amcache.program_entry
        windows.shimcache.app_compat
        windows.jumplist.recent_item
        windows.srum.network_usage
        windows.timeline.activity
        windows.browser.history
    """

    id: str = Field(default_factory=lambda: uuid4().hex)
    artifact_number: str  # Human-readable: ART-NNN
    case_id: str
    evidence_id: str | None = None
    run_id: str | None = None  # Link to ToolRun

    artifact_type: str  # Dotted type: windows.evtx.logon
    category: ArtifactCategory = ArtifactCategory.OTHER
    source_tool: str = ""  # Tool that produced this artifact
    source_file: str = ""  # Source file within the evidence

    # Core forensic data
    timestamp: datetime | None = None
    end_timestamp: datetime | None = None
    hostname: str | None = None
    username: str | None = None
    description: str = ""

    # Flexible data — tool-specific fields
    data: dict = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    severity: str | None = None  # informational, low, medium, high, critical

    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


def generate_artifact_number(sequence: int) -> str:
    """Generate a human-readable artifact number.

    Format: ART-NNN (e.g. ART-001)
    """
    return f"ART-{sequence:03d}"
