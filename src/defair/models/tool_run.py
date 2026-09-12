"""ToolRun model — tracks every tool execution for provenance."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class ToolRunStatus(StrEnum):
    """Execution status of a tool run."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class ToolRun(BaseModel):
    """A single execution of a forensic tool.

    Every analysis produces a ToolRun that records:
    - which tool ran (name, version)
    - what input it processed
    - what it produced
    - exit code, stdout/stderr
    - timing information

    This is the backbone of forensic provenance — every artifact
    can be traced back to the tool run that created it.
    """

    id: str = Field(default_factory=lambda: uuid4().hex)
    run_number: str  # Human-readable: RUN-NNN
    case_id: str
    evidence_id: str | None = None

    tool_name: str  # e.g. "mftecmd", "evtxecmd"
    tool_version: str | None = None
    command: str = ""  # Normalized command line
    parameters: dict = Field(default_factory=dict)

    status: ToolRunStatus = ToolRunStatus.PENDING
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""

    output_path: str | None = None  # Where outputs were stored
    output_files: list[str] = Field(default_factory=list)
    output_hash: str | None = None  # SHA-256 of primary output

    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_seconds: float | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


def generate_run_number(sequence: int) -> str:
    """Generate a human-readable run number.

    Format: RUN-NNN (e.g. RUN-001)
    """
    return f"RUN-{sequence:03d}"
