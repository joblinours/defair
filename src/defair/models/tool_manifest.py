"""ToolManifest model — describes a forensic tool's capabilities."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class ToolCategory(StrEnum):
    """Category of forensic tool."""

    FILESYSTEM = "filesystem"
    EVENTLOG = "eventlog"
    REGISTRY = "registry"
    EXECUTION = "execution"
    BROWSER = "browser"
    NETWORK = "network"
    MEMORY = "memory"
    PERSISTENCE = "persistence"
    TIMELINE = "timeline"
    DISCOVERY = "discovery"
    GENERAL = "general"


class ToolStatus(StrEnum):
    """Maturity status of a tool integration."""

    SUPPORTED = "supported"
    EXPERIMENTAL = "experimental"
    LEGACY = "legacy"
    UNAVAILABLE = "unavailable"


class ToolManifest(BaseModel):
    """Manifest describing a forensic tool's capabilities and execution.

    Each integrated tool has a manifest that tells the system:
    - what it does (category, capabilities, artifact types)
    - how to run it (command, arguments, timeout)
    - what it needs (input types, dependencies)
    - what it produces (output format, artifact types)
    """

    name: str  # Unique identifier: "mftecmd", "evtxecmd", etc.
    display_name: str  # Human-readable: "MFTECmd", "EvtxECmd"
    vendor: str = ""
    version: str | None = None
    description: str = ""
    category: ToolCategory = ToolCategory.GENERAL
    status: ToolStatus = ToolStatus.EXPERIMENTAL

    # Execution
    command: str = ""  # e.g. "/opt/eztools/MFTECmd" or "python -m dissect"
    runtime: str = "native"  # native, dotnet, python
    timeout: int = 3600  # Default timeout in seconds

    # Capabilities
    capabilities: list[str] = Field(default_factory=list)
    input_types: list[str] = Field(default_factory=list)  # file types accepted
    output_formats: list[str] = Field(default_factory=list)  # csv, json, jsonl
    artifact_types: list[str] = Field(default_factory=list)  # artifact types produced

    # SANS FOR500 categories this tool covers
    sans_categories: list[str] = Field(default_factory=list)

    # Security
    network_required: bool = False
    privileged: bool = False
