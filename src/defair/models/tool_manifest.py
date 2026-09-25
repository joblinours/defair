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
    DETECTION = "detection"
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
    # Working directory for tools that resolve data relative to it (Hayabusa)
    cwd: str | None = None
    # Tools that print their results: stdout is streamed to this file
    stdout_file: str | None = None
    # Registered tool to run instead when this one fails (pure-Python parser)
    fallback: str | None = None
    # Exit codes meaning "ran fine" (e.g. scanners exit 2 when they match)
    success_exit_codes: list[int] = Field(default_factory=lambda: [0])
    # Keyword options a caller (CLI --option / MCP run_tool) may pass
    allowed_options: list[str] = Field(default_factory=list)

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
