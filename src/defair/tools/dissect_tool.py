"""Dissect wrapper — evidence discovery and artifact identification.

Dissect is the primary discovery engine. It can:
- Identify host OS, hostname, domain
- Discover available artifact types
- Access filesystems within disk images
- Extract specific files and artifacts
- Parse Windows/Linux artifacts natively

Used as the FIRST tool in any investigation to determine
what artifacts are available and which tools to run.
"""

from __future__ import annotations

import shutil

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.base import BaseTool


class DissectTool(BaseTool):
    """Wrapper for FOX-IT Dissect framework."""

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="dissect",
            display_name="Dissect",
            vendor="FOX-IT / NCC Group",
            description="Forensic framework for evidence discovery, host identification, artifact extraction, and filesystem access. Python-native, no external runtime needed.",
            category=ToolCategory.DISCOVERY,
            command="target-query",
            runtime="python",
            timeout=3600,
            capabilities=[
                "discovery", "host_identification", "filesystem_access",
                "artifact_extraction", "disk_image", "e01", "vmdk",
                "vhd", "raw", "ntfs", "ext4", "registry", "evtx",
            ],
            input_types=["E01", "raw", "dd", "vmdk", "vhd", "vhdx", "qcow2"],
            output_formats=["csv", "json", "record"],
            artifact_types=[
                "discovery.host_info",
                "discovery.os_info",
                "discovery.artifact_list",
                "discovery.filesystem",
                "discovery.partition",
            ],
            sans_categories=[],  # Discovery tool, not artifact-specific
        )

    def is_available(self) -> bool:
        """Check if dissect is importable."""
        return shutil.which("target-query") is not None

    def build_command(self, input_path: str, output_dir: str, **kwargs) -> list[str]:
        function = kwargs.get("function", "general.default")
        cmd = ["target-query", "-t", input_path, "-f", function]

        if kwargs.get("output_format", "csv") == "json":
            cmd.extend(["-j"])
        if kwargs.get("list_functions"):
            cmd = ["target-query", "-t", input_path, "-l"]

        return cmd

    def build_info_command(self, input_path: str) -> list[str]:
        """Build command for target-info (host identification)."""
        return ["target-info", "-t", input_path]

    def build_fs_command(self, input_path: str, fs_path: str) -> list[str]:
        """Build command for filesystem access."""
        return ["target-fs", "-t", input_path, "cat", fs_path]
