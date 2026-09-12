"""AmcacheParser wrapper — Amcache.hve analyzer.

Covers SANS FOR500 categories:
- Program Execution (application compatibility cache)
  - Full path of executed programs
  - First execution time (key last write time)
  - SHA-1 hash of executables
  - File size and version info
  - Publisher information

Amcache.hve is a registry hive that tracks application execution
and driver/device installation. Critical for proving program execution.
"""

from __future__ import annotations

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.base import BaseTool


class AmcacheParserTool(BaseTool):
    """Wrapper for Eric Zimmerman's AmcacheParser."""

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="amcacheparser",
            display_name="AmcacheParser",
            vendor="Eric Zimmerman",
            description="Amcache.hve parser. Extracts application execution records, SHA-1 hashes, file metadata, and driver information.",
            category=ToolCategory.EXECUTION,
            command="AmcacheParser",
            runtime="dotnet",
            timeout=1800,
            capabilities=["amcache", "execution_history", "sha1_hash", "file_metadata", "drivers"],
            input_types=["Amcache.hve"],
            output_formats=["csv"],
            artifact_types=[
                "windows.amcache.program_entry",
                "windows.amcache.file_entry",
                "windows.amcache.driver_binary",
                "windows.amcache.device_container",
            ],
            sans_categories=["program_execution"],
        )

    def build_command(self, input_path: str, output_dir: str, **kwargs) -> list[str]:
        cmd = ["AmcacheParser", "-f", input_path, "--csv", output_dir]
        if kwargs.get("include_linked"):
            cmd.append("-i")
        return cmd
