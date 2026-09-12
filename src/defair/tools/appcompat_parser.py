"""AppCompatCacheParser wrapper — Shimcache / AppCompatCache parser.

Covers SANS FOR500 categories:
- Program Execution (Shimcache)
  - Executable path
  - Last modified timestamp of the file
  - Cache entry position (execution order indicator)
  - Execution flag (Win7 and earlier)

Shimcache (AppCompatCache) is stored in SYSTEM registry hive.
It tracks file path and last modification time of executables
that Windows checked for compatibility shims.

Note: Presence in Shimcache doesn't always mean execution (post-Win7),
but it means the OS interacted with the file.
"""

from __future__ import annotations

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.base import BaseTool


class AppCompatCacheParserTool(BaseTool):
    """Wrapper for Eric Zimmerman's AppCompatCacheParser."""

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="appcompatcacheparser",
            display_name="AppCompatCacheParser",
            vendor="Eric Zimmerman",
            description="Shimcache / AppCompatCache parser. Extracts file paths, modification times, and cache positions from SYSTEM hive.",
            category=ToolCategory.EXECUTION,
            command="AppCompatCacheParser",
            runtime="dotnet",
            timeout=600,
            capabilities=["shimcache", "appcompatcache", "execution_indicator"],
            input_types=["SYSTEM"],
            output_formats=["csv"],
            artifact_types=[
                "windows.shimcache.cache_entry",
            ],
            sans_categories=["program_execution"],
        )

    def build_command(self, input_path: str, output_dir: str, **kwargs) -> list[str]:
        cmd = ["AppCompatCacheParser", "-f", input_path, "--csv", output_dir]
        if kwargs.get("sort_by_timestamp"):
            cmd.append("-t")
        return cmd
