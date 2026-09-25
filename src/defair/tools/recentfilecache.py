"""RecentFileCacheParser wrapper — RecentFileCache.bcf (Windows 7 / 2008 R2).

Covers SANS FOR500 categories:
- Program Execution (executables recorded by the Application Experience service)

RecentFileCache.bcf lists paths of executables recently run, mostly from
removable media or new locations; it replaced by Amcache.hve on Windows 8+.
Entries carry no timestamp of their own.

Located at: C:\\Windows\\AppCompat\\Programs\\RecentFileCache.bcf
"""

from __future__ import annotations

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.base import BaseTool


class RecentFileCacheParserTool(BaseTool):
    """Wrapper for Eric Zimmerman's RecentFileCacheParser."""

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="recentfilecacheparser",
            display_name="RecentFileCacheParser",
            allowed_options=[],
            vendor="Eric Zimmerman",
            description="RecentFileCache.bcf parser (Windows 7): paths of recently executed programs.",
            category=ToolCategory.EXECUTION,
            command="RecentFileCacheParser",
            runtime="dotnet",
            timeout=600,
            capabilities=["recentfilecache", "program_execution"],
            input_types=["RecentFileCache.bcf"],
            output_formats=["csv"],
            artifact_types=["windows.recentfilecache.entry"],
            sans_categories=["program_execution"],
        )

    def build_command(self, input_path: str, output_dir: str, **kwargs) -> list[str]:
        return ["RecentFileCacheParser", "-f", input_path, "--csv", output_dir, "-q"]
