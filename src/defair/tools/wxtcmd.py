"""WxTCmd wrapper — Windows 10/11 Timeline (ActivitiesCache.db) parser.

Covers SANS FOR500 categories:
- Program Execution (Windows Timeline activities)
  - Application usage with focus time
  - File access history
  - Activity start/end timestamps
  - Device sync information
  - Content URI and clipboard data

ActivitiesCache.db is a SQLite database at:
  C:\\Users\\<user>\\AppData\\Local\\ConnectedDevicesPlatform\\<id>\\ActivitiesCache.db

Note: Feature was deprecated in Windows 11 but the database may still exist.
"""

from __future__ import annotations

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.base import BaseTool


class WxTCmdTool(BaseTool):
    """Wrapper for Eric Zimmerman's WxTCmd."""

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="wxtcmd",
            display_name="WxTCmd",
            allowed_options=[],
            vendor="Eric Zimmerman",
            description="Windows 10/11 Timeline parser. Extracts activity history, app usage, focus times, and file access from ActivitiesCache.db.",
            category=ToolCategory.TIMELINE,
            command="WxTCmd",
            runtime="dotnet",
            timeout=600,
            capabilities=["windows_timeline", "activity_cache", "app_usage", "focus_time"],
            input_types=["ActivitiesCache.db"],
            output_formats=["csv"],
            artifact_types=[
                "windows.timeline.activity",
                "windows.timeline.activity_operation",
            ],
            sans_categories=["program_execution"],
        )

    def build_command(self, input_path: str, output_dir: str, **kwargs) -> list[str]:
        return ["WxTCmd", "-f", input_path, "--csv", output_dir]
