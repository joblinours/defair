"""SQLECmd wrapper — SQLite database parser for forensic artifacts.

Covers SANS FOR500 categories:
- Browser Usage (Chrome/Firefox/Edge history, cookies, downloads, sessions)
- File Download (browser downloads database)
- Network Activity (browser search terms, typed URLs)
- Program Execution (SRUM via SQLite)

SQLECmd uses map files to parse known SQLite databases:
- Browser databases (Chrome, Firefox, Edge)
- Windows databases (SRUM, Notifications, etc.)
- Application-specific databases
"""

from __future__ import annotations

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.base import BaseTool


class SQLECmdTool(BaseTool):
    """Wrapper for Eric Zimmerman's SQLECmd."""

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="sqlecmd",
            display_name="SQLECmd",
            allowed_options=["directory", "maps_dir"],
            vendor="Eric Zimmerman",
            description="SQLite forensic parser. Uses map files to extract browser history, downloads, cookies, SRUM data, and other forensic artifacts from SQLite databases.",
            category=ToolCategory.BROWSER,
            command="SQLECmd",
            runtime="dotnet",
            timeout=1800,
            capabilities=[
                "sqlite", "browser_history", "browser_downloads", "browser_cookies",
                "chrome", "firefox", "edge", "notifications",
            ],
            input_types=["sqlite", "db", "sqlite3"],
            output_formats=["csv"],
            artifact_types=[
                "windows.browser.history",
                "windows.browser.download",
                "windows.browser.cookie",
                "windows.browser.autofill",
                "windows.browser.login",
                "windows.browser.search_term",
                "windows.browser.session",
                "windows.sqlite.generic",
            ],
            sans_categories=[
                "browser_usage",
                "file_download",
                "network_activity",
            ],
        )

    def build_command(self, input_path: str, output_dir: str, **kwargs) -> list[str]:
        cmd = ["SQLECmd"]

        if kwargs.get("directory"):
            cmd.extend(["-d", input_path])
        else:
            cmd.extend(["-f", input_path])

        cmd.extend(["--csv", output_dir])

        if kwargs.get("maps_dir"):
            cmd.extend(["--maps", kwargs["maps_dir"]])

        return cmd
