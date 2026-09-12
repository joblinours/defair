"""JLECmd wrapper — Windows Jump List parser.

Covers SANS FOR500 categories:
- Program Execution (recent/frequent program use)
- File/Folder Opening (files opened by specific programs)
- File Download (downloaded files appearing in jump lists)

Jump Lists record:
- Files recently opened by each application (by AppID)
- AutomaticDestinations: auto-populated by the OS
- CustomDestinations: pinned items by the user
- Target file timestamps and paths
- First and last interaction times
"""

from __future__ import annotations

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.base import BaseTool


class JLECmdTool(BaseTool):
    """Wrapper for Eric Zimmerman's JLECmd."""

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="jlecmd",
            display_name="JLECmd",
            vendor="Eric Zimmerman",
            description="Windows Jump List parser. Extracts recently/frequently accessed files per application from AutomaticDestinations and CustomDestinations.",
            category=ToolCategory.FILESYSTEM,
            command="JLECmd",
            runtime="dotnet",
            timeout=1800,
            capabilities=["jump_lists", "automatic_destinations", "custom_destinations", "appid"],
            input_types=["automaticDestinations-ms", "customDestinations-ms"],
            output_formats=["csv", "json"],
            artifact_types=[
                "windows.jumplist.auto_entry",
                "windows.jumplist.custom_entry",
            ],
            sans_categories=[
                "program_execution",
                "file_folder_opening",
                "file_download",
            ],
        )

    def build_command(self, input_path: str, output_dir: str, **kwargs) -> list[str]:
        cmd = ["JLECmd"]

        if kwargs.get("directory"):
            cmd.extend(["-d", input_path])
        else:
            cmd.extend(["-f", input_path])

        cmd.extend(["--csv", output_dir])

        if kwargs.get("json_output"):
            cmd.extend(["--json", output_dir])
        if kwargs.get("all_files"):
            cmd.append("--all")

        return cmd
