"""LECmd wrapper — Windows LNK shortcut file parser.

Covers SANS FOR500 categories:
- File/Folder Opening (shortcuts to recently opened files)
- File Download (shortcuts to downloaded files)
- External Device (shortcuts referencing removable drives, volume serial)
- Program Execution (shortcuts to executed programs)

LNK files contain:
- Target path and timestamps (created, modified, accessed)
- Volume information (serial number, type, label)
- Network share information
- Machine ID / MAC address
- Working directory and arguments
"""

from __future__ import annotations

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.base import BaseTool


class LECmdTool(BaseTool):
    """Wrapper for Eric Zimmerman's LECmd."""

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="lecmd",
            display_name="LECmd",
            allowed_options=["directory", "json_output"],
            vendor="Eric Zimmerman",
            description="Windows LNK shortcut parser. Extracts target paths, timestamps, volume info, MAC address, and network share data.",
            category=ToolCategory.FILESYSTEM,
            command="LECmd",
            runtime="dotnet",
            timeout=1800,
            capabilities=["lnk", "shortcuts", "volume_serial", "mac_address", "network_share"],
            input_types=["lnk"],
            output_formats=["csv", "json"],
            artifact_types=[
                "windows.lnk.shortcut",
            ],
            sans_categories=[
                "file_folder_opening",
                "file_download",
                "external_device",
                "program_execution",
            ],
        )

    def build_command(self, input_path: str, output_dir: str, **kwargs) -> list[str]:
        cmd = ["LECmd"]

        if kwargs.get("directory"):
            cmd.extend(["-d", input_path])
        else:
            cmd.extend(["-f", input_path])

        cmd.extend(["--csv", output_dir])

        if kwargs.get("json_output"):
            cmd.extend(["--json", output_dir])

        return cmd
