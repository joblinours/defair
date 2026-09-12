"""SBECmd wrapper — Windows ShellBags parser.

Covers SANS FOR500 categories:
- File/Folder Opening
  - Folders accessed by the user (even if deleted)
  - First and last interaction timestamps
  - Folder paths including network shares and zip files
  - Evidence of folder access even after deletion

ShellBags are stored in NTUSER.DAT and UsrClass.dat registry hives.
They record folder browsing history in Windows Explorer.
"""

from __future__ import annotations

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.base import BaseTool


class SBECmdTool(BaseTool):
    """Wrapper for Eric Zimmerman's SBECmd."""

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="sbecmd",
            display_name="SBECmd",
            vendor="Eric Zimmerman",
            description="ShellBags parser. Extracts folder browsing history, timestamps, and evidence of folder access from NTUSER.DAT/UsrClass.dat.",
            category=ToolCategory.REGISTRY,
            command="SBECmd",
            runtime="dotnet",
            timeout=1800,
            capabilities=["shellbags", "folder_access", "browsing_history", "deleted_folders"],
            input_types=["NTUSER.DAT", "UsrClass.dat"],
            output_formats=["csv"],
            artifact_types=[
                "windows.shellbags.folder_access",
            ],
            sans_categories=["file_folder_opening"],
        )

    def build_command(self, input_path: str, output_dir: str, **kwargs) -> list[str]:
        cmd = ["SBECmd"]

        if kwargs.get("directory"):
            cmd.extend(["-d", input_path])
        else:
            cmd.extend(["-f", input_path])

        cmd.extend(["--csv", output_dir])
        return cmd
