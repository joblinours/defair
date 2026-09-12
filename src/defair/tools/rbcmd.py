"""RBCmd wrapper — Windows Recycle Bin ($I / $R) parser.

Covers SANS FOR500 categories:
- Deleted File Knowledge
  - Original filename and path
  - Deletion timestamp
  - File size
  - User SID who deleted the file

Win10+ uses $I files (metadata) and $R files (actual data).
Older Windows used INFO2 format.
"""

from __future__ import annotations

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.base import BaseTool


class RBCmdTool(BaseTool):
    """Wrapper for Eric Zimmerman's RBCmd."""

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="rbcmd",
            display_name="RBCmd",
            vendor="Eric Zimmerman",
            description="Recycle Bin parser. Extracts original path, deletion time, file size, and user SID from $I/$R files.",
            category=ToolCategory.FILESYSTEM,
            command="RBCmd",
            runtime="dotnet",
            timeout=600,
            capabilities=["recycle_bin", "deleted_files", "original_path", "deletion_time"],
            input_types=["$I", "$R", "INFO2"],
            output_formats=["csv"],
            artifact_types=[
                "windows.recyclebin.deleted_item",
            ],
            sans_categories=["deleted_file"],
        )

    def build_command(self, input_path: str, output_dir: str, **kwargs) -> list[str]:
        cmd = ["RBCmd"]

        if kwargs.get("directory"):
            cmd.extend(["-d", input_path])
        else:
            cmd.extend(["-f", input_path])

        cmd.extend(["--csv", output_dir])
        return cmd
