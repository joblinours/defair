"""MFTECmd wrapper — NTFS $MFT and $J (USN Journal) parser.

Covers SANS FOR500 categories:
- File Download (timestamps)
- File/Folder Opening (timestamps)
- Deleted File Knowledge (resident data, $I30)
- Program Execution (file creation timestamps)

Produces: CSV with file entries, timestamps (MACB), paths, sizes.
"""

from __future__ import annotations

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.base import BaseTool


class MFTECmdTool(BaseTool):
    """Wrapper for Eric Zimmerman's MFTECmd."""

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="mftecmd",
            display_name="MFTECmd",
            allowed_options=["body_file", "json_output", "mft_path"],
            vendor="Eric Zimmerman",
            description="NTFS $MFT and $J (USN Journal) parser. Extracts file metadata, timestamps, paths, and resident data.",
            category=ToolCategory.FILESYSTEM,
            command="MFTECmd",
            runtime="dotnet",
            timeout=3600,
            capabilities=["mft", "usn_journal", "ntfs", "file_timestamps", "macb"],
            input_types=["$MFT", "$J", "$SDS", "$Boot"],
            output_formats=["csv", "json"],
            artifact_types=[
                "windows.mft.file_entry",
                "windows.mft.directory_entry",
                "windows.usn.journal_entry",
            ],
            sans_categories=[
                "file_download",
                "file_folder_opening",
                "deleted_file",
                "program_execution",
            ],
        )

    def build_command(self, input_path: str, output_dir: str, **kwargs) -> list[str]:
        cmd = ["MFTECmd", "-f", input_path, "--csv", output_dir]
        # $J: the $MFT resolves each record's parent path
        if kwargs.get("mft_path") and _is_usn(input_path):
            cmd.extend(["-m", kwargs["mft_path"]])
        if kwargs.get("body_file"):
            cmd.extend(["--body", output_dir, "--bdl", "C"])
        if kwargs.get("json_output"):
            cmd.extend(["--json", output_dir])
        return cmd


def _is_usn(path: str) -> bool:
    name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name in ("$j", "$usnjrnl%3a$j", "$usnjrnl:$j", "j") or name.endswith("$j")
