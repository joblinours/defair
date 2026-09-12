"""PECmd wrapper — Windows Prefetch file parser.

Covers SANS FOR500 categories:
- Program Execution (which programs ran, when, how often)
- File/Folder Opening (files/dirs referenced by executed programs)

Prefetch files (.pf) record:
- Executable name and path
- Run count and last 8 run times
- Files and directories referenced during first 10 seconds
- Volume information
"""

from __future__ import annotations

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.base import BaseTool


class PECmdTool(BaseTool):
    """Wrapper for Eric Zimmerman's PECmd."""

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="pecmd",
            display_name="PECmd",
            vendor="Eric Zimmerman",
            description="Windows Prefetch parser. Extracts execution history, run counts, timestamps, and referenced files/directories.",
            category=ToolCategory.EXECUTION,
            command="PECmd",
            runtime="dotnet",
            timeout=1800,
            capabilities=["prefetch", "execution_history", "run_count", "referenced_files"],
            input_types=["pf"],
            output_formats=["csv", "json"],
            artifact_types=[
                "windows.prefetch.execution",
                "windows.prefetch.referenced_file",
                "windows.prefetch.volume",
            ],
            sans_categories=["program_execution", "file_folder_opening"],
        )

    def build_command(self, input_path: str, output_dir: str, **kwargs) -> list[str]:
        cmd = ["PECmd"]

        if kwargs.get("directory"):
            cmd.extend(["-d", input_path])
        else:
            cmd.extend(["-f", input_path])

        cmd.extend(["--csv", output_dir])

        if kwargs.get("json_output"):
            cmd.extend(["--json", output_dir])

        return cmd
