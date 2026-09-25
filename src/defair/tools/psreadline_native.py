"""Native PowerShell PSReadLine history parser (``ConsoleHost_history.txt``).

PSReadLine saves every interactive command a user typed in PowerShell, per
user, even when script block logging is off. The file has no timestamps:
each command keeps its position (``line_number``), and multi-line commands
(continued with a backtick or typed in a block) are rejoined.

Located at: ``Users/<user>/AppData/Roaming/Microsoft/Windows/PowerShell/
PSReadLine/ConsoleHost_history.txt``
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.native import NativeTool


class PsReadLineNativeTool(NativeTool):
    """Parse PowerShell PSReadLine command history."""

    module = "re"  # pure Python: always available

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="psreadline_native",
            display_name="PowerShell history (native)",
            allowed_options=[],
            vendor="DEFAIR",
            description="PSReadLine ConsoleHost_history.txt: commands typed by each user in PowerShell.",
            category=ToolCategory.EXECUTION,
            command="python-native",
            runtime="python",
            timeout=600,
            capabilities=["powershell", "psreadline", "command_history", "program_execution"],
            input_types=["ConsoleHost_history.txt", "Users directory"],
            output_formats=["jsonl"],
            artifact_types=["windows.powershell.history"],
            sans_categories=["program_execution"],
        )

    def _inputs(self, input_path: str) -> list[Path]:
        path = Path(input_path)
        if path.is_dir():
            return sorted(p for p in path.rglob("*")
                          if p.is_file() and p.name.lower().endswith("_history.txt"))
        return [path]

    def parse_file(self, path: Path) -> Iterator[dict]:
        text = path.read_bytes().decode("utf-8-sig", errors="replace")
        user = user_from_path(path)
        total = 0
        buffer: list[str] = []
        start = 0
        for number, line in enumerate(text.splitlines(), 1):
            if not buffer:
                start = number
            buffer.append(line)
            if line.endswith("`"):
                continue  # continued on the next line
            command = "\n".join(buffer).strip()
            buffer = []
            if command:
                total += 1
                yield {"command": command, "line_number": start, "index": total, "user": user}
        if buffer and "\n".join(buffer).strip():
            yield {"command": "\n".join(buffer).strip(), "line_number": start,
                   "index": total + 1, "user": user}


def user_from_path(path: Path) -> str | None:
    parts = [p.lower() for p in path.parts]
    if "users" in parts:
        index = parts.index("users")
        if index + 1 < len(path.parts):
            return path.parts[index + 1]
    return None
