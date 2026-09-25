"""Native IIS W3C access log parser (``inetpub/logs/LogFiles/W3SVC*/u_ex*.log``).

W3C extended logs declare their columns in ``#Fields:`` headers (they may
change inside one file) and are written in UTC by definition. Each request
becomes one artifact: client IP, method, URI + query, status, user agent,
authenticated user — web shell use and exploitation attempts land here.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.native import NativeTool


class IisNativeTool(NativeTool):
    """Parse IIS W3C extended access logs."""

    module = "re"  # pure Python: always available

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="iis_native",
            display_name="IIS logs (native)",
            allowed_options=[],
            vendor="DEFAIR",
            description="IIS W3C extended access logs: one artifact per HTTP request (UTC).",
            category=ToolCategory.NETWORK,
            command="python-native",
            runtime="python",
            timeout=7200,
            capabilities=["iis", "web_server", "access_logs", "web_shell"],
            input_types=["u_ex*.log", "inetpub/logs/LogFiles directory"],
            output_formats=["jsonl"],
            artifact_types=["windows.iis.request"],
            sans_categories=["network_activity"],
        )

    def _inputs(self, input_path: str) -> list[Path]:
        path = Path(input_path)
        if path.is_dir():
            return sorted(p for p in path.rglob("*.log") if p.is_file())
        return [path]

    def parse_file(self, path: Path) -> Iterator[dict]:
        fields: list[str] = []
        with path.open(encoding="utf-8", errors="replace") as fh:
            for number, line in enumerate(fh, 1):
                line = line.rstrip("\r\n")
                if not line:
                    continue
                if line.startswith("#"):
                    if line.startswith("#Fields:"):
                        fields = line[len("#Fields:"):].split()
                    continue
                if not fields:
                    continue
                values = line.split(" ")
                if len(values) != len(fields):
                    continue  # truncated / malformed line
                row = {k: (None if v == "-" else v) for k, v in zip(fields, values, strict=True)}
                row["line_number"] = number
                if row.get("date") and row.get("time"):
                    row["time_utc"] = f"{row['date']}T{row['time']}Z"
                yield row
