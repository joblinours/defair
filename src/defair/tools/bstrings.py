"""bstrings wrapper — string search in binary files (ASCII + Unicode).

Targeted searches through any file (hives, pagefile, memory dumps, unknown
binaries): a literal string (``search``), a regex (``regex``, or a built-in
pattern name such as ``ipv4``, ``url``, ``email``, ``guid``, ``b64``), or a
file of patterns. Every hit is written with its offset and encoding.

Mass extraction of every string (pagefile, unallocated space) is done by
``strings_native``; bstrings is for pattern hunting.
"""

from __future__ import annotations

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.base import BaseTool

OUTPUT_FILE = "bstrings.txt"


class BstringsTool(BaseTool):
    """Wrapper for Eric Zimmerman's bstrings."""

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="bstrings",
            display_name="bstrings",
            allowed_options=[
                "directory", "search", "regex", "search_file", "regex_file",
                "min_length", "max_length", "mask",
            ],
            vendor="Eric Zimmerman",
            description="Binary string search (ASCII + UTF-16): literal, regex or built-in patterns, with offsets.",
            category=ToolCategory.GENERAL,
            command="bstrings",
            runtime="dotnet",
            timeout=7200,
            # bstrings reads its data from stdin unless stdin is a terminal
            stdin_tty=True,
            capabilities=["strings", "regex_search", "ioc_search", "unicode"],
            input_types=["any binary file", "directory"],
            output_formats=["txt"],
            artifact_types=["windows.strings.match"],
            sans_categories=[],
        )

    def build_command(self, input_path: str, output_dir: str, **kwargs) -> list[str]:
        flag = "-d" if kwargs.get("directory") else "-f"
        cmd = ["bstrings", flag, input_path, "-o", f"{output_dir}/{OUTPUT_FILE}",
               "--off", "-q", "-s"]
        for option, arg in (("search", "--ls"), ("regex", "--lr"), ("search_file", "--fs"),
                            ("regex_file", "--fr"), ("min_length", "-m"),
                            ("max_length", "-x"), ("mask", "--mask")):
            if kwargs.get(option) not in (None, ""):
                cmd.extend([arg, str(kwargs[option])])
        return cmd
