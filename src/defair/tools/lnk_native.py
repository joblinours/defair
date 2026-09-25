"""Native LNK parser (LnkParse3) — fallback when LECmd fails."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.native import NativeTool


class LnkNativeTool(NativeTool):
    """Parse Windows shortcut files with LnkParse3."""

    suffixes = (".lnk",)
    module = "LnkParse3"

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="lnk_native",
            display_name="LNK (native)",
            allowed_options=[],
            vendor="DEFAIR (LnkParse3)",
            description="Pure-Python LNK parser; fallback for LECmd.",
            category=ToolCategory.FILESYSTEM,
            command="python-native",
            runtime="python",
            timeout=1800,
            capabilities=["lnk", "fallback"],
            input_types=["lnk"],
            output_formats=["jsonl"],
            artifact_types=["windows.lnk.shortcut"],
            sans_categories=["file_folder_opening"],
        )

    def parse_file(self, path: Path) -> Iterator[dict]:
        import LnkParse3

        with path.open("rb") as fh:
            info = LnkParse3.lnk_file(fh).get_json()
        header = info.get("header") or {}
        data = info.get("data") or {}
        link_info = info.get("link_info") or {}
        yield {
            "target_created": header.get("creation_time"),
            "target_modified": header.get("modified_time"),
            "target_accessed": header.get("accessed_time"),
            "file_size": header.get("file_size"),
            "local_path": link_info.get("local_base_path") or link_info.get("common_path_suffix"),
            "relative_path": data.get("relative_path"),
            "working_directory": data.get("working_directory"),
            "arguments": data.get("command_line_arguments"),
            "icon_location": data.get("icon_location"),
            "machine_id": (info.get("extra") or {}).get("DISTRIBUTED_LINK_TRACKER_BLOCK", {}).get("machine_identifier"),
        }
