"""Dissect plugins as a parsing engine (fallback, or ``engine=dissect``).

``target-query -f <plugin> -j <target>`` runs one Dissect plugin (evtx,
prefetch, amcache.applications, shimcache, lnk, mft.records, usnjrnl,
recyclebin, shellbags, userassist, runkeys, jumplist.*, activitiescache,
browser.history…) directly on the original evidence — disk image or triage
collection — without extracting anything. Records stream to ``records.jsonl``.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.models.tool_run import ToolRun, ToolRunStatus
from defair.tools.base import BaseTool

RECORDS_FILE = "records.jsonl"
# target-query exits 0 even when the plugin cannot run on this target
_FAILURE_MARKERS = ("Unsupported plugin", "Failed to find any loader", "Unsupported function",
                    "No plugin found", "not a valid plugin")


class DissectPluginTool(BaseTool):
    """Run one Dissect plugin on a target and capture its records."""

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="dissect_plugin",
            display_name="Dissect plugin",
            allowed_options=["plugin"],
            vendor="Fox-IT / NCC Group (dissect.target)",
            description=(
                "Runs a Dissect plugin (evtx, prefetch, amcache, shimcache, lnk, mft, "
                "usnjrnl, recyclebin, shellbags, userassist, runkeys, browser history…) "
                "directly on a disk image or triage collection."
            ),
            category=ToolCategory.DISCOVERY,
            command="target-query",
            runtime="python",
            timeout=7200,
            stdout_file=RECORDS_FILE,
            capabilities=["dissect", "fallback", "disk_image", "e01", "vmdk", "vhdx", "kape",
                          "velociraptor"],
            input_types=["E01", "raw", "vmdk", "vhd", "vhdx", "qcow2", "directory"],
            output_formats=["jsonl"],
            artifact_types=["windows.*"],
        )

    def is_available(self) -> bool:
        return shutil.which("target-query") is not None

    def build_command(self, input_path: str, output_dir: str, **kwargs) -> list[str]:
        # Without an explicit plugin: host / OS information
        plugin = kwargs.get("plugin") or "osinfo"
        return ["target-query", "-f", plugin, "-j", input_path]

    def check_result(self, tool_run: ToolRun, output_dir: Path) -> None:
        records = output_dir / RECORDS_FILE
        empty = not records.exists() or records.stat().st_size == 0
        markers = [m for m in _FAILURE_MARKERS if m in tool_run.stderr]
        if tool_run.status == ToolRunStatus.COMPLETED and empty and markers:
            tool_run.status = ToolRunStatus.FAILED
            tool_run.stderr = f"Dissect: {markers[0]}\n" + tool_run.stderr[-4000:]
