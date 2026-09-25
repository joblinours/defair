"""Native EVTX parser (pyevtx-rs) — fallback when EvtxECmd fails."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.normalizers.evtx_flatten import flatten_event
from defair.tools.native import NativeTool


class EvtxNativeTool(NativeTool):
    """Parse EVTX files with the ``evtx`` (pyevtx-rs) library."""

    suffixes = (".evtx",)
    module = "evtx"

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="evtx_native",
            display_name="EVTX (native)",
            allowed_options=[],
            vendor="DEFAIR (pyevtx-rs)",
            description="Pure-Python EVTX parser; fallback for EvtxECmd.",
            category=ToolCategory.EVENTLOG,
            command="python-native",
            runtime="python",
            timeout=3600,
            capabilities=["evtx", "fallback"],
            input_types=["evtx"],
            output_formats=["jsonl"],
            artifact_types=["windows.evtx.*"],
            sans_categories=["account_usage", "program_execution", "persistence"],
        )

    def parse_file(self, path: Path) -> Iterator[dict]:
        from evtx import PyEvtxParser

        for record in PyEvtxParser(str(path)).records_json():
            flat = flatten_event(json.loads(record["data"]))
            flat.setdefault("EventRecordID", record.get("event_record_id"))
            flat.setdefault("TimeCreated", record.get("timestamp"))
            yield flat
