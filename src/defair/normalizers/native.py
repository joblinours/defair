"""Normalizers for the pure-Python fallback parsers."""

from __future__ import annotations

from typing import Any

from defair.models.artifact import ArtifactCategory
from defair.normalizers.base import BaseNormalizer, parse_timestamp


class EvtxNativeNormalizer(BaseNormalizer):
    """Flattened EVTX records → the same artifacts as EvtxECmd."""

    @property
    def tool_name(self) -> str:
        return "evtx_native"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        from defair.normalizers.eztools import classify_evtx

        event_id = row.get("EventID")
        channel = row.get("Channel", "")
        info = classify_evtx(event_id, channel)
        source = row.get("_source_file", "")
        event_data = {k: v for k, v in row.items() if not k.startswith("_")}
        username = row.get("TargetUserName") or row.get("SubjectUserName") or row.get("User")
        artifact = {
            "artifact_type": info["artifact_type"],
            "category": info["category"],
            "source_tool": "evtx_native",
            "source_file": source,
            "timestamp": row.get("TimeCreated"),
            "hostname": row.get("Computer"),
            "username": username,
            "description": info["catalog_description"] or f"EventID {event_id} ({channel})",
            "tags": [f"mitre:{t}" for t in info["mitre"]],
            "data": {
                "event_id": str(event_id) if event_id is not None else "",
                "channel": channel,
                "provider": row.get("Provider", ""),
                "record_number": row.get("EventRecordID"),
                "event_data": event_data,
                "catalog_description": info["catalog_description"],
                "mitre_techniques": info["mitre"],
            },
            **ctx,
        }
        if row.get("EventRecordID") is not None:
            artifact["record_key"] = f"{source}#{row['EventRecordID']}"
        return artifact


class LnkNativeNormalizer(BaseNormalizer):
    """LnkParse3 output → windows.lnk.shortcut artifacts (same shape as LECmd)."""

    @property
    def tool_name(self) -> str:
        return "lnk_native"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        target = row.get("local_path") or row.get("relative_path") or ""
        return {
            "artifact_type": "windows.lnk.shortcut",
            "category": ArtifactCategory.FILE_FOLDER_OPENING,
            "source_tool": "lnk_native",
            "source_file": row.get("_source_file", ""),
            "timestamp": parse_timestamp(row.get("target_created")),
            "description": target,
            "data": {
                "target_path": target,
                "arguments": row.get("arguments"),
                "working_directory": row.get("working_directory"),
                "file_size": row.get("file_size"),
                "machine_id": row.get("machine_id"),
                "target_created": parse_timestamp(row.get("target_created")),
                "target_modified": parse_timestamp(row.get("target_modified")),
                "target_accessed": parse_timestamp(row.get("target_accessed")),
            },
            **ctx,
        }
