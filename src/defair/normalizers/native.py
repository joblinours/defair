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


def _skip(normalizer: BaseNormalizer, reason: str, n: int = 1) -> None:
    reasons = normalizer.stats.setdefault("skip_reasons", {})
    reasons[reason] = reasons.get(reason, 0) + n


def _join(directory: str | None, name: str) -> str:
    if not directory:
        return name
    return f"{directory.rstrip('/').rstrip(chr(92))}\\{name}"


class IndxNativeNormalizer(BaseNormalizer):
    """``$I30`` slack entries → windows.ntfs.indx_slack artifacts."""

    @property
    def tool_name(self) -> str:
        return "indx_native"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        path = _join(row.get("directory"), row["name"])
        data = {k: v for k, v in row.items() if not k.startswith("_")}
        data["path"] = path
        return {
            "artifact_type": "windows.ntfs.indx_slack",
            "category": ArtifactCategory.DELETED_FILE,
            "source_tool": "indx_native",
            "source_file": row.get("_source_file", ""),
            "timestamp": row.get("created"),
            "timestamp_desc": "Created ($FN, INDX slack)",
            "description": f"INDX slack: {path}",
            "data": data,
            "record_key": f"{row.get('volume', 0)}:{row.get('directory_entry')}:"
                          f"{row.get('stream_offset')}",
            **ctx,
        }


LOGFILE_DESCRIPTIONS = {
    "file_linked": "name added to a folder",
    "file_unlinked": "name removed from a folder",
    "record_initialized": "FILE record created",
    "record_deallocated": "FILE record freed",
    "file_name_created": "$FILE_NAME attribute created",
    "file_name_deleted": "$FILE_NAME attribute removed (rename / delete)",
}


class LogFileNativeNormalizer(BaseNormalizer):
    """Decoded ``$LogFile`` operations → windows.ntfs.logfile_op artifacts."""

    @property
    def tool_name(self) -> str:
        return "logfile_native"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        operation = row.get("operation")
        if operation == "_undecoded":
            for name, n in (row.get("counts") or {}).items():
                _skip(self, f"$LogFile {name} (not decoded)", n)
            return None
        name = row.get("name") or f"<FILE record, parent {row.get('parent_entry')}>"
        data = {k: v for k, v in row.items() if not k.startswith("_")}
        return {
            "artifact_type": "windows.ntfs.logfile_op",
            "category": ArtifactCategory.DELETED_FILE if operation in (
                "file_unlinked", "record_deallocated", "file_name_deleted")
            else ArtifactCategory.FILE_FOLDER_OPENING,
            "source_tool": "logfile_native",
            "source_file": row.get("_source_file", ""),
            "timestamp": row.get("event_time"),
            "timestamp_desc": row.get("event_time_desc"),
            "description": f"$LogFile: {name} — {LOGFILE_DESCRIPTIONS.get(operation, operation)}",
            "data": data,
            "record_key": f"lsn#{row.get('lsn')}#{operation}",
            **ctx,
        }
