"""Normalizers for the pure-Python fallback parsers."""

from __future__ import annotations

from typing import Any, ClassVar

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


class MplogNativeNormalizer(BaseNormalizer):
    """Defender MPLog events → windows.defender.mplog artifacts."""

    CATEGORIES: ClassVar[dict] = {
        "detection": ArtifactCategory.MALWARE,
        "blocked_file": ArtifactCategory.MALWARE,
        "process": ArtifactCategory.PROGRAM_EXECUTION,
        "file_hash": ArtifactCategory.PROGRAM_EXECUTION,
        "original_file_name": ArtifactCategory.PROGRAM_EXECUTION,
        "exclusion": ArtifactCategory.PERSISTENCE,
    }

    @property
    def tool_name(self) -> str:
        return "mplog_native"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        event = row.get("event", "")
        subject = row.get("threat") or row.get("process") or row.get("target") or ""
        where = row.get("target") if row.get("threat") else row.get("max_time_file")
        description = f"Defender {event}: {subject}" + (f" — {where}" if where else "")
        data = {k: v for k, v in row.items() if not k.startswith("_")}
        artifact = {
            "artifact_type": "windows.defender.mplog",
            "category": self.CATEGORIES.get(event, ArtifactCategory.OTHER),
            "source_tool": "mplog_native",
            "source_file": row.get("_source_file", ""),
            "timestamp": row.get("time"),
            "timestamp_desc": "Logged (MPLog)",
            "description": description[:500],
            "tags": ["defender:detection"] if event == "detection" else [],
            "data": data,
            "record_key": f"{row.get('_source_file', '')}#{row.get('line_number')}",
            **ctx,
        }
        if event == "detection":
            artifact["severity"] = "high"
        return artifact


class PsReadLineNativeNormalizer(BaseNormalizer):
    """PSReadLine commands → windows.powershell.history artifacts (no timestamp)."""

    @property
    def tool_name(self) -> str:
        return "psreadline_native"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        command = row.get("command") or ""
        return {
            "artifact_type": "windows.powershell.history",
            "category": ArtifactCategory.PROGRAM_EXECUTION,
            "source_tool": "psreadline_native",
            "source_file": row.get("_source_file", ""),
            "timestamp": None,
            "username": row.get("user"),
            "description": f"PS> {command[:300]}",
            "data": {"command": command, "line_number": row.get("line_number"),
                     "index": row.get("index"), "user": row.get("user")},
            "record_key": f"{row.get('_source_file', '')}#{row.get('line_number')}",
            **ctx,
        }


class TasksNativeNormalizer(BaseNormalizer):
    """Scheduled Task definitions → windows.scheduled_task.definition artifacts."""

    @property
    def tool_name(self) -> str:
        return "tasks_native"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        actions = row.get("actions") or []
        commands = [" ".join(filter(None, (a.get("command"), a.get("arguments"))))
                    if a.get("type") == "exec" else f"COM {a.get('class_id')}" for a in actions]
        name = row.get("task_path") or row.get("uri") or ""
        return {
            "artifact_type": "windows.scheduled_task.definition",
            "category": ArtifactCategory.PERSISTENCE,
            "source_tool": "tasks_native",
            "source_file": row.get("_source_file", ""),
            "timestamp": row.get("registration_date"),
            "timestamp_desc": "Task Registered",
            "username": row.get("user_id"),
            "description": f"Task {name}: {'; '.join(commands) or '(no action)'}"[:500],
            "data": {k: v for k, v in row.items() if not k.startswith("_")},
            "record_key": f"task#{name}",
            **ctx,
        }


class WebCacheNativeNormalizer(BaseNormalizer):
    """WebCache records → windows.browser.{history,download,cookie} artifacts."""

    TYPES: ClassVar[dict] = {
        "history": ("windows.browser.history", ArtifactCategory.BROWSER_USAGE),
        "download": ("windows.browser.download", ArtifactCategory.FILE_DOWNLOAD),
        "cookie": ("windows.browser.cookie", ArtifactCategory.BROWSER_USAGE),
    }

    @property
    def tool_name(self) -> str:
        return "webcache_native"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        if row.get("_error"):
            _skip(self, row["_error"][:200])
            return None
        kind = row.get("kind", "history")
        artifact_type, category = self.TYPES.get(kind, self.TYPES["history"])
        url = row.get("url") or ""
        if url.lower().startswith("file:///"):
            category = ArtifactCategory.FILE_FOLDER_OPENING
        timestamp = row.get("AccessedTime") or row.get("ModifiedTime")
        return {
            "artifact_type": artifact_type,
            "category": category,
            "source_tool": "webcache_native",
            "source_file": row.get("_source_file", ""),
            "timestamp": timestamp,
            "timestamp_desc": "Last Accessed" if row.get("AccessedTime") else "Modified",
            "username": row.get("user"),
            "description": url[:500],
            "data": {k: v for k, v in row.items() if not k.startswith("_")},
            "record_key": f"{row.get('container_id')}#{row.get('entry_id')}",
            **ctx,
        }


class RdpCacheNativeNormalizer(BaseNormalizer):
    """Rebuilt RDP bitmap caches → windows.rdp.bitmap_cache artifacts."""

    @property
    def tool_name(self) -> str:
        return "rdpcache_native"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        if row.get("tiles_skipped"):
            _skip(self, "RDP cache compressed tiles (not decoded)", row["tiles_skipped"])
        return {
            "artifact_type": "windows.rdp.bitmap_cache",
            "category": ArtifactCategory.ACCOUNT_USAGE,
            "source_tool": "rdpcache_native",
            "source_file": row.get("_source_file", ""),
            "timestamp": None,
            "username": row.get("user"),
            "description": f"RDP bitmap cache {row.get('cache_file')}: {row.get('tiles', 0)} tile(s)"
                           + (f" — collage {row['collage']}" if row.get("collage") else ""),
            "data": {k: v for k, v in row.items() if not k.startswith("_")},
            "record_key": f"rdpcache#{row.get('_source_file', '')}",
            **ctx,
        }


class IisNativeNormalizer(BaseNormalizer):
    """IIS W3C requests → windows.iis.request artifacts."""

    @property
    def tool_name(self) -> str:
        return "iis_native"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        uri = row.get("cs-uri-stem") or ""
        if row.get("cs-uri-query"):
            uri = f"{uri}?{row['cs-uri-query']}"
        data = {k: v for k, v in row.items() if not k.startswith("_")}
        return {
            "artifact_type": "windows.iis.request",
            "category": ArtifactCategory.NETWORK_ACTIVITY,
            "source_tool": "iis_native",
            "source_file": row.get("_source_file", ""),
            "timestamp": row.get("time_utc"),
            "timestamp_desc": "Request Received",
            "username": row.get("cs-username"),
            "description": f"{row.get('c-ip', '?')} {row.get('cs-method', '')} {uri} → "
                           f"{row.get('sc-status', '')}"[:500],
            "data": data,
            "record_key": f"{row.get('_source_file', '')}#{row.get('line_number')}",
            **ctx,
        }
