"""Normalizer for Dissect records (``target-query -j``).

Dissect emits a ``recorddescriptor`` line per record type (its fields and
their types) followed by records. The descriptor tells which fields are
datetimes; the record type name (``filesystem/windows/evtx``,
``windows/prefetch``…) maps to DEFAIR artifact types, so Dissect results land
next to — and in the same shape as — the EZ Tools ones.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from defair.models.artifact import ArtifactCategory
from defair.normalizers.base import BaseNormalizer

# record type prefix → (artifact type, category, description field)
TYPE_MAP: list[tuple[str, str, ArtifactCategory, tuple[str, ...]]] = [
    ("filesystem/windows/evtx", "windows.evtx.generic", ArtifactCategory.OTHER, ("EventID",)),
    ("windows/prefetch", "windows.prefetch.execution", ArtifactCategory.PROGRAM_EXECUTION,
     ("filename", "linkedfile")),
    ("windows/appcompat/InventoryApplication", "windows.amcache.program_entry",
     ArtifactCategory.PROGRAM_EXECUTION, ("name", "path")),
    ("windows/appcompat", "windows.amcache.program_entry", ArtifactCategory.PROGRAM_EXECUTION,
     ("path", "name")),
    ("windows/shimcache", "windows.shimcache.cache_entry", ArtifactCategory.PROGRAM_EXECUTION,
     ("path",)),
    ("windows/filesystem/lnk", "windows.lnk.shortcut", ArtifactCategory.FILE_FOLDER_OPENING,
     ("target_path", "lnk_path")),
    ("filesystem/ntfs/mft", "windows.mft.file_entry", ArtifactCategory.OTHER, ("path",)),
    ("filesystem/ntfs/usnjrnl", "windows.usn.journal_entry", ArtifactCategory.FILE_FOLDER_OPENING,
     ("path", "reason")),
    ("windows/recyclebin", "windows.recyclebin.deleted_item", ArtifactCategory.DELETED_FILE,
     ("path", "source")),
    ("windows/shellbag", "windows.shellbags.folder_access", ArtifactCategory.FILE_FOLDER_OPENING,
     ("path",)),
    ("windows/registry/userassist", "windows.registry.userassist", ArtifactCategory.PROGRAM_EXECUTION,
     ("path",)),
    ("windows/registry/run", "windows.registry.run_key", ArtifactCategory.PERSISTENCE,
     ("path", "name")),
    ("windows/activitiescache", "windows.timeline.activity", ArtifactCategory.FILE_FOLDER_OPENING,
     ("app_id", "content")),
    ("windows/jumplist", "windows.jumplist.auto_entry", ArtifactCategory.FILE_FOLDER_OPENING,
     ("target_path", "path")),
    ("browser/", "windows.browser.history", ArtifactCategory.BROWSER_USAGE, ("url", "title")),
    ("powershell/history", "windows.powershell.history", ArtifactCategory.PROGRAM_EXECUTION,
     ("command",)),
    ("filesystem/windows/task/action/exec", "windows.scheduled_task.definition",
     ArtifactCategory.PERSISTENCE, ("command", "task_name")),
    ("filesystem/windows/task", "windows.scheduled_task.definition", ArtifactCategory.PERSISTENCE,
     ("task_name", "uri")),
    ("windows/defender/mplog", "windows.defender.mplog", ArtifactCategory.MALWARE,
     ("threat", "detection", "process_image_name", "blocked_file")),
    ("application/webserver/log/access", "windows.iis.request", ArtifactCategory.NETWORK_ACTIVITY,
     ("uri", "remote_ip")),
    ("windows/ual/client_access", "windows.ual.client_access", ArtifactCategory.ACCOUNT_USAGE,
     ("authenticated_username", "address")),
    ("windows/ual/role_access", "windows.ual.role_access", ArtifactCategory.SYSTEM_INFO,
     ("role_name",)),
    ("windows/registry/recentfilecache", "windows.recentfilecache.entry",
     ArtifactCategory.PROGRAM_EXECUTION, ("path",)),
]

MFT_TS_TYPES = {"B": "Created", "M": "Modified", "C": "MFT Entry Changed", "A": "Accessed"}


class DissectNormalizer(BaseNormalizer):
    """Dissect records → DEFAIR artifacts."""

    @property
    def tool_name(self) -> str:
        return "dissect_plugin"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        return self._normalize(row, {}, **ctx)

    def normalize_file(self, file_path: str | Path, **context) -> list[dict[str, Any]]:
        path = Path(file_path)
        if not path.exists():
            return []
        descriptors: dict[str, list[str]] = {}
        artifacts = []
        with path.open(encoding="utf-8", errors="replace") as fh:
            for index, line in enumerate(fh):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    self.stats["errors"] += 1
                    continue
                if record.get("_type") == "recorddescriptor":
                    name, fields = record["_data"]
                    descriptors[name] = [f[1] for f in fields if f[0] == "datetime"]
                    continue
                self.stats["rows_read"] += 1
                art = self._normalize(record, descriptors, **context)
                if art is None:
                    self.stats["skipped"] += 1
                    continue
                art["record_key"] = f"{path.name}#{index}"
                artifacts.append(art)
        return artifacts

    def _normalize(self, record: dict, descriptors: dict, **ctx) -> dict[str, Any] | None:
        rtype = (record.get("_recorddescriptor") or ["unknown"])[0]
        data = {k: v for k, v in record.items() if not k.startswith("_")}
        artifact_type, category, desc_fields = f"windows.dissect.{rtype.replace('/', '.')}", \
            ArtifactCategory.OTHER, ("path",)
        for prefix, a_type, cat, fields in TYPE_MAP:
            if rtype.startswith(prefix):
                artifact_type, category, desc_fields = a_type, cat, fields
                break

        dt_fields = descriptors.get(rtype) or [k for k in data if k == "ts" or k.startswith("ts_")]
        ts_field = "ts" if "ts" in data else next((f for f in dt_fields if data.get(f)), None)
        timestamp = data.get(ts_field) if ts_field else None
        timestamp_desc = None
        if rtype.startswith("filesystem/ntfs/mft") and data.get("ts_type"):
            timestamp_desc = f"{MFT_TS_TYPES.get(data['ts_type'], data['ts_type'])} (MFT)"
        elif ts_field and ts_field != "ts":
            timestamp_desc = ts_field.replace("ts_", "").replace("_", " ").capitalize()

        tags: list[str] = []
        if rtype.startswith("filesystem/windows/evtx"):
            from defair.normalizers.eztools import classify_evtx

            info = classify_evtx(data.get("EventID"), data.get("Channel"))
            artifact_type, category = info["artifact_type"], info["category"]
            tags = [f"mitre:{t}" for t in info["mitre"]]
            description = info["catalog_description"] or f"EventID {data.get('EventID')}"
            # same keys as EvtxECmd / evtx_native (provenance, EVTX views)
            data.setdefault("event_id", str(data.get("EventID", "")))
            data.setdefault("channel", data.get("Channel", ""))
        else:
            description = next((str(data[f]) for f in desc_fields if data.get(f)), rtype)

        return {
            "artifact_type": artifact_type,
            "category": category,
            "source_tool": "dissect_plugin",
            "source_file": str(data.get("source") or record.get("_source") or ""),
            "timestamp": timestamp,
            "timestamp_desc": timestamp_desc,
            "hostname": data.get("hostname") or data.get("Computer"),
            "username": data.get("username") or data.get("user"),
            "description": description,
            "tags": tags,
            "data": {"record_type": rtype, **data},
            **ctx,
        }
