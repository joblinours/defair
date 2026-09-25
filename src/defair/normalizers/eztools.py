"""EZ Tools normalizers — convert EZ Tools CSV/JSON output to normalized artifacts.

Each normalizer class handles one EZ Tool's output format and maps its
columns to the Artifact model fields. The normalizers know about the
specific column names and formats each tool produces.
"""

from __future__ import annotations

from typing import Any

from defair.models.artifact import ArtifactCategory
from defair.normalizers.base import BaseNormalizer, parse_timestamp


class MFTECmdNormalizer(BaseNormalizer):
    """Normalize MFTECmd CSV output."""

    @property
    def tool_name(self) -> str:
        return "mftecmd"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        return {
            "artifact_type": "windows.mft.file_entry",
            "category": ArtifactCategory.OTHER,
            "source_tool": "mftecmd",
            "source_file": row.get("SourceFile", ""),
            "timestamp": parse_timestamp(row.get("Created0x10")),
            "description": row.get("FileName", ""),
            "data": {
                "entry_number": row.get("EntryNumber"),
                "sequence_number": row.get("SequenceNumber"),
                "parent_entry": row.get("ParentEntryNumber"),
                "parent_path": row.get("ParentPath", ""),
                "filename": row.get("FileName", ""),
                "extension": row.get("Extension", ""),
                "file_size": row.get("FileSize"),
                "is_directory": row.get("IsDirectory"),
                # MACB timestamps (Standard Info $SI)
                "created_si": parse_timestamp(row.get("Created0x10")),
                "modified_si": parse_timestamp(row.get("LastModified0x10")),
                "accessed_si": parse_timestamp(row.get("LastAccess0x10")),
                "entry_modified_si": parse_timestamp(row.get("LastRecordChange0x10")),
                # MACB timestamps (Filename $FN)
                "created_fn": parse_timestamp(row.get("Created0x30")),
                "modified_fn": parse_timestamp(row.get("LastModified0x30")),
                "accessed_fn": parse_timestamp(row.get("LastAccess0x30")),
                "entry_modified_fn": parse_timestamp(row.get("LastRecordChange0x30")),
                "in_use": row.get("InUse"),
                "has_ads": row.get("HasAds"),
                "si_flags": row.get("SiFlags"),
                "reference_count": row.get("ReferenceCount"),
                "zone_id": row.get("ZoneIdContents"),
            },
            **ctx,
        }


class EvtxECmdNormalizer(BaseNormalizer):
    """Normalize EvtxECmd CSV output."""

    @property
    def tool_name(self) -> str:
        return "evtxecmd"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        event_id = row.get("EventId", "")
        channel = row.get("Channel", "")
        artifact_type = self._classify_event(event_id, channel)

        return {
            "artifact_type": artifact_type,
            "category": self._categorize_event(event_id, channel),
            "source_tool": "evtxecmd",
            "source_file": row.get("SourceFile", ""),
            "timestamp": parse_timestamp(row.get("TimeCreated")),
            "hostname": row.get("Computer"),
            "username": row.get("UserName"),
            "description": row.get("MapDescription", row.get("PayloadData1", "")),
            "data": {
                "event_id": event_id,
                "channel": channel,
                "provider": row.get("Provider", ""),
                "level": row.get("Level", ""),
                "keywords": row.get("Keywords", ""),
                "payload_data1": row.get("PayloadData1", ""),
                "payload_data2": row.get("PayloadData2", ""),
                "payload_data3": row.get("PayloadData3", ""),
                "payload_data4": row.get("PayloadData4", ""),
                "payload_data5": row.get("PayloadData5", ""),
                "payload_data6": row.get("PayloadData6", ""),
                "executable_info": row.get("ExecutableInfo", ""),
                "record_number": row.get("RecordNumber"),
                "hidden_record": row.get("HiddenRecord"),
            },
            **ctx,
        }

    def _classify_event(self, event_id: str, channel: str) -> str:
        """Map event ID to specific artifact type."""
        eid = str(event_id)
        mapping = {
            "4624": "windows.evtx.logon",
            "4625": "windows.evtx.logon_failed",
            "4634": "windows.evtx.logoff",
            "4648": "windows.evtx.explicit_logon",
            "4688": "windows.evtx.process_creation",
            "4697": "windows.evtx.service_install",
            "7045": "windows.evtx.service_install",
            "1": "windows.evtx.sysmon_process_create",
            "3": "windows.evtx.sysmon_network",
            "4104": "windows.evtx.powershell_scriptblock",
            "1102": "windows.evtx.audit_log_cleared",
            "1149": "windows.evtx.rdp_connection",
            "21": "windows.evtx.rdp_logon",
            "25": "windows.evtx.rdp_reconnect",
        }
        return mapping.get(eid, "windows.evtx.generic")

    def _categorize_event(self, event_id: str, channel: str) -> ArtifactCategory:
        """Map event to SANS category."""
        eid = str(event_id)
        if eid in ("4624", "4625", "4634", "4648", "1149", "21", "25"):
            return ArtifactCategory.ACCOUNT_USAGE
        if eid in ("4688", "1"):
            return ArtifactCategory.PROGRAM_EXECUTION
        if eid in ("4697", "7045"):
            return ArtifactCategory.PERSISTENCE
        if eid == "3":
            return ArtifactCategory.NETWORK_ACTIVITY
        if "Microsoft-Windows-DriverFrameworks" in channel:
            return ArtifactCategory.EXTERNAL_DEVICE
        return ArtifactCategory.OTHER


class PrefetchNormalizer(BaseNormalizer):
    """Normalize Prefetch parser CSV output (PECmd or windowsprefetch)."""

    @property
    def tool_name(self) -> str:
        return "prefetch"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        return {
            "artifact_type": "windows.prefetch.execution",
            "category": ArtifactCategory.PROGRAM_EXECUTION,
            "source_tool": "prefetch",
            "source_file": row.get("SourceFilename", ""),
            "timestamp": parse_timestamp(row.get("LastRun")),
            "description": f"Prefetch: {row.get('ExecutableName', '')}",
            "data": {
                "executable_name": row.get("ExecutableName", ""),
                "run_count": row.get("RunCount"),
                "hash": row.get("Hash", ""),
                "source_filename": row.get("SourceFilename", ""),
                "last_run": parse_timestamp(row.get("LastRun")),
                "previous_run0": parse_timestamp(row.get("PreviousRun0")),
                "previous_run1": parse_timestamp(row.get("PreviousRun1")),
                "previous_run2": parse_timestamp(row.get("PreviousRun2")),
                "previous_run3": parse_timestamp(row.get("PreviousRun3")),
                "previous_run4": parse_timestamp(row.get("PreviousRun4")),
                "previous_run5": parse_timestamp(row.get("PreviousRun5")),
                "previous_run6": parse_timestamp(row.get("PreviousRun6")),
                "volume0_name": row.get("Volume0Name", ""),
                "volume0_serial": row.get("Volume0Serial", ""),
                "directories": row.get("Directories", ""),
                "files_loaded": row.get("FilesLoaded", ""),
            },
            **ctx,
        }


class RECmdNormalizer(BaseNormalizer):
    """Normalize RECmd batch CSV output."""

    @property
    def tool_name(self) -> str:
        return "recmd"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        plugin = row.get("Description", row.get("Plugin", ""))
        hive_path = row.get("HivePath", "")

        return {
            "artifact_type": self._classify_registry(plugin, hive_path),
            "category": self._categorize_registry(plugin, hive_path),
            "source_tool": "recmd",
            "source_file": hive_path,
            "timestamp": parse_timestamp(row.get("LastWriteTimestamp")),
            "description": row.get("ValueData", row.get("Description", "")),
            "data": {
                "key_path": row.get("KeyPath", ""),
                "value_name": row.get("ValueName", ""),
                "value_data": row.get("ValueData", ""),
                "value_type": row.get("ValueType", ""),
                "batch_key_path": row.get("BatchKeyPath", ""),
                "batch_value_name": row.get("BatchValueName", ""),
                "batch_value_data": row.get("BatchValueData", ""),
                "plugin": plugin,
                "hive_path": hive_path,
                "recursive": row.get("Recursive"),
                "comment": row.get("Comment", ""),
            },
            **ctx,
        }

    def _classify_registry(self, plugin: str, hive: str) -> str:
        plugin_lower = plugin.lower()
        if "userassist" in plugin_lower:
            return "windows.registry.userassist"
        if "run" in plugin_lower and "key" in plugin_lower:
            return "windows.registry.run_key"
        if "mru" in plugin_lower:
            if "lastvisited" in plugin_lower:
                return "windows.registry.mru_lastvisited"
            return "windows.registry.mru_opensave"
        if "service" in plugin_lower:
            return "windows.registry.service"
        if "bam" in plugin_lower or "dam" in plugin_lower:
            return "windows.registry.bam_dam"
        if "usb" in plugin_lower or "usbstor" in plugin_lower:
            return "windows.registry.usb_device"
        if "network" in plugin_lower:
            return "windows.registry.network_profile"
        if "shellbag" in plugin_lower:
            return "windows.registry.shellbag"
        if "typedurl" in plugin_lower:
            return "windows.registry.typed_urls"
        if "wordwheel" in plugin_lower:
            return "windows.registry.wordwheelquery"
        if "mountpoint" in plugin_lower:
            return "windows.registry.mountpoint"
        if "timezone" in plugin_lower:
            return "windows.registry.timezone"
        return "windows.registry.generic"

    def _categorize_registry(self, plugin: str, hive: str) -> ArtifactCategory:
        plugin_lower = plugin.lower()
        if any(k in plugin_lower for k in ("userassist", "bam", "dam", "recent")):
            return ArtifactCategory.PROGRAM_EXECUTION
        if "mru" in plugin_lower:
            return ArtifactCategory.FILE_FOLDER_OPENING
        if any(k in plugin_lower for k in ("run", "service")):
            return ArtifactCategory.PERSISTENCE
        if any(k in plugin_lower for k in ("usb", "mountpoint")):
            return ArtifactCategory.EXTERNAL_DEVICE
        if "network" in plugin_lower:
            return ArtifactCategory.NETWORK_ACTIVITY
        if "typedurl" in plugin_lower:
            return ArtifactCategory.BROWSER_USAGE
        if "wordwheel" in plugin_lower:
            return ArtifactCategory.DELETED_FILE
        if any(k in plugin_lower for k in ("sam", "login", "profile")):
            return ArtifactCategory.ACCOUNT_USAGE
        return ArtifactCategory.OTHER


class AmcacheNormalizer(BaseNormalizer):
    """Normalize AmcacheParser CSV output."""

    @property
    def tool_name(self) -> str:
        return "amcacheparser"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        return {
            "artifact_type": "windows.amcache.program_entry",
            "category": ArtifactCategory.PROGRAM_EXECUTION,
            "source_tool": "amcacheparser",
            "source_file": "Amcache.hve",
            "timestamp": parse_timestamp(row.get("KeyLastWriteTimestamp", row.get("FileKeyLastWriteTimestamp"))),
            "description": f"Amcache: {row.get('ProgramName', row.get('FullPath', ''))}",
            "data": {
                "program_name": row.get("ProgramName", ""),
                "full_path": row.get("FullPath", ""),
                "sha1": row.get("SHA1", row.get("FileExtSHA1", "")),
                "publisher": row.get("Publisher", ""),
                "version": row.get("Version", row.get("ProductVersion", "")),
                "file_size": row.get("Size", row.get("FileSize")),
                "is_pe": row.get("IsPeFile"),
                "binary_type": row.get("BinaryType", ""),
                "product_name": row.get("ProductName", ""),
                "language": row.get("Language", ""),
                "link_date": parse_timestamp(row.get("LinkDate")),
            },
            **ctx,
        }


class AppCompatNormalizer(BaseNormalizer):
    """Normalize AppCompatCacheParser CSV output."""

    @property
    def tool_name(self) -> str:
        return "appcompatcacheparser"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        return {
            "artifact_type": "windows.shimcache.cache_entry",
            "category": ArtifactCategory.PROGRAM_EXECUTION,
            "source_tool": "appcompatcacheparser",
            "source_file": "SYSTEM",
            "timestamp": parse_timestamp(row.get("LastModifiedTimeUTC")),
            "description": f"Shimcache: {row.get('Path', '')}",
            "data": {
                "cache_entry_position": row.get("CacheEntryPosition"),
                "path": row.get("Path", ""),
                "last_modified": parse_timestamp(row.get("LastModifiedTimeUTC")),
                "executed": row.get("Executed", ""),
                "data_size": row.get("DataSize"),
                "duplicate": row.get("Duplicate"),
                "source_file": row.get("SourceFile", ""),
            },
            **ctx,
        }


class LECmdNormalizer(BaseNormalizer):
    """Normalize LECmd CSV output."""

    @property
    def tool_name(self) -> str:
        return "lecmd"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        return {
            "artifact_type": "windows.lnk.shortcut",
            "category": ArtifactCategory.FILE_FOLDER_OPENING,
            "source_tool": "lecmd",
            "source_file": row.get("SourceFile", ""),
            "timestamp": parse_timestamp(row.get("TargetCreated")),
            "description": f"LNK → {row.get('LocalPath', row.get('NetworkPath', ''))}",
            "data": {
                "source_file": row.get("SourceFile", ""),
                "source_created": parse_timestamp(row.get("SourceCreated")),
                "source_modified": parse_timestamp(row.get("SourceModified")),
                "source_accessed": parse_timestamp(row.get("SourceAccessed")),
                "target_created": parse_timestamp(row.get("TargetCreated")),
                "target_modified": parse_timestamp(row.get("TargetModified")),
                "target_accessed": parse_timestamp(row.get("TargetAccessed")),
                "local_path": row.get("LocalPath", ""),
                "network_path": row.get("NetworkPath", ""),
                "arguments": row.get("Arguments", ""),
                "working_directory": row.get("WorkingDirectory", ""),
                "relative_path": row.get("RelativePath", ""),
                "file_size": row.get("FileSize"),
                "drive_type": row.get("DriveType", ""),
                "volume_label": row.get("VolumeLabel", ""),
                "volume_serial": row.get("VolumeSerialNumber", ""),
                "machine_id": row.get("MachineId", ""),
                "mac_address": row.get("MacAddress", ""),
                "header_flags": row.get("HeaderFlags", ""),
                "file_attributes": row.get("FileAttributes", ""),
            },
            **ctx,
        }


class JLECmdNormalizer(BaseNormalizer):
    """Normalize JLECmd CSV output."""

    @property
    def tool_name(self) -> str:
        return "jlecmd"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        return {
            "artifact_type": "windows.jumplist.auto_entry",
            "category": ArtifactCategory.FILE_FOLDER_OPENING,
            "source_tool": "jlecmd",
            "source_file": row.get("SourceFile", ""),
            "timestamp": parse_timestamp(row.get("TargetCreated", row.get("InteractionCount"))),
            "description": f"JumpList: {row.get('LocalPath', row.get('Arguments', ''))}",
            "data": {
                "source_file": row.get("SourceFile", ""),
                "app_id": row.get("AppId", ""),
                "app_id_description": row.get("AppIdDescription", ""),
                "entry_name": row.get("EntryName", ""),
                "local_path": row.get("LocalPath", ""),
                "arguments": row.get("Arguments", ""),
                "target_created": parse_timestamp(row.get("TargetCreated")),
                "target_modified": parse_timestamp(row.get("TargetModified")),
                "target_accessed": parse_timestamp(row.get("TargetAccessed")),
                "file_size": row.get("FileSize"),
                "machine_id": row.get("MachineId", ""),
                "mac_address": row.get("MacAddress", ""),
                "interaction_count": row.get("InteractionCount"),
            },
            **ctx,
        }


class RBCmdNormalizer(BaseNormalizer):
    """Normalize RBCmd CSV output."""

    @property
    def tool_name(self) -> str:
        return "rbcmd"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        return {
            "artifact_type": "windows.recyclebin.deleted_item",
            "category": ArtifactCategory.DELETED_FILE,
            "source_tool": "rbcmd",
            "source_file": row.get("SourceName", ""),
            "timestamp": parse_timestamp(row.get("DeletedOn")),
            "description": f"Deleted: {row.get('FileName', '')}",
            "data": {
                "file_name": row.get("FileName", ""),
                "file_size": row.get("FileSize"),
                "deleted_on": parse_timestamp(row.get("DeletedOn")),
                "source_name": row.get("SourceName", ""),
                "user_sid": row.get("UserSid", ""),
            },
            **ctx,
        }


class SBECmdNormalizer(BaseNormalizer):
    """Normalize SBECmd CSV output."""

    @property
    def tool_name(self) -> str:
        return "sbecmd"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        return {
            "artifact_type": "windows.shellbags.folder_access",
            "category": ArtifactCategory.FILE_FOLDER_OPENING,
            "source_tool": "sbecmd",
            "source_file": row.get("SourceFile", ""),
            "timestamp": parse_timestamp(row.get("LastInteracted", row.get("LastWriteTime"))),
            "description": f"ShellBag: {row.get('AbsolutePath', '')}",
            "data": {
                "absolute_path": row.get("AbsolutePath", ""),
                "shell_type": row.get("ShellType", ""),
                "value": row.get("Value", ""),
                "created_on": parse_timestamp(row.get("CreatedOn")),
                "modified_on": parse_timestamp(row.get("ModifiedOn")),
                "accessed_on": parse_timestamp(row.get("AccessedOn")),
                "last_interacted": parse_timestamp(row.get("LastInteracted")),
                "last_write_time": parse_timestamp(row.get("LastWriteTime")),
                "mft_entry": row.get("MFTEntry"),
                "mft_sequence": row.get("MFTSequenceNumber"),
            },
            **ctx,
        }


class WxTCmdNormalizer(BaseNormalizer):
    """Normalize WxTCmd CSV output."""

    @property
    def tool_name(self) -> str:
        return "wxtcmd"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        return {
            "artifact_type": "windows.timeline.activity",
            "category": ArtifactCategory.PROGRAM_EXECUTION,
            "source_tool": "wxtcmd",
            "source_file": "ActivitiesCache.db",
            "timestamp": parse_timestamp(row.get("StartTime", row.get("LastModifiedTime"))),
            "end_timestamp": parse_timestamp(row.get("EndTime")),
            "description": f"Timeline: {row.get('Executable', row.get('DisplayText', ''))}",
            "data": {
                "executable": row.get("Executable", ""),
                "display_text": row.get("DisplayText", ""),
                "content_uri": row.get("ContentUri", ""),
                "app_activity_id": row.get("AppActivityId", ""),
                "activity_type": row.get("ActivityType", ""),
                "start_time": parse_timestamp(row.get("StartTime")),
                "end_time": parse_timestamp(row.get("EndTime")),
                "last_modified_time": parse_timestamp(row.get("LastModifiedTime")),
                "expiration_time": parse_timestamp(row.get("ExpirationTime")),
                "created_in_cloud": parse_timestamp(row.get("CreatedInCloud")),
                "duration": row.get("Duration"),
                "platform": row.get("Platform", ""),
                "device_id": row.get("DeviceId", ""),
            },
            **ctx,
        }


class SQLECmdNormalizer(BaseNormalizer):
    """Normalize SQLECmd CSV output."""

    @property
    def tool_name(self) -> str:
        return "sqlecmd"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        map_name = row.get("Map", row.get("MapName", ""))
        return {
            "artifact_type": self._classify_sqlite(map_name),
            "category": self._categorize_sqlite(map_name),
            "source_tool": "sqlecmd",
            "source_file": row.get("SourceFile", ""),
            "timestamp": parse_timestamp(row.get("Timestamp", row.get("LastVisitTime"))),
            "description": row.get("URL", row.get("Title", row.get("Value", ""))),
            "data": dict(row),  # Preserve all columns
            **ctx,
        }

    def _classify_sqlite(self, map_name: str) -> str:
        ml = map_name.lower()
        if "history" in ml:
            return "windows.browser.history"
        if "download" in ml:
            return "windows.browser.download"
        if "cookie" in ml:
            return "windows.browser.cookie"
        if "autofill" in ml:
            return "windows.browser.autofill"
        if "login" in ml:
            return "windows.browser.login"
        return "windows.sqlite.generic"

    def _categorize_sqlite(self, map_name: str) -> ArtifactCategory:
        ml = map_name.lower()
        if any(k in ml for k in ("history", "cookie", "autofill", "login", "session")):
            return ArtifactCategory.BROWSER_USAGE
        if "download" in ml:
            return ArtifactCategory.FILE_DOWNLOAD
        return ArtifactCategory.OTHER


class SrumECmdNormalizer(BaseNormalizer):
    """Normalize SrumECmd CSV output."""

    @property
    def tool_name(self) -> str:
        return "srumecmd"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        return {
            "artifact_type": "windows.srum.network_usage",
            "category": ArtifactCategory.NETWORK_ACTIVITY,
            "source_tool": "srumecmd",
            "source_file": "SRUDB.dat",
            "timestamp": parse_timestamp(row.get("Timestamp")),
            "username": row.get("UserName", row.get("UserId")),
            "description": f"SRUM: {row.get('ExeInfo', row.get('AppId', ''))}",
            "data": {
                "exe_info": row.get("ExeInfo", ""),
                "app_id": row.get("AppId", ""),
                "user_sid": row.get("UserId", ""),
                "user_name": row.get("UserName", ""),
                "bytes_sent": row.get("BytesSent"),
                "bytes_received": row.get("BytesRecvd"),
                "interface_luid": row.get("InterfaceLuid", ""),
                "profile_id": row.get("ProfileId"),
                "l2_profile_flags": row.get("L2ProfileFlags"),
            },
            **ctx,
        }


# Registry of all normalizers by tool name
NORMALIZER_MAP: dict[str, type[BaseNormalizer]] = {
    "mftecmd": MFTECmdNormalizer,
    "evtxecmd": EvtxECmdNormalizer,
    "prefetch": PrefetchNormalizer,
    "recmd": RECmdNormalizer,
    "amcacheparser": AmcacheNormalizer,
    "appcompatcacheparser": AppCompatNormalizer,
    "lecmd": LECmdNormalizer,
    "jlecmd": JLECmdNormalizer,
    "rbcmd": RBCmdNormalizer,
    "sbecmd": SBECmdNormalizer,
    "wxtcmd": WxTCmdNormalizer,
    "sqlecmd": SQLECmdNormalizer,
    "srumecmd": SrumECmdNormalizer,
}

# Register Hayabusa normalizer (detection tool, separate module)
from defair.normalizers.hayabusa import HayabusaNormalizer

NORMALIZER_MAP["hayabusa"] = HayabusaNormalizer

# Register Raijin normalizer (YARA + Sigma detections, separate module)
from defair.normalizers.raijin import RaijinNormalizer

NORMALIZER_MAP["raijin"] = RaijinNormalizer


def get_normalizer(tool_name: str) -> BaseNormalizer | None:
    """Get a normalizer instance for a tool."""
    cls = NORMALIZER_MAP.get(tool_name)
    if cls is None:
        return None
    return cls()
