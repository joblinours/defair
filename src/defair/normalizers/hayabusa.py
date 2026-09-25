"""Hayabusa normalizer — convert Hayabusa CSV detections to artifacts.

Hayabusa CSV columns (standard profile):
  Timestamp, RuleTitle, Level, Computer, Channel, EventID,
  RecordID, Details, ExtraFieldInfo, MitreTactics, MitreTags,
  OtherTags, RuleFile, EvtxFile

Maps each detection to an artifact with severity and MITRE ATT&CK data.
"""

from __future__ import annotations

from typing import Any

from defair.models.artifact import ArtifactCategory
from defair.normalizers.base import BaseNormalizer, parse_timestamp

LEVEL_ALIASES = {
    "crit": "critical",
    "emer": "critical",
    "med": "medium",
    "info": "informational",
    "inf": "informational",
}


class HayabusaNormalizer(BaseNormalizer):
    """Normalize Hayabusa CSV output into detection artifacts."""

    @property
    def tool_name(self) -> str:
        return "hayabusa"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        level = (row.get("Level") or "").strip().lower()
        if not level:
            return None
        # Hayabusa 4.x output profiles abbreviate levels
        level = LEVEL_ALIASES.get(level, level)

        artifact_type = self._classify_detection(level)
        severity = self._map_severity(level)

        # Parse MITRE fields
        mitre_tactics = row.get("MitreTactics", "")
        mitre_tags = row.get("MitreTags", "")

        return {
            "artifact_type": artifact_type,
            "category": self._categorize_detection(level),
            "source_tool": "hayabusa",
            "source_file": row.get("EvtxFile", row.get("RuleFile", "")),
            "timestamp": parse_timestamp(row.get("Timestamp")),
            "hostname": row.get("Computer"),
            "description": row.get("RuleTitle", ""),
            "severity": severity,
            "data": {
                "rule_title": row.get("RuleTitle", ""),
                "level": level,
                "channel": row.get("Channel", ""),
                "event_id": row.get("EventID", ""),
                "record_id": row.get("RecordID", ""),
                "details": row.get("Details", ""),
                "extra_field_info": row.get("ExtraFieldInfo", ""),
                "mitre_tactics": mitre_tactics,
                "mitre_tags": mitre_tags,
                "other_tags": row.get("OtherTags", ""),
                "rule_file": row.get("RuleFile", ""),
                "evtx_file": row.get("EvtxFile", ""),
            },
            **ctx,
        }

    def _classify_detection(self, level: str) -> str:
        """High/critical → alert, rest → detection."""
        if level in ("critical", "high"):
            return "windows.hayabusa.alert"
        return "windows.hayabusa.detection"

    def _map_severity(self, level: str) -> str:
        """Map Hayabusa level to DEFAIR severity."""
        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "informational",
            "info": "informational",
        }
        return mapping.get(level, "informational")

    def _categorize_detection(self, level: str) -> ArtifactCategory:
        """High-severity detections → persistence, rest → other."""
        if level in ("critical", "high"):
            return ArtifactCategory.PERSISTENCE
        return ArtifactCategory.OTHER
