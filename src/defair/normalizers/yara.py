"""Normalizer for YARA scanner output."""

from __future__ import annotations

from typing import Any

from defair.models.artifact import ArtifactCategory
from defair.normalizers.base import BaseNormalizer


class YaraNormalizer(BaseNormalizer):
    """Normalize YARA scanner CSV output into DEFAIR artifacts."""

    @property
    def tool_name(self) -> str:
        return "yara"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        severity = self._map_severity(row.get("Severity", "medium"))
        rule_name = row.get("RuleName", "")
        file_path = row.get("FilePath", "")
        file_name = row.get("FileName", "")
        description = row.get("Description", "")

        if not description:
            description = f"YARA match: {rule_name} on {file_name}"

        return {
            "artifact_type": "detection.yara.match",
            "category": ArtifactCategory.MALWARE,
            "source_tool": "yara",
            "source_file": file_path,
            "timestamp": row.get("Timestamp"),
            "description": description,
            "severity": severity,
            "data": {
                "rule_name": rule_name,
                "namespace": row.get("Namespace", ""),
                "tags": row.get("Tags", ""),
                "file_path": file_path,
                "file_name": file_name,
                "author": row.get("Author", ""),
                "reference": row.get("Reference", ""),
                "matched_strings": row.get("MatchedStrings", ""),
                "match_count": row.get("MatchCount", "0"),
            },
            **ctx,
        }

    @staticmethod
    def _map_severity(level: str) -> str:
        """Map YARA rule severity to DEFAIR severity."""
        level = level.strip().lower()
        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "informational",
            "informational": "informational",
        }
        return mapping.get(level, "medium")
