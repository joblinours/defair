"""BaseNormalizer — abstract base for converting tool output to artifacts.

Each tool normalizer takes raw CSV/JSON output and converts it to
a list of normalized Artifact objects with consistent fields.
"""

from __future__ import annotations

import csv
import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import structlog

# Re-exported: normalizers import parse_timestamp from base
from defair.normalizers.timestamps import parse_timestamp

log = structlog.get_logger(component="normalizer")


class BaseNormalizer(ABC):
    """Abstract base for tool output normalizers.

    Subclasses implement normalize_row() to convert a single parsed row
    from a tool's output into an Artifact dict (without id/number, which
    are assigned by the service layer).
    """

    #: what the tool processed (set by the pipeline) — lets normalizers
    #: resolve reported paths to real files
    input_path: str | None = None
    #: name of the output file being normalized (lets a normalizer tell
    #: apart the several CSVs one tool writes)
    current_file: str = ""

    @property
    def stats(self) -> dict:
        """Per-normalizer counters: rows read, skipped (filtered), errors."""
        if "_stats" not in self.__dict__:
            self.__dict__["_stats"] = {"rows_read": 0, "skipped": 0, "errors": 0}
        return self.__dict__["_stats"]

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """The tool this normalizer handles (matches ToolManifest.name)."""

    @abstractmethod
    def normalize_row(self, row: dict[str, Any], **context) -> dict[str, Any] | None:
        """Convert a single output row to normalized artifact fields.

        Args:
            row: A single row from the tool's CSV/JSON output.
            **context: Extra context (case_id, evidence_id, run_id, etc.)

        Returns:
            Dict with artifact fields, or None to skip this row.
        """

    def normalize_file(
        self,
        file_path: str | Path,
        **context,
    ) -> list[dict[str, Any]]:
        """Normalize all rows from a tool output file.

        Supports CSV and JSON/JSONL files.

        Args:
            file_path: Path to the output file.
            **context: Extra context passed to normalize_row.

        Returns:
            List of normalized artifact dicts.
        """
        path = Path(file_path)
        if not path.exists():
            log.warning("normalizer_file_not_found", file=str(path))
            return []

        self.current_file = path.name
        rows = self._read_file(path)
        artifacts = []
        stats = self.stats

        for index, row in enumerate(rows):
            stats["rows_read"] += 1
            try:
                result = self.normalize_row(row, **context)
            except Exception as e:
                stats["errors"] += 1
                stats.setdefault("error_reasons", {})
                reason = f"{type(e).__name__}: {e}"[:200]
                stats["error_reasons"][reason] = stats["error_reasons"].get(reason, 0) + 1
                log.warning(
                    "normalizer_row_error",
                    tool=self.tool_name,
                    error=str(e),
                    row_preview=str(row)[:200],
                )
                continue
            if result is None:
                stats["skipped"] += 1
                continue
            # Stable key: re-normalizing the same output yields the same key
            result.setdefault("record_key", f"{path.name}#{index}")
            artifacts.append(result)

        log.info(
            "normalizer_completed",
            tool=self.tool_name,
            file=path.name,
            total_rows=len(rows),
            artifacts_produced=len(artifacts),
        )

        return artifacts

    def normalize_directory(
        self,
        output_dir: str | Path,
        **context,
    ) -> list[dict[str, Any]]:
        """Normalize all supported files in an output directory.

        Args:
            output_dir: Directory containing tool outputs.
            **context: Extra context.

        Returns:
            All normalized artifacts from all files.
        """
        dirpath = Path(output_dir)
        if not dirpath.exists():
            return []

        all_artifacts = []
        for f in sorted(dirpath.iterdir()):
            if f.suffix.lower() in (".csv", ".json", ".jsonl"):
                all_artifacts.extend(self.normalize_file(f, **context))

        return all_artifacts

    def _read_file(self, path: Path) -> list[dict[str, Any]]:
        """Read a CSV or JSON file into a list of dicts."""
        suffix = path.suffix.lower()

        if suffix == ".csv":
            return self._read_csv(path)
        if suffix == ".json":
            return self._read_json(path)
        if suffix == ".jsonl":
            return self._read_jsonl(path)

        log.warning("normalizer_unsupported_format", file=path.name, suffix=suffix)
        return []

    def _read_csv(self, path: Path) -> list[dict[str, Any]]:
        """Read a CSV file into list of dicts."""
        rows = []
        try:
            with path.open(encoding="utf-8-sig", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    rows.append(dict(row))
        except Exception as e:
            log.error("normalizer_csv_error", file=path.name, error=str(e))
        return rows

    def _read_json(self, path: Path) -> list[dict[str, Any]]:
        """Read a JSON file (array or single object)."""
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return [data]
        except Exception as e:
            log.error("normalizer_json_error", file=path.name, error=str(e))
        return []

    def _read_jsonl(self, path: Path) -> list[dict[str, Any]]:
        """Read a JSONL file (one JSON object per line)."""
        rows = []
        try:
            for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        except Exception as e:
            log.error("normalizer_jsonl_error", file=path.name, error=str(e))
        return rows


__all__ = ["BaseNormalizer", "parse_timestamp"]
