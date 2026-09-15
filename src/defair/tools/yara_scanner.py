"""YaraTool — YARA rule-based file scanner.

Scans files and directories against YARA rules to detect malware,
suspicious patterns, and indicators of compromise.

Supports:
- Scanning single files or entire directories recursively
- Built-in rules from /opt/yara/rules/ (community rules)
- Custom rules mounted at /rules/yara/
- Multiple rule files compiled together
- Timeout per file to avoid hanging on large binaries
"""

from __future__ import annotations

import asyncio
import csv
import time
from datetime import UTC, datetime
from pathlib import Path

import structlog

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.models.tool_run import ToolRun, ToolRunStatus
from defair.tools.base import BaseTool

log = structlog.get_logger(component="tools.yara")

# Default rule directories (checked in order, all loaded)
DEFAULT_RULE_DIRS = [
    "/opt/yara/rules",    # Built-in community rules
    "/rules/yara",        # User-mounted custom rules
]


class YaraTool(BaseTool):
    """YARA rule scanner using yara-python.

    Scans files against compiled YARA rules and produces CSV output
    with match details including rule name, tags, metadata, and strings.
    """

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="yara",
            display_name="YARA Scanner",
            vendor="DEFAIR (yara-python)",
            description=(
                "YARA rule-based file scanner. Detects malware, suspicious "
                "patterns, and IOCs using community and custom rule sets."
            ),
            category=ToolCategory.DETECTION,
            command="python-native",
            runtime="python",
            timeout=3600,
            capabilities=["yara", "malware_detection", "ioc_scanning", "pattern_matching"],
            input_types=["*"],
            output_formats=["csv"],
            artifact_types=[
                "detection.yara.match",
            ],
            sans_categories=["program_execution", "malware"],
        )

    def build_command(self, input_path: str, output_dir: str, **kwargs) -> list[str]:
        return ["python-native", "yara", input_path, output_dir]

    def is_available(self) -> bool:
        """Available if yara-python is importable."""
        try:
            import yara  # noqa: F401

            return True
        except ImportError:
            return False

    async def run(
        self,
        input_path: str,
        output_dir: str,
        case_id: str,
        evidence_id: str | None = None,
        run_number: str = "RUN-000",
        timeout: int | None = None,
        **kwargs,
    ) -> ToolRun:
        """Scan files against YARA rules.

        Args:
            input_path: File or directory to scan.
            output_dir: Where to write results CSV.
            case_id: Case ID.
            evidence_id: Optional evidence ID.
            run_number: Run number.
            timeout: Override timeout.
            **kwargs:
                rules_dir: Additional rules directory path.
                file_timeout: Per-file scan timeout in seconds (default 60).
                max_file_size: Skip files larger than this (bytes, default 100MB).
        """
        m = self.manifest()
        effective_timeout = timeout or m.timeout
        rules_dirs = list(DEFAULT_RULE_DIRS)
        if kwargs.get("rules_dir"):
            rules_dirs.append(kwargs["rules_dir"])

        tool_run = ToolRun(
            run_number=run_number,
            case_id=case_id,
            evidence_id=evidence_id,
            tool_name=m.name,
            tool_version=self.get_version(),
            command=f"yara-scan {input_path}",
            parameters=kwargs,
            status=ToolRunStatus.RUNNING,
            started_at=datetime.now(UTC),
        )

        log.info("tool_run_started", tool=m.name, run_number=run_number, input=input_path)

        out = Path(output_dir)
        if out.exists():
            import shutil

            shutil.rmtree(out)
        out.mkdir(parents=True, exist_ok=True)

        start = time.monotonic()
        try:
            matches = await asyncio.wait_for(
                asyncio.to_thread(
                    self._scan_files,
                    input_path,
                    rules_dirs,
                    file_timeout=kwargs.get("file_timeout", 60),
                    max_file_size=kwargs.get("max_file_size", 100 * 1024 * 1024),
                ),
                timeout=effective_timeout,
            )

            csv_path = out / "yara_results.csv"
            self._write_csv(matches, csv_path)

            tool_run.exit_code = 0
            tool_run.status = ToolRunStatus.COMPLETED
            tool_run.stdout = f"Scanned files, {len(matches)} YARA match(es) found"

        except TimeoutError:
            tool_run.status = ToolRunStatus.TIMEOUT
            tool_run.stderr = f"Timed out after {effective_timeout}s"
            log.warning("tool_run_timeout", tool=m.name, timeout=effective_timeout)

        except Exception as e:
            tool_run.status = ToolRunStatus.FAILED
            tool_run.stderr = str(e)
            tool_run.exit_code = 1
            log.error("tool_run_error", tool=m.name, error=str(e))

        elapsed = time.monotonic() - start
        tool_run.completed_at = datetime.now(UTC)
        tool_run.duration_seconds = round(elapsed, 3)
        tool_run.output_path = output_dir

        if out.exists():
            tool_run.output_files = [
                str(f.relative_to(out)) for f in out.rglob("*") if f.is_file()
            ]

        log.info(
            "tool_run_completed",
            tool=m.name,
            run_number=run_number,
            status=tool_run.status,
            duration=tool_run.duration_seconds,
            matches=len(matches) if tool_run.status == ToolRunStatus.COMPLETED else 0,
        )

        return tool_run

    def _scan_files(
        self,
        input_path: str,
        rules_dirs: list[str],
        file_timeout: int = 60,
        max_file_size: int = 100 * 1024 * 1024,
    ) -> list[dict]:
        """Compile rules and scan files."""
        import yara

        # Collect all .yar/.yara rule files
        rule_files = self._collect_rule_files(rules_dirs)
        if not rule_files:
            log.warning("no_yara_rules_found", dirs=rules_dirs)
            return []

        # Compile rules — use filepaths dict for yara.compile
        filepaths = {}
        for i, rf in enumerate(rule_files):
            # Use a namespace based on the rule file to avoid conflicts
            ns = rf.stem.replace("-", "_").replace(" ", "_")
            # Handle duplicate namespaces
            key = f"{ns}_{i}" if ns in filepaths else ns
            filepaths[key] = str(rf)

        try:
            rules = yara.compile(filepaths=filepaths)
        except yara.SyntaxError as e:
            log.error("yara_compile_error", error=str(e))
            # Try compiling rules one by one, skip broken ones
            rules = self._compile_rules_individually(rule_files)
            if rules is None:
                return []

        # Collect files to scan
        path = Path(input_path)
        files_to_scan = []
        if path.is_file():
            files_to_scan = [path]
        elif path.is_dir():
            files_to_scan = [f for f in path.rglob("*") if f.is_file()]
        else:
            raise ValueError(f"Input path does not exist: {input_path}")

        # Scan each file
        matches = []
        scanned = 0
        skipped = 0
        for filepath in files_to_scan:
            try:
                if filepath.stat().st_size > max_file_size:
                    skipped += 1
                    continue

                file_matches = rules.match(
                    str(filepath),
                    timeout=file_timeout,
                )
                scanned += 1

                for match in file_matches:
                    matches.append(self._match_to_dict(match, filepath))

            except yara.TimeoutError:
                log.warning("yara_file_timeout", file=str(filepath))
                skipped += 1
            except yara.Error as e:
                log.warning("yara_scan_error", file=str(filepath), error=str(e))
                skipped += 1

        log.info("yara_scan_complete", scanned=scanned, skipped=skipped, matches=len(matches))
        return matches

    @staticmethod
    def _collect_rule_files(rules_dirs: list[str]) -> list[Path]:
        """Collect all .yar and .yara files from rule directories."""
        rule_files = []
        for dir_path in rules_dirs:
            d = Path(dir_path)
            if d.is_dir():
                rule_files.extend(d.rglob("*.yar"))
                rule_files.extend(d.rglob("*.yara"))
        return sorted(set(rule_files))

    @staticmethod
    def _compile_rules_individually(rule_files: list[Path]):
        """Compile rules one by one, skipping broken ones."""
        import yara

        filepaths = {}
        for i, rf in enumerate(rule_files):
            ns = f"{rf.stem.replace('-', '_').replace(' ', '_')}_{i}"
            try:
                # Test compile individually first
                yara.compile(filepath=str(rf))
                filepaths[ns] = str(rf)
            except yara.SyntaxError:
                log.warning("yara_rule_skipped", file=str(rf))

        if not filepaths:
            return None

        return yara.compile(filepaths=filepaths)

    @staticmethod
    def _match_to_dict(match, filepath: Path) -> dict:
        """Convert a YARA match to a flat dict for CSV."""
        # Extract matched strings (limit to avoid huge rows)
        matched_strings = []
        for s in match.strings[:10]:
            for instance in s.instances[:3]:
                matched_strings.append(f"{s.identifier}@0x{instance.offset:x}")

        # Extract metadata
        meta = match.meta if hasattr(match, "meta") else {}

        return {
            "Timestamp": datetime.now(UTC).isoformat(),
            "FilePath": str(filepath),
            "FileName": filepath.name,
            "RuleName": match.rule,
            "Namespace": match.namespace,
            "Tags": ", ".join(match.tags) if match.tags else "",
            "Severity": meta.get("severity", meta.get("level", "medium")),
            "Description": meta.get("description", ""),
            "Author": meta.get("author", ""),
            "Reference": meta.get("reference", ""),
            "MatchedStrings": "; ".join(matched_strings),
            "MatchCount": str(len(match.strings)),
        }

    @staticmethod
    def _write_csv(matches: list[dict], csv_path: Path) -> None:
        """Write YARA matches to CSV."""
        if not matches:
            return

        fieldnames = [
            "Timestamp", "FilePath", "FileName", "RuleName", "Namespace",
            "Tags", "Severity", "Description", "Author", "Reference",
            "MatchedStrings", "MatchCount",
        ]
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(matches)
