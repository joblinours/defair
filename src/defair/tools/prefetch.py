"""PrefetchTool — cross-platform Windows Prefetch parser.

Replaces PECmd (which requires Windows APIs) with the pure-Python
`windowsprefetch` library. Runs natively on Linux containers.

Covers SANS FOR500 categories:
- Program Execution (which programs ran, when, how often)
- File/Folder Opening (files/dirs referenced by executed programs)

Prefetch files (.pf) record:
- Executable name and path
- Run count and last 8 run times
- Files and directories referenced during first 10 seconds
- Volume information
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

log = structlog.get_logger(component="tools.prefetch")


class PrefetchTool(BaseTool):
    """Pure-Python Prefetch parser using windowsprefetch library.

    Unlike PECmd which requires Windows APIs, this runs natively
    on Linux. Produces CSV output compatible with the normalizer.
    """

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="prefetch",
            display_name="Prefetch Parser",
            vendor="DEFAIR (windowsprefetch)",
            description=(
                "Cross-platform Windows Prefetch parser. Extracts execution "
                "history, run counts, timestamps, and referenced files/directories."
            ),
            category=ToolCategory.EXECUTION,
            command="python-native",
            runtime="python",
            timeout=1800,
            capabilities=["prefetch", "execution_history", "run_count", "referenced_files"],
            input_types=["pf"],
            output_formats=["csv"],
            artifact_types=[
                "windows.prefetch.execution",
                "windows.prefetch.referenced_file",
                "windows.prefetch.volume",
            ],
            sans_categories=["program_execution", "file_folder_opening"],
        )

    def build_command(self, input_path: str, output_dir: str, **kwargs) -> list[str]:
        # Not used — run() is overridden. Kept for BaseTool contract.
        return ["python-native", "prefetch", input_path, output_dir]

    def is_available(self) -> bool:
        """Always available — pure Python, no external binary."""
        try:
            import windowsprefetch  # noqa: F401

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
        """Parse Prefetch files using windowsprefetch library.

        Supports a single .pf file or a directory of .pf files.
        Writes results to a CSV in output_dir.
        """
        m = self.manifest()
        effective_timeout = timeout or m.timeout

        tool_run = ToolRun(
            run_number=run_number,
            case_id=case_id,
            evidence_id=evidence_id,
            tool_name=m.name,
            tool_version=self.get_version(),
            command=f"prefetch-parser {input_path}",
            parameters=kwargs,
            status=ToolRunStatus.RUNNING,
            started_at=datetime.now(UTC),
        )

        log.info("tool_run_started", tool=m.name, run_number=run_number, input=input_path)

        # Ensure output directory is clean
        out = Path(output_dir)
        if out.exists():
            import shutil

            shutil.rmtree(out)
        out.mkdir(parents=True, exist_ok=True)

        start = time.monotonic()
        try:
            # Run parsing in a thread to not block the event loop
            rows = await asyncio.wait_for(
                asyncio.to_thread(self._parse_prefetch_files, input_path),
                timeout=effective_timeout,
            )

            # Write CSV output
            csv_path = out / "prefetch_results.csv"
            self._write_csv(rows, csv_path)

            tool_run.exit_code = 0
            tool_run.status = ToolRunStatus.COMPLETED
            tool_run.stdout = f"Parsed {len(rows)} prefetch file(s)"

        except TimeoutError:
            tool_run.status = ToolRunStatus.TIMEOUT
            tool_run.stderr = f"Timed out after {effective_timeout}s"
            log.warning("tool_run_timeout", tool=m.name, timeout=effective_timeout)

        except Exception as e:
            tool_run.status = ToolRunStatus.FAILED
            tool_run.stderr = str(e)
            tool_run.exit_code = 1
            log.error("tool_run_error", tool=m.name, error=str(e))

        # Finalize
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
            parsed=len(rows) if tool_run.status == ToolRunStatus.COMPLETED else 0,
        )

        return tool_run

    def _parse_prefetch_files(self, input_path: str) -> list[dict]:
        """Parse one or more .pf files, returning dicts for CSV output."""
        import windowsprefetch

        path = Path(input_path)
        pf_files = []

        if path.is_file() and path.suffix.lower() == ".pf":
            pf_files = [path]
        elif path.is_dir():
            pf_files = sorted(path.rglob("*.pf"))
        else:
            raise ValueError(f"Input is not a .pf file or directory: {input_path}")

        if not pf_files:
            log.warning("no_prefetch_files", path=input_path)
            return []

        rows = []
        for pf_path in pf_files:
            try:
                pf = windowsprefetch.Prefetch(str(pf_path))
                row = self._extract_row(pf, pf_path)
                rows.append(row)
            except Exception as e:
                log.warning("prefetch_parse_error", file=str(pf_path), error=str(e))

        return rows

    @staticmethod
    def _extract_row(pf, pf_path: Path) -> dict:
        """Extract a flat dict from a parsed Prefetch object."""
        # Timestamps — Hayabusa-style list, first is most recent
        timestamps = getattr(pf, "timestamps", [])
        last_run = timestamps[0] if timestamps else ""
        previous_runs = timestamps[1:8] if len(timestamps) > 1 else []

        # Resources loaded (files referenced during execution)
        resources = getattr(pf, "resources", [])
        resources_str = "; ".join(resources) if resources else ""

        # Directory strings
        dir_strings = []
        for volume in getattr(pf, "directoryStringsArray", []):
            if isinstance(volume, (list, tuple)):
                dir_strings.extend(volume)
            else:
                dir_strings.append(str(volume))
        dirs_str = "; ".join(dir_strings)

        # Volume info
        vol_info = getattr(pf, "volumesInformationArray", [])
        vol0_name = ""
        vol0_serial = ""
        vol0_created = ""
        if vol_info:
            v = vol_info[0]
            vol0_name_raw = v.get("Volume Name", b"")
            vol0_name = (
                vol0_name_raw.decode("UTF-16", errors="backslashreplace")
                if isinstance(vol0_name_raw, bytes)
                else str(vol0_name_raw)
            )
            vol0_serial = v.get("Serial Number", "")
            vol0_created = v.get("Creation Date", "")

        return {
            "SourceFilename": str(pf_path),
            "ExecutableName": getattr(pf, "executableName", ""),
            "Hash": getattr(pf, "hash", ""),
            "RunCount": str(getattr(pf, "runCount", 0)),
            "LastRun": last_run,
            "PreviousRun0": previous_runs[0] if len(previous_runs) > 0 else "",
            "PreviousRun1": previous_runs[1] if len(previous_runs) > 1 else "",
            "PreviousRun2": previous_runs[2] if len(previous_runs) > 2 else "",
            "PreviousRun3": previous_runs[3] if len(previous_runs) > 3 else "",
            "PreviousRun4": previous_runs[4] if len(previous_runs) > 4 else "",
            "PreviousRun5": previous_runs[5] if len(previous_runs) > 5 else "",
            "PreviousRun6": previous_runs[6] if len(previous_runs) > 6 else "",
            "Volume0Name": vol0_name,
            "Volume0Serial": vol0_serial,
            "Volume0Created": vol0_created,
            "Directories": dirs_str,
            "FilesLoaded": resources_str,
        }

    @staticmethod
    def _write_csv(rows: list[dict], csv_path: Path) -> None:
        """Write parsed rows to CSV."""
        if not rows:
            return

        fieldnames = [
            "SourceFilename", "ExecutableName", "Hash", "RunCount",
            "LastRun", "PreviousRun0", "PreviousRun1", "PreviousRun2",
            "PreviousRun3", "PreviousRun4", "PreviousRun5", "PreviousRun6",
            "Volume0Name", "Volume0Serial", "Volume0Created",
            "Directories", "FilesLoaded",
        ]
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
