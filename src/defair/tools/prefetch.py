"""PrefetchTool — cross-platform Windows Prefetch parser.

Uses libscca (via pyscca) which handles all Prefetch format versions
including Win10+ MAM-compressed files natively on Linux.

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
    """Cross-platform Prefetch parser using libscca (pyscca).

    Unlike PECmd (Windows-only .NET) and windowsprefetch (uses ctypes.windll
    for Win10+ MAM decompression), libscca is a C library that handles all
    Prefetch format versions natively on Linux.
    """

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="prefetch",
            display_name="Prefetch Parser",
            allowed_options=[],
            vendor="DEFAIR (libscca)",
            description=(
                "Cross-platform Windows Prefetch parser. Extracts execution "
                "history, run counts, timestamps, and referenced files/directories. "
                "Supports all format versions including Win10+ (MAM compression)."
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
        """Available if pyscca (libscca-python) is importable."""
        try:
            import pyscca  # noqa: F401

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
        """Parse Prefetch files using libscca.

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
        rows = []
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
            parsed=len(rows),
        )

        return tool_run

    def _parse_prefetch_files(self, input_path: str) -> list[dict]:
        """Parse one or more .pf files using libscca, returning dicts for CSV output."""
        import pyscca

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
                scca_file = pyscca.file()
                scca_file.open(str(pf_path))
                try:
                    row = self._extract_row(scca_file, pf_path)
                    rows.append(row)
                finally:
                    scca_file.close()
            except Exception as e:
                log.warning("prefetch_parse_error", file=str(pf_path), error=str(e))

        return rows

    @staticmethod
    def _extract_row(scca_file, pf_path: Path) -> dict:
        """Extract a flat dict from a pyscca file object."""
        # Executable name
        exe_name = scca_file.get_executable_filename() or ""

        # Prefetch hash
        pf_hash = ""
        try:
            pf_hash = f"{scca_file.get_prefetch_hash():08X}"
        except Exception:
            log.debug("prefetch_hash_unavailable", file=str(pf_path))

        # Run count
        run_count = scca_file.get_run_count()

        # Timestamps — up to 8 last run times
        timestamps = []
        for i in range(8):
            try:
                ts = scca_file.get_last_run_time(i)
                if ts and ts.year > 1601:  # Filter out null FILETIME (1601-01-01)
                    timestamps.append(ts.strftime("%Y-%m-%d %H:%M:%S"))
            except Exception:
                break

        last_run = timestamps[0] if timestamps else ""
        previous_runs = timestamps[1:] if len(timestamps) > 1 else []

        # Referenced files (filenames / resources loaded)
        filenames = []
        try:
            for i in range(scca_file.get_number_of_filenames()):
                fn = scca_file.get_filename(i)
                if fn:
                    filenames.append(fn)
        except Exception:
            log.debug("prefetch_filenames_error", file=str(pf_path))
        resources_str = "; ".join(filenames) if filenames else ""

        # Directories from filenames (extract unique directory parts)
        dirs = set()
        for fn in filenames:
            parts = fn.rsplit("\\", 1)
            if len(parts) > 1:
                dirs.add(parts[0])
        dirs_str = "; ".join(sorted(dirs))

        # Volume info
        vol0_name = ""
        vol0_serial = ""
        vol0_created = ""
        try:
            if scca_file.get_number_of_volumes() > 0:
                vol = scca_file.get_volume_information(0)
                vol0_name = getattr(vol, "device_path", "") or ""
                vol0_serial = ""
                vol0_created = ""
                try:
                    vol0_serial = f"{vol.serial_number:08X}" if vol.serial_number else ""
                except Exception:
                    log.debug("prefetch_vol_serial_error", file=str(pf_path))
                try:
                    if vol.creation_time and vol.creation_time.year > 1601:
                        vol0_created = vol.creation_time.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    log.debug("prefetch_vol_time_error", file=str(pf_path))
        except Exception:
            log.debug("prefetch_volume_error", file=str(pf_path))

        return {
            "SourceFilename": str(pf_path),
            "ExecutableName": exe_name,
            "Hash": pf_hash,
            "RunCount": str(run_count),
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
