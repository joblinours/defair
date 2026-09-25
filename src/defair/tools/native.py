"""Pure-Python parsers used as fallbacks when an external tool fails.

A native tool parses in-process (in a worker thread), writes one JSON object
per record to ``results.jsonl`` and is tracked as a regular ToolRun.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import structlog

from defair.models.tool_run import ToolRun, ToolRunStatus
from defair.tools.base import BaseTool

log = structlog.get_logger(component="tools.native")

RESULTS_FILE = "results.jsonl"


class NativeTool(BaseTool):
    """Base for in-process parsers. Subclasses implement ``parse_file``."""

    #: file suffixes (lowercase) this parser accepts when given a directory
    suffixes: tuple[str, ...] = ()
    #: import name of the parsing library (availability check)
    module: str = ""

    def build_command(self, input_path: str, output_dir: str, **kwargs) -> list[str]:
        return ["python-native", self.manifest().name, input_path, output_dir]

    def is_available(self) -> bool:
        try:
            __import__(self.module)
            return True
        except ImportError:
            return False

    def parse_file(self, path: Path) -> Iterator[dict]:
        raise NotImplementedError

    def _inputs(self, input_path: str) -> list[Path]:
        path = Path(input_path)
        if path.is_dir():
            return sorted(p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in self.suffixes)
        return [path]

    #: the run's output directory (parsers that also write files, e.g. images)
    output_dir: Path | None = None

    def _parse_all(self, input_path: str, out: Path) -> tuple[int, list[str]]:
        self.output_dir = out
        count, errors = 0, []
        with (out / RESULTS_FILE).open("w", encoding="utf-8") as fh:
            for path in self._inputs(input_path):
                try:
                    for record in self.parse_file(path):
                        record.setdefault("_source_file", str(path))
                        fh.write(json.dumps(record, default=str) + "\n")
                        count += 1
                except Exception as e:  # noqa: BLE001 — one bad file must not stop the run
                    errors.append(f"{path}: {type(e).__name__}: {e}")
        return count, errors

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
        m = self.manifest()
        tool_run = ToolRun(
            run_number=run_number,
            case_id=case_id,
            evidence_id=evidence_id,
            tool_name=m.name,
            tool_version=self.get_version(),
            command=f"{m.name} {input_path}",
            parameters=kwargs,
            status=ToolRunStatus.RUNNING,
            started_at=datetime.now(UTC),
        )
        out = Path(output_dir)
        shutil.rmtree(out, ignore_errors=True)
        out.mkdir(parents=True, exist_ok=True)

        start = time.monotonic()
        try:
            count, errors = await asyncio.wait_for(
                asyncio.to_thread(self._parse_all, input_path, out),
                timeout=timeout or m.timeout,
            )
            tool_run.stdout = f"Parsed {count} record(s)"
            tool_run.stderr = "\n".join(errors)[:10000]
            tool_run.exit_code = 0 if count or not errors else 1
            tool_run.status = ToolRunStatus.COMPLETED if tool_run.exit_code == 0 else ToolRunStatus.FAILED
        except TimeoutError:
            tool_run.status = ToolRunStatus.TIMEOUT
            tool_run.stderr = f"Timed out after {timeout or m.timeout}s"

        tool_run.completed_at = datetime.now(UTC)
        tool_run.duration_seconds = round(time.monotonic() - start, 3)
        tool_run.output_path = output_dir
        tool_run.output_files = [p.name for p in out.iterdir() if p.is_file()]
        log.info("tool_run_completed", tool=m.name, run_number=run_number, status=tool_run.status)
        return tool_run
