"""BaseTool — abstract base class for all forensic tool wrappers.

Every forensic tool integration inherits from BaseTool. The base class
provides a consistent interface for:
- Tool health check (is the binary present and runnable?)
- Tool execution (run with arguments, capture output)
- Output discovery (find generated files)
- Provenance tracking (ToolRun creation)
"""

from __future__ import annotations

import asyncio
import json
import shutil
import time
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from pathlib import Path

import structlog

from defair.models.tool_manifest import ToolManifest
from defair.models.tool_run import ToolRun, ToolRunStatus

log = structlog.get_logger(component="tools")

# Written at image build time: {tool: {"version": ..., "sha256": ...}}
VERSIONS_FILE = Path("/opt/defair/versions.json")


def installed_versions(path: Path = VERSIONS_FILE) -> dict:
    """Pinned tool versions recorded in the image (empty outside a container)."""
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


class BaseTool(ABC):
    """Abstract base class for forensic tool wrappers.

    Subclasses must implement:
    - manifest() → static tool description
    - build_command() → construct the command line for a given input
    - parse_output() → list of dicts to feed into normalizers

    The base class handles execution, timing, and ToolRun creation.
    """

    @staticmethod
    @abstractmethod
    def manifest() -> ToolManifest:
        """Return the tool's manifest describing its capabilities."""

    @abstractmethod
    def build_command(
        self,
        input_path: str,
        output_dir: str,
        **kwargs,
    ) -> list[str]:
        """Build the command-line arguments for this tool.

        Args:
            input_path: Path to the input file/directory.
            output_dir: Directory where outputs should be written.
            **kwargs: Tool-specific options.

        Returns:
            Full command as a list of strings (e.g. ["MFTECmd", "-f", ...]).
        """

    def parse_output(self, output_dir: str, **kwargs) -> list[dict]:
        """Parse the tool's output files into raw artifact dicts.

        Default implementation returns an empty list. Override in
        subclasses that produce parseable output.

        Args:
            output_dir: Directory containing tool outputs.

        Returns:
            List of raw artifact dictionaries.
        """
        return []

    def check_result(self, tool_run: ToolRun, output_dir: Path) -> None:
        """Hook: inspect a finished run (e.g. a tool that exits 0 on failure)."""

    def is_available(self) -> bool:
        """Check if the tool binary is available on the system."""
        m = self.manifest()
        if not m.command:
            return False
        binary = m.command.split()[0]
        return shutil.which(binary) is not None

    def get_version(self) -> str | None:
        """Get the tool's version: the pinned image version, else the manifest's."""
        m = self.manifest()
        pinned = installed_versions().get(m.name, {})
        return pinned.get("version") or m.version

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
        """Execute the tool and return a ToolRun with full provenance.

        Args:
            input_path: Path to the input file/directory.
            output_dir: Directory for outputs.
            case_id: Case this run belongs to.
            evidence_id: Optional evidence ID.
            run_number: Human-readable run number.
            timeout: Override timeout in seconds.
            **kwargs: Tool-specific options.

        Returns:
            A ToolRun recording the execution details.
        """
        m = self.manifest()
        effective_timeout = timeout or m.timeout

        # Build command
        cmd = self.build_command(input_path, output_dir, **kwargs)
        command_str = " ".join(cmd)

        # Create ToolRun
        tool_run = ToolRun(
            run_number=run_number,
            case_id=case_id,
            evidence_id=evidence_id,
            tool_name=m.name,
            tool_version=self.get_version(),
            command=command_str,
            parameters=kwargs,
            status=ToolRunStatus.RUNNING,
            started_at=datetime.now(UTC),
        )

        log.info(
            "tool_run_started",
            tool=m.name,
            run_number=run_number,
            command=command_str,
        )

        # Ensure output directory exists and is clean (avoids duplicates
        # when the workspace volume persists across container recreations
        # but the DB is fresh → same RUN-NNN directory reused with stale files)
        out = Path(output_dir)
        if out.exists():
            import shutil as _shutil

            _shutil.rmtree(out)
        out.mkdir(parents=True, exist_ok=True)

        # Execute. Tools whose results come on stdout (manifest.stdout_file)
        # stream it to a file: record streams can be far larger than memory.
        start = time.monotonic()
        stdout_fh = (out / m.stdout_file).open("wb") if m.stdout_file else None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=stdout_fh or asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=effective_timeout,
                )
            except (TimeoutError, asyncio.CancelledError):
                # Timed out or the profile run was cancelled: never leave the
                # tool running behind us
                if proc.returncode is None:
                    proc.kill()
                    await proc.wait()
                raise

            tool_run.exit_code = proc.returncode
            tool_run.stdout = (stdout_bytes or b"").decode(errors="replace")
            tool_run.stderr = (stderr_bytes or b"").decode(errors="replace")

            if proc.returncode in m.success_exit_codes:
                tool_run.status = ToolRunStatus.COMPLETED
            else:
                tool_run.status = ToolRunStatus.FAILED
            if stdout_fh:
                stdout_fh.close()
            self.check_result(tool_run, out)

        except TimeoutError:
            tool_run.status = ToolRunStatus.TIMEOUT
            tool_run.stderr = f"Timed out after {effective_timeout}s"
            log.warning("tool_run_timeout", tool=m.name, timeout=effective_timeout)

        except FileNotFoundError:
            tool_run.status = ToolRunStatus.FAILED
            tool_run.stderr = f"Tool binary not found: {cmd[0]}"
            tool_run.exit_code = 127
            log.error("tool_not_found", tool=m.name, binary=cmd[0])

        except Exception as e:
            tool_run.status = ToolRunStatus.FAILED
            tool_run.stderr = str(e)
            log.error("tool_run_error", tool=m.name, error=str(e))

        if stdout_fh and not stdout_fh.closed:
            stdout_fh.close()

        # Finalize timing
        elapsed = time.monotonic() - start
        tool_run.completed_at = datetime.now(UTC)
        tool_run.duration_seconds = round(elapsed, 3)
        tool_run.output_path = output_dir

        # Discover output files
        out_path = Path(output_dir)
        if out_path.exists():
            tool_run.output_files = [
                str(f.relative_to(out_path))
                for f in out_path.rglob("*")
                if f.is_file()
            ]

        log.info(
            "tool_run_completed",
            tool=m.name,
            run_number=run_number,
            status=tool_run.status,
            exit_code=tool_run.exit_code,
            duration=tool_run.duration_seconds,
            output_files=len(tool_run.output_files),
        )

        return tool_run
