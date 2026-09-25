"""DEFAIR CLI — main entry point and click group."""

from __future__ import annotations

import io
import re
import sys
import time

import click

from defair import __version__
from defair.cli.cases import case_group, cases_group
from defair.cli.containers import container_group
from defair.cli.evidence import evidence_group
from defair.cli.evtx import evtx_group
from defair.cli.findings import findings_group
from defair.cli.host import host_group
from defair.cli.hunt import hunt_cmd
from defair.cli.normalize import normalize_group
from defair.cli.rules import rules_group
from defair.cli.runs import profile_group, run_group
from defair.cli.scan import scan_group
from defair.cli.search import search_cmd
from defair.cli.timeline import timeline_group
from defair.cli.tools_cli import (
    analyze_cmd,
    artifacts_group,
    discover_cmd,
    runs_group,
    tools_group,
)
from defair.cli.watchlist import watchlist_group
from defair.config import load_config
from defair.logging import configure_logging, default_log_file, get_logger, redact_argv

MAX_LOGGED_OUTPUT = 16_000  # characters of a command's output kept in the log


class _Tee(io.TextIOBase):
    """Copies what a command prints so its result can be logged too."""

    def __init__(self, stream) -> None:
        self.stream = stream
        self.buffer_text: list[str] = []
        self.size = 0

    def write(self, s) -> int:
        text = s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
        if self.size < MAX_LOGGED_OUTPUT:
            self.buffer_text.append(text)
            self.size += len(text)
        if isinstance(s, bytes):
            return self.stream.buffer.write(s)
        return self.stream.write(s)

    @property
    def buffer(self):
        return self.stream.buffer

    def flush(self) -> None:
        self.stream.flush()

    def isatty(self) -> bool:
        return self.stream.isatty()

    @property
    def encoding(self):
        return getattr(self.stream, "encoding", "utf-8")

    def captured(self) -> str:
        text = re.sub(r"\x1b\[[0-9;]*m", "", "".join(self.buffer_text))
        return text[:MAX_LOGGED_OUTPUT]


class LoggedGroup(click.Group):
    """Logs every command: its (redacted) arguments, output, exit code, duration.

    Inside a forensic container these lines go to /workspace/logs/defair.log,
    which the container's PID 1 follows — so `docker logs` shows every action.
    """

    def invoke(self, ctx: click.Context):
        start = time.monotonic()
        tee = None
        if default_log_file() and not ctx.resilient_parsing:
            tee = _Tee(sys.stdout)
            sys.stdout = tee
        exit_code, error = 0, None
        try:
            return super().invoke(ctx)
        except click.exceptions.Exit as e:
            exit_code = e.exit_code
            raise
        except SystemExit as e:
            exit_code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
            raise
        except click.ClickException as e:
            exit_code, error = e.exit_code, e.format_message()
            raise
        except Exception as e:
            exit_code, error = 1, f"{type(e).__name__}: {e}"
            get_logger("cli").exception("cli_command_crashed", argv=redact_argv(sys.argv[1:]))
            raise
        finally:
            if tee is not None:
                sys.stdout = tee.stream
            if ctx.obj is not None and "config" in ctx.obj:  # logging configured
                get_logger("cli").info(
                    "cli_command_finished",
                    argv=redact_argv(sys.argv[1:]),
                    exit_code=exit_code,
                    error=error,
                    duration_seconds=round(time.monotonic() - start, 3),
                    output=tee.captured() if tee else None,
                )


def _is_inside_container() -> bool:
    """Detect if we are running inside a Docker container."""
    from pathlib import Path

    return Path("/.dockerenv").exists()


@click.group(cls=LoggedGroup)
@click.version_option(version=__version__, prog_name="defair")
@click.option("--config", "config_path", type=click.Path(), default=None, help="Config file path.")
@click.option("--db", "db_path", type=click.Path(), default=None, help="Override database path.")
@click.option(
    "-c", "--container", "container_name", default=None, envvar="DEFAIR_CONTAINER",
    help="Target container for case/evidence commands. Required on host.",
)
@click.pass_context
def cli(ctx: click.Context, config_path: str | None, db_path: str | None, container_name: str | None) -> None:
    """DEFAIR — Digital Forensics & Incident Response platform.

    MCP-first, containerized, modular DFIR workbench.

    On the host, use -c <container> to target a forensic container:

      defair -c defair-case-2026-001 case create "My case"

    Inside a container, commands run locally (no -c needed).
    """
    from pathlib import Path

    config = load_config(Path(config_path) if config_path else None)
    configure_logging(config.logging)

    if db_path:
        config.storage.database = Path(db_path).expanduser()
        config.storage.database.parent.mkdir(parents=True, exist_ok=True)

    ctx.ensure_object(dict)
    ctx.obj["config"] = config
    ctx.obj["db_path"] = str(config.storage.database)
    ctx.obj["container"] = container_name
    ctx.obj["inside_container"] = _is_inside_container()
    get_logger("cli").info("cli_command_started", argv=redact_argv(sys.argv[1:]),
                           inside_container=ctx.obj["inside_container"])


# Register sub-groups
cli.add_command(cases_group)
cli.add_command(case_group)
cli.add_command(evidence_group)
cli.add_command(container_group)
cli.add_command(tools_group)
cli.add_command(runs_group)
cli.add_command(artifacts_group)
cli.add_command(discover_cmd)
cli.add_command(analyze_cmd)
cli.add_command(hunt_cmd)
cli.add_command(timeline_group)
cli.add_command(findings_group)
cli.add_command(search_cmd)
cli.add_command(scan_group)
cli.add_command(rules_group)
cli.add_command(normalize_group)
cli.add_command(profile_group)
cli.add_command(run_group)
cli.add_command(evtx_group)
cli.add_command(host_group)
cli.add_command(watchlist_group)
