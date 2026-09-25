"""DEFAIR CLI — main entry point and click group."""

from __future__ import annotations

import click

from defair import __version__
from defair.cli.cases import case_group, cases_group
from defair.cli.containers import container_group
from defair.cli.evidence import evidence_group
from defair.cli.findings import findings_group
from defair.cli.hunt import hunt_cmd
from defair.cli.rules import rules_group
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
from defair.config import load_config
from defair.logging import configure_logging


def _is_inside_container() -> bool:
    """Detect if we are running inside a Docker container."""
    from pathlib import Path

    return Path("/.dockerenv").exists()


@click.group()
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
