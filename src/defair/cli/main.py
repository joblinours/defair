"""DEFAIR CLI — main entry point and click group."""

from __future__ import annotations

import click

from defair import __version__
from defair.cli.cases import case_group, cases_group
from defair.cli.evidence import evidence_group
from defair.config import load_config
from defair.logging import configure_logging


@click.group()
@click.version_option(version=__version__, prog_name="defair")
@click.option("--config", "config_path", type=click.Path(), default=None, help="Config file path.")
@click.option("--db", "db_path", type=click.Path(), default=None, help="Override database path.")
@click.pass_context
def cli(ctx: click.Context, config_path: str | None, db_path: str | None) -> None:
    """DEFAIR — Digital Forensics & Incident Response platform.

    MCP-first, containerized, modular DFIR workbench.
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


# Register sub-groups
cli.add_command(cases_group)
cli.add_command(case_group)
cli.add_command(evidence_group)
