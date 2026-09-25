"""CLI commands for the normalization pipeline (replay, rerun, stats)."""

from __future__ import annotations

import json

import click
from rich.console import Console

from defair.cli.proxy import get_container_or_fail, proxy_command
from defair.database import get_initialized_connection, run_sync

console = Console()


@click.group("normalize")
def normalize_group() -> None:
    """Normalization pipeline: rebuild artifacts, inspect counters.

    Tool outputs are normalized to JSONL under /workspace/normalized/ before
    being loaded into the case database; artifact ids are deterministic.
    """


def _run(ctx: click.Context, proxy_args: list[str], coro_factory) -> None:
    container = get_container_or_fail(ctx)
    if container:
        return proxy_command(container, proxy_args)

    async def _go() -> None:
        conn = await get_initialized_connection(ctx.obj["db_path"])
        try:
            result = await coro_factory(conn)
        except ValueError as e:
            console.print(f"[red]✗[/red] {e}")
            raise SystemExit(1)
        finally:
            await conn.close()
        click.echo(json.dumps(result, indent=2, default=str))

    run_sync(_go())


@normalize_group.command("replay")
@click.option("--case", "case_id", required=True, help="Case number (CASE-YYYY-NNN), name or ID.")
@click.option("--from-dir", "json_dir", default=None,
              help="Load every *.jsonl under this directory (when the database was lost).")
@click.pass_context
def normalize_replay(ctx: click.Context, case_id: str, json_dir: str | None) -> None:
    """Rebuild a case's artifacts from the normalized JSONL files."""
    from defair.services import normalization_service

    args = ["normalize", "replay", "--case", case_id, *(["--from-dir", json_dir] if json_dir else [])]
    _run(ctx, args, lambda conn: normalization_service.replay(conn, case_id, json_dir))


@normalize_group.command("rerun")
@click.argument("run")
@click.pass_context
def normalize_rerun(ctx: click.Context, run: str) -> None:
    """Re-normalize RUN (RUN-NNN or id) from its raw tool output."""
    from defair.services import normalization_service

    _run(ctx, ["normalize", "rerun", run], lambda conn: normalization_service.rerun(conn, run))


@normalize_group.command("stats")
@click.argument("run")
@click.pass_context
def normalize_stats(ctx: click.Context, run: str) -> None:
    """Show normalization counters and JSONL files of RUN."""
    from defair.services import normalization_service

    _run(ctx, ["normalize", "stats", run], lambda conn: normalization_service.stats(conn, run))
