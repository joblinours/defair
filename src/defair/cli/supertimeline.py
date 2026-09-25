"""CLI commands for the supertimeline (Plaso + Sleuth Kit worker jobs).

On the HOST (``-c <case container>``): ``start``, ``status``, ``cancel``,
``jobs`` — they drive the worker container. Inside the case container:
``prepare``, ``import``, ``state`` — they own the case database (the host
calls them through ``docker exec``).
"""

from __future__ import annotations

import json

import click
from rich.console import Console

from defair.database import get_initialized_connection, run_sync

console = Console()


def _host_container(ctx: click.Context) -> str:
    container = ctx.obj.get("container")
    if ctx.obj.get("inside_container") or not container:
        console.print("[red]✗[/red] This command runs on the host, with -c <case container> "
                      "(it starts the worker container).")
        raise SystemExit(2)
    return container


def _echo(data) -> None:
    click.echo(json.dumps(data, indent=2, default=str))


@click.group("supertimeline")
def supertimeline_group() -> None:
    """Supertimeline with Plaso and the Sleuth Kit (worker-plaso image)."""


# -- host -------------------------------------------------------------------


@supertimeline_group.command("start")
@click.option("--case", "case_id", required=True, help="Case number (CASE-YYYY-NNN), name or ID.")
@click.option("--evidence", "evidence_id", required=True, help="Evidence (EVD-NNN).")
@click.option("--mode", default="plaso", type=click.Choice(["plaso", "bodyfile", "both", "unallocated", "all"]),
              help="plaso, bodyfile (fls), both, unallocated (blkls strings) or all.")
@click.option("--parsers", default=None, help="Plaso parsers / preset (default: automatic).")
@click.option("--timezone", default=None, help="Time zone of sources without one (default UTC).")
@click.option("--overwrite", is_flag=True, help="Rebuild the .plaso storage even if reusable.")
@click.option("--filter", "psort_filter", default=None, help="psort event filter expression.")
@click.pass_context
def st_start(ctx, case_id, evidence_id, mode, parsers, timezone, overwrite, psort_filter) -> None:
    """Start a supertimeline job (returns immediately with the RUN-NNN)."""
    from defair.config import load_config
    from defair.services import supertimeline_host

    container = _host_container(ctx)
    config = load_config()
    try:
        result = run_sync(supertimeline_host.start(
            container, case_id, evidence_id, config.workers, config.container, mode=mode,
            parsers=parsers, timezone=timezone, overwrite=overwrite, psort_filter=psort_filter))
    except (RuntimeError, ValueError, FileNotFoundError, ConnectionError) as e:
        console.print(f"[red]✗[/red] {e}")
        raise SystemExit(1) from e
    console.print(f"[green]✓[/green] {result['run_number']} started ({result['job']['job']}, "
                  f"{result['job']['image']}) — follow it with: "
                  f"defair -c {container} supertimeline status {result['run_number']}")
    if (result.get("plan", {}).get("plaso") or {}).get("reused"):
        console.print("  existing .plaso storage reused — only psort runs")


@supertimeline_group.command("status")
@click.argument("run_number")
@click.option("--no-import", is_flag=True, help="Do not import the results when finished.")
@click.pass_context
def st_status(ctx, run_number, no_import) -> None:
    """Job state; imports the events into the case once it has finished."""
    from defair.services import supertimeline_host

    container = _host_container(ctx)
    try:
        _echo(run_sync(supertimeline_host.status(container, run_number, auto_import=not no_import)))
    except (RuntimeError, ValueError, ConnectionError) as e:
        console.print(f"[red]✗[/red] {e}")
        raise SystemExit(1) from e


@supertimeline_group.command("cancel")
@click.argument("run_number")
@click.pass_context
def st_cancel(ctx, run_number) -> None:
    """Stop a running job (what was produced is still imported by status)."""
    from defair.services import supertimeline_host

    _echo(run_sync(supertimeline_host.cancel(_host_container(ctx), run_number)))


@supertimeline_group.command("jobs")
@click.pass_context
def st_jobs(ctx) -> None:
    """Worker job containers of the case container."""
    from defair.services import supertimeline_host

    _echo(run_sync(supertimeline_host.jobs(_host_container(ctx))))


# -- case container ------------------------------------------------------------


@supertimeline_group.command("prepare")
@click.option("--case", "case_id", required=True)
@click.option("--evidence", "evidence_id", required=True)
@click.option("--mode", default="plaso")
@click.option("--parsers", default=None)
@click.option("--timezone", default=None)
@click.option("--overwrite", is_flag=True)
@click.option("--filter", "psort_filter", default=None)
@click.option("--workers", default=4, type=int)
@click.pass_context
def st_prepare(ctx, case_id, evidence_id, mode, parsers, timezone, overwrite, psort_filter, workers) -> None:
    """(case container) Reserve the run and write the job spec — JSON output."""
    from defair.services import supertimeline_service

    async def _run():
        conn = await get_initialized_connection(ctx.obj["db_path"])
        try:
            return await supertimeline_service.prepare_job(
                conn, case_id, evidence_id, mode=mode, parsers=parsers, timezone=timezone,
                overwrite=overwrite, psort_filter=psort_filter, workers=workers)
        finally:
            await conn.close()

    try:
        _echo(run_sync(_run()))
    except ValueError as e:
        click.echo(str(e), err=True)
        raise SystemExit(1) from e


@supertimeline_group.command("import")
@click.argument("run_number")
@click.option("--force", is_flag=True, help="Import again (replaces the run's events).")
@click.pass_context
def st_import(ctx, run_number, force) -> None:
    """(case container) Import a finished job's outputs — JSON output."""
    from defair.services import supertimeline_service

    async def _run():
        conn = await get_initialized_connection(ctx.obj["db_path"])
        try:
            return await supertimeline_service.import_job(conn, run_number, force=force)
        finally:
            await conn.close()

    try:
        _echo(run_sync(_run()))
    except ValueError as e:
        click.echo(str(e), err=True)
        raise SystemExit(1) from e


@supertimeline_group.command("state")
@click.argument("run_number")
@click.pass_context
def st_state(ctx, run_number) -> None:
    """(case container) What the case knows about a run — JSON output."""
    from defair.services import supertimeline_service

    async def _run():
        conn = await get_initialized_connection(ctx.obj["db_path"])
        try:
            return await supertimeline_service.job_state(conn, run_number)
        finally:
            await conn.close()

    _echo(run_sync(_run()))
