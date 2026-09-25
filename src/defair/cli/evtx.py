"""CLI commands for typed EVTX views (``defair evtx views|view``)."""

from __future__ import annotations

import json

import click
from rich.console import Console
from rich.table import Table

from defair.cli.proxy import get_container_or_fail, proxy_command
from defair.database import get_initialized_connection, run_sync

console = Console()


@click.group("evtx")
def evtx_group() -> None:
    """Typed EVTX views (logons, process creation, services, …)."""


@evtx_group.command("views")
@click.option("--json", "as_json", is_flag=True, help="JSON output.")
def evtx_views(as_json: bool) -> None:
    """List the available EVTX views."""
    from defair.services.evtx_view_service import list_views

    views = list_views()
    if as_json:
        click.echo(json.dumps(views, indent=2))
        return
    table = Table(title=f"EVTX views ({len(views)})")
    table.add_column("View", style="cyan")
    table.add_column("Events")
    table.add_column("Description")
    for view in views:
        table.add_row(view["name"], "\n".join(view["events"]), view["description"])
    console.print(table)


@evtx_group.command("view")
@click.argument("name")
@click.option("--case", "case_id", required=True, help="Case number (CASE-YYYY-NNN), name or ID.")
@click.option("--since", default=None, help="ISO date/time lower bound.")
@click.option("--until", default=None, help="ISO date/time upper bound.")
@click.option("--host", "hostname", default=None, help="Computer name contains.")
@click.option("--user", "username", default=None, help="User name contains.")
@click.option("--event-id", type=int, default=None, help="Only this EventID of the view.")
@click.option("--desc", is_flag=True, help="Newest first.")
@click.option("--limit", default=200, help="Max rows.")
@click.option("--offset", default=0, help="Skip the first N rows.")
@click.option("--json", "as_json", is_flag=True, help="JSON output.")
@click.pass_context
def evtx_view(ctx: click.Context, name: str, case_id: str, since: str | None, until: str | None,
              hostname: str | None, username: str | None, event_id: int | None, desc: bool,
              limit: int, offset: int, as_json: bool) -> None:
    """Show one EVTX view for a case (e.g. ``defair evtx view logons --case X``)."""
    container = get_container_or_fail(ctx)
    if container:
        cmd = ["evtx", "view", name, "--case", case_id, "--limit", str(limit), "--offset", str(offset)]
        for flag, value in (("--since", since), ("--until", until), ("--host", hostname),
                            ("--user", username), ("--event-id", event_id)):
            if value is not None:
                cmd.extend([flag, str(value)])
        if desc:
            cmd.append("--desc")
        if as_json:
            cmd.append("--json")
        return proxy_command(container, cmd)

    from defair.services import evtx_view_service

    async def _run() -> None:
        conn = await get_initialized_connection(ctx.obj["db_path"])
        try:
            result = await evtx_view_service.get_view(
                conn, case_id, name, since=since, until=until, hostname=hostname,
                username=username, event_id=event_id, order="desc" if desc else "asc",
                limit=limit, offset=offset,
            )
        except ValueError as e:
            console.print(f"[red]✗[/red] {e}")
            ctx.exit(1)
            return
        finally:
            await conn.close()
        if as_json:
            click.echo(evtx_view_service.dumps(result))
            return
        table = Table(title=f"{name} — {result['total']} event(s)"
                            + (f", showing {len(result['rows'])}" if result["total"] > len(result["rows"]) else ""))
        for column in ("timestamp", "event_id", "computer", *result["columns"], "artifact"):
            table.add_column(column, overflow="fold")
        for row in result["rows"]:
            table.add_row(*[str(row.get(c) if row.get(c) is not None else "")[:200]
                            for c in ("timestamp", "event_id", "computer", *result["columns"], "artifact")])
        console.print(table)

    run_sync(_run())
