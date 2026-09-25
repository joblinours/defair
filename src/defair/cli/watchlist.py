"""CLI commands for keyword / IOC watchlists (``defair watchlist``)."""

from __future__ import annotations

import json

import click
from rich.console import Console
from rich.table import Table

from defair.cli.proxy import get_container_or_fail, proxy_command
from defair.database import get_initialized_connection, run_sync

console = Console()


@click.group("watchlist")
def watchlist_group() -> None:
    """Keyword / IOC watchlists: built-in + per-case (/workspace/watchlists/*.yaml)."""


@watchlist_group.command("list")
@click.option("--json", "as_json", is_flag=True, help="JSON output.")
@click.pass_context
def watchlist_list(ctx: click.Context, as_json: bool) -> None:
    """List the available watchlists."""
    container = get_container_or_fail(ctx)
    if container:
        return proxy_command(container, ["watchlist", "list", *(["--json"] if as_json else [])])
    from defair.services.watchlist_service import list_watchlists, summary

    items = [summary(w) for w in list_watchlists()]
    if as_json:
        click.echo(json.dumps(items, indent=2))
        return
    table = Table(title=f"Watchlists ({len(items)})")
    for column in ("name", "terms", "severity", "origin", "description"):
        table.add_column(column)
    for item in items:
        table.add_row(item["name"], str(item["terms"]), item["severity"], item["origin"], item["description"])
    console.print(table)


@watchlist_group.command("show")
@click.argument("name")
@click.pass_context
def watchlist_show(ctx: click.Context, name: str) -> None:
    """Show the terms of one watchlist."""
    container = get_container_or_fail(ctx)
    if container:
        return proxy_command(container, ["watchlist", "show", name])
    from defair.services.watchlist_service import get_watchlist, summary

    try:
        wl = get_watchlist(name)
    except ValueError as e:
        console.print(f"[red]✗[/red] {e}")
        raise SystemExit(1) from e
    click.echo(json.dumps({**summary(wl), "terms": [
        {"pattern": t.pattern, "regex": t.regex, "note": t.note} for t in wl.terms]}, indent=2))


@watchlist_group.command("search")
@click.option("--case", "case_id", required=True, help="Case number (CASE-YYYY-NNN), name or ID.")
@click.option("--watchlist", "-w", "names", multiple=True, help="Watchlist name (repeatable; default: all).")
@click.option("--term", "-t", "terms", multiple=True, help="Ad-hoc literal term (repeatable).")
@click.option("--scope", "scopes", multiple=True, type=click.Choice(["artifacts", "strings", "evidence"]),
              help="Where to search (repeatable; default: all).")
@click.option("--findings", "create_findings", is_flag=True, help="Create one finding per term hit.")
@click.option("--json", "as_json", is_flag=True, help="JSON output (full report).")
@click.pass_context
def watchlist_search(ctx: click.Context, case_id: str, names: tuple[str, ...], terms: tuple[str, ...],
                     scopes: tuple[str, ...], create_findings: bool, as_json: bool) -> None:
    """Search watchlists across the case's artifacts, strings index and raw files."""
    container = get_container_or_fail(ctx)
    if container:
        cmd = ["watchlist", "search", "--case", case_id]
        for name in names:
            cmd.extend(["--watchlist", name])
        for term in terms:
            cmd.extend(["--term", term])
        for scope in scopes:
            cmd.extend(["--scope", scope])
        if create_findings:
            cmd.append("--findings")
        if as_json:
            cmd.append("--json")
        return proxy_command(container, cmd)

    from defair.services import watchlist_service

    async def _run() -> None:
        conn = await get_initialized_connection(ctx.obj["db_path"])
        try:
            report = await watchlist_service.search_watchlist(
                conn, case_id, watchlists=list(names) or None, terms=list(terms) or None,
                scopes=scopes or watchlist_service.SCOPES, create_findings=create_findings,
            )
        except ValueError as e:
            console.print(f"[red]✗[/red] {e}")
            ctx.exit(1)
            return
        finally:
            await conn.close()
        if as_json:
            click.echo(json.dumps(report, indent=2, default=str))
            return
        console.print(f"[bold]{report['total_hits']}[/bold] hit(s) — engine {report['engine']}, "
                      f"files searched {report['scopes']}")
        table = Table()
        for column in ("watchlist", "term", "artifacts", "strings", "evidence", "first hit"):
            table.add_column(column, overflow="fold")
        for wl in report["watchlists"]:
            for entry in wl["terms_hit"]:
                first = entry["first_hits"][0] if entry["first_hits"] else {}
                where = first.get("artifact") or first.get("file") or ""
                table.add_row(wl["name"], entry["term"], str(entry["hits"]["artifacts"]),
                              str(entry["hits"]["strings"]), str(entry["hits"]["evidence"]),
                              f"{where} {first.get('description') or first.get('text') or ''}"[:120])
        console.print(table)
        if report["findings"]:
            console.print(f"Findings: {', '.join(report['findings'])}")
        if report.get("report_path"):
            console.print(f"[dim]Report: {report['report_path']}[/dim]")

    run_sync(_run())
