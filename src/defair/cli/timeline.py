"""CLI commands for timeline operations."""

from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

from defair.cli.proxy import get_container_or_fail, proxy_command
from defair.database import get_initialized_connection, run_sync

console = Console()


@click.group("timeline")
def timeline_group() -> None:
    """Timeline operations — search, summarize, export."""


@timeline_group.command("summary")
@click.option("--case", "case_id", required=True, help="Case ID or case number.")
@click.pass_context
def timeline_summary(ctx: click.Context, case_id: str) -> None:
    """Show timeline summary for a case."""
    container = get_container_or_fail(ctx)
    if container:
        return proxy_command(container, ["timeline", "summary", "--case", case_id])

    from defair.services import timeline_service
    from defair.services.case_service import get_case

    async def _run() -> None:
        db_path = ctx.obj["db_path"]
        conn = await get_initialized_connection(db_path)
        try:
            case = await get_case(conn, case_id)
            if case is None:
                console.print(f"[red]✗[/red] Case not found: {case_id}")
                ctx.exit(1)
                return

            result = await timeline_service.build_timeline(conn, case.id)

            console.print(f"\n[bold]Timeline Summary[/bold] — {case_id}")
            console.print(f"  Total events: [cyan]{result['total_events']}[/cyan]")
            console.print(f"  Earliest:     {result.get('earliest', 'N/A')}")
            console.print(f"  Latest:       {result.get('latest', 'N/A')}")

            if result.get("by_tool"):
                console.print("\n[bold]By Tool:[/bold]")
                for tool, count in result["by_tool"].items():
                    console.print(f"  {tool}: {count}")

            if result.get("by_category"):
                console.print("\n[bold]By Category:[/bold]")
                for cat, count in result["by_category"].items():
                    console.print(f"  {cat}: {count}")

            if result.get("by_severity"):
                console.print("\n[bold]By Severity:[/bold]")
                for sev, count in result["by_severity"].items():
                    color = {"critical": "red", "high": "yellow", "medium": "blue"}.get(sev, "dim")
                    console.print(f"  [{color}]{sev}[/{color}]: {count}")

        finally:
            await conn.close()

    run_sync(_run())


@timeline_group.command("search")
@click.option("--case", "case_id", required=True, help="Case ID or case number.")
@click.option("--query", "-q", default=None, help="Text search in description/data.")
@click.option("--from", "from_time", default=None, help="Start time (ISO 8601).")
@click.option("--to", "to_time", default=None, help="End time (ISO 8601).")
@click.option("--hostname", default=None, help="Filter by hostname.")
@click.option("--username", default=None, help="Filter by username.")
@click.option("--category", default=None, help="Filter by category.")
@click.option("--severity", default=None, help="Filter by severity.")
@click.option("--tool", "source_tool", default=None, help="Filter by source tool.")
@click.option("--limit", default=50, help="Max results.")
@click.pass_context
def timeline_search(
    ctx: click.Context,
    case_id: str,
    query: str | None,
    from_time: str | None,
    to_time: str | None,
    hostname: str | None,
    username: str | None,
    category: str | None,
    severity: str | None,
    source_tool: str | None,
    limit: int,
) -> None:
    """Search the timeline with filters."""
    container = get_container_or_fail(ctx)
    if container:
        cmd = ["timeline", "search", "--case", case_id, "--limit", str(limit)]
        if query:
            cmd.extend(["--query", query])
        if from_time:
            cmd.extend(["--from", from_time])
        if to_time:
            cmd.extend(["--to", to_time])
        if hostname:
            cmd.extend(["--hostname", hostname])
        if username:
            cmd.extend(["--username", username])
        if category:
            cmd.extend(["--category", category])
        if severity:
            cmd.extend(["--severity", severity])
        if source_tool:
            cmd.extend(["--tool", source_tool])
        return proxy_command(container, cmd)

    from defair.services import timeline_service
    from defair.services.case_service import get_case

    async def _run() -> None:
        db_path = ctx.obj["db_path"]
        conn = await get_initialized_connection(db_path)
        try:
            case = await get_case(conn, case_id)
            if case is None:
                console.print(f"[red]✗[/red] Case not found: {case_id}")
                ctx.exit(1)
                return

            results = await timeline_service.search_timeline(
                conn, case.id,
                query=query,
                from_time=from_time,
                to_time=to_time,
                hostname=hostname,
                username=username,
                category=category,
                severity=severity,
                source_tool=source_tool,
                limit=limit,
            )

            if not results:
                console.print("[dim]No events found.[/dim]")
                return

            table = Table(title=f"Timeline ({len(results)} events)")
            table.add_column("Timestamp", style="cyan", max_width=20)
            table.add_column("Type")
            table.add_column("Severity")
            table.add_column("Description", max_width=50)
            table.add_column("Tool")

            for r in results:
                sev = r.get("severity") or ""
                sev_style = {"critical": "red", "high": "yellow", "medium": "blue"}.get(sev, "dim")
                table.add_row(
                    (r.get("timestamp") or "")[:19],
                    r.get("artifact_type", "").split(".")[-1],
                    f"[{sev_style}]{sev}[/{sev_style}]" if sev else "",
                    (r.get("description") or "")[:50],
                    r.get("source_tool", ""),
                )
            console.print(table)

        finally:
            await conn.close()

    run_sync(_run())


@timeline_group.command("export")
@click.option("--case", "case_id", required=True, help="Case ID or case number.")
@click.option("--format", "fmt", default="csv", type=click.Choice(["csv", "jsonl"]), help="Export format.")
@click.option("--output", "output_path", default=None, help="Output file path.")
@click.pass_context
def timeline_export(ctx: click.Context, case_id: str, fmt: str, output_path: str | None) -> None:
    """Export timeline to CSV or JSONL."""
    container = get_container_or_fail(ctx)
    if container:
        cmd = ["timeline", "export", "--case", case_id, "--format", fmt]
        if output_path:
            cmd.extend(["--output", output_path])
        return proxy_command(container, cmd)

    from defair.services import timeline_service
    from defair.services.case_service import get_case

    async def _run() -> None:
        db_path = ctx.obj["db_path"]
        conn = await get_initialized_connection(db_path)
        try:
            case = await get_case(conn, case_id)
            if case is None:
                console.print(f"[red]✗[/red] Case not found: {case_id}")
                ctx.exit(1)
                return

            result = await timeline_service.export_timeline(
                conn, case.id, format=fmt, output_path=output_path,
            )

            console.print(f"[green]✓[/green] Exported {result['count']} events to {result['path']}")

        finally:
            await conn.close()

    run_sync(_run())
