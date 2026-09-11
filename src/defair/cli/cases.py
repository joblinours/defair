"""CLI commands for case management."""

from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

from defair.database import get_initialized_connection, run_sync
from defair.services import case_service

console = Console()


@click.group("cases")
def cases_group() -> None:
    """Manage forensic cases (list, search)."""


@cases_group.command("list")
@click.pass_context
def cases_list(ctx: click.Context) -> None:
    """List all forensic cases."""
    db_path = ctx.obj["db_path"]

    async def _run() -> None:
        conn = await get_initialized_connection(db_path)
        try:
            cases = await case_service.list_cases(conn)
        finally:
            await conn.close()

        if not cases:
            console.print("[dim]No cases found.[/dim]")
            return

        table = Table(title="Cases")
        table.add_column("Case #", style="cyan", no_wrap=True)
        table.add_column("Name", style="bold")
        table.add_column("Status")
        table.add_column("Created")
        table.add_column("Description", max_width=40)

        for c in cases:
            status_style = "green" if c.status == "active" else "dim"
            table.add_row(
                c.case_number,
                c.name,
                f"[{status_style}]{c.status}[/{status_style}]",
                c.created_at.strftime("%Y-%m-%d %H:%M"),
                c.description[:40] if c.description else "",
            )
        console.print(table)

    run_sync(_run())


@click.group("case")
def case_group() -> None:
    """Manage a single forensic case (create, get)."""


@case_group.command("create")
@click.argument("name")
@click.option("--description", "-d", default="", help="Case description.")
@click.pass_context
def case_create(ctx: click.Context, name: str, description: str) -> None:
    """Create a new forensic case."""
    db_path = ctx.obj["db_path"]

    async def _run() -> None:
        conn = await get_initialized_connection(db_path)
        try:
            case = await case_service.create_case(conn, name, description)
        finally:
            await conn.close()

        console.print(f"[green]✓[/green] Case created: [cyan]{case.case_number}[/cyan]")
        console.print(f"  Name:    {case.name}")
        console.print(f"  ID:      {case.id}")
        console.print(f"  Status:  {case.status}")
        console.print(f"  Created: {case.created_at.strftime('%Y-%m-%d %H:%M UTC')}")

    run_sync(_run())


@case_group.command("get")
@click.argument("case_id")
@click.pass_context
def case_get(ctx: click.Context, case_id: str) -> None:
    """Get details of a specific case (by ID or case number)."""
    db_path = ctx.obj["db_path"]

    async def _run() -> None:
        conn = await get_initialized_connection(db_path)
        try:
            case = await case_service.get_case(conn, case_id)
        finally:
            await conn.close()

        if case is None:
            console.print(f"[red]✗[/red] Case not found: {case_id}")
            raise SystemExit(1)

        console.print(f"[cyan]{case.case_number}[/cyan] — {case.name}")
        console.print(f"  ID:          {case.id}")
        console.print(f"  Status:      {case.status}")
        console.print(f"  Description: {case.description or '(none)'}")
        console.print(f"  Created:     {case.created_at.strftime('%Y-%m-%d %H:%M UTC')}")
        console.print(f"  Updated:     {case.updated_at.strftime('%Y-%m-%d %H:%M UTC')}")

    run_sync(_run())
