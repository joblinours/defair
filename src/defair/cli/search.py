"""CLI command for IOC search across artifacts."""

from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

from defair.cli.proxy import get_container_or_fail, proxy_command
from defair.database import get_initialized_connection, run_sync

console = Console()


@click.command("search")
@click.argument("value")
@click.option("--case", "case_id", required=True, help="Case ID or case number.")
@click.option("--limit", default=50, help="Max results.")
@click.pass_context
def search_cmd(ctx: click.Context, value: str, case_id: str, limit: int) -> None:
    """Search for an IOC across all artifacts in a case.

    Searches descriptions, data, hostnames, usernames, and filenames.

    Examples:
      defair search "powershell" --case CASE-2026-001
      defair search "192.168.1.100" --case CASE-2026-001
      defair search "SharpHound" --case CASE-2026-001
    """
    container = get_container_or_fail(ctx)
    if container:
        cmd = ["search", value, "--case", case_id, "--limit", str(limit)]
        return proxy_command(container, cmd)

    from defair.services import search_service
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

            result = await search_service.search_ioc(
                conn, case.id, value, limit=limit,
            )

            console.print(f"\n[bold]IOC Search:[/bold] {value}")
            console.print(f"  Matches: [cyan]{result['match_count']}[/cyan]")
            console.print(f"  Tools:   {', '.join(result['tools_matched']) or 'none'}")

            if result["matches"]:
                table = Table(title=f"Matches ({result['match_count']})")
                table.add_column("Timestamp", style="cyan", max_width=20)
                table.add_column("Type")
                table.add_column("Description", max_width=50)
                table.add_column("Tool")

                for m in result["matches"][:limit]:
                    table.add_row(
                        (m.get("timestamp") or "")[:19],
                        m.get("artifact_type", "").split(".")[-1],
                        (m.get("description") or "")[:50],
                        m.get("source_tool", ""),
                    )
                console.print(table)

        finally:
            await conn.close()

    run_sync(_run())
