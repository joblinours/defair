"""CLI commands for investigation findings."""

from __future__ import annotations

import json

import click
from rich.console import Console
from rich.table import Table

from defair.cli.proxy import get_container_or_fail, proxy_command
from defair.database import get_initialized_connection, run_sync

console = Console()


@click.group("findings")
def findings_group() -> None:
    """Manage investigation findings."""


@findings_group.command("list")
@click.option("--case", "case_id", required=True, help="Case ID or case number.")
@click.option("--severity", default=None, help="Filter by severity.")
@click.option("--status", default=None, help="Filter by status.")
@click.option("--limit", default=50, help="Max results.")
@click.pass_context
def findings_list(
    ctx: click.Context,
    case_id: str,
    severity: str | None,
    status: str | None,
    limit: int,
) -> None:
    """List findings for a case."""
    container = get_container_or_fail(ctx)
    if container:
        cmd = ["findings", "list", "--case", case_id, "--limit", str(limit)]
        if severity:
            cmd.extend(["--severity", severity])
        if status:
            cmd.extend(["--status", status])
        return proxy_command(container, cmd)

    from defair.services import finding_service
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

            results = await finding_service.list_findings(
                conn, case_id=case.id, severity=severity, status=status, limit=limit,
            )

            if not results:
                console.print("[dim]No findings found.[/dim]")
                return

            table = Table(title=f"Findings ({len(results)})")
            table.add_column("#", style="cyan")
            table.add_column("Severity")
            table.add_column("Status")
            table.add_column("Title", max_width=50)
            table.add_column("Source")
            table.add_column("Artifacts")

            for f in results:
                sev = f.get("severity", "")
                sev_color = {
                    "critical": "red", "high": "yellow",
                    "medium": "blue", "low": "dim",
                }.get(sev, "dim")
                art_ids = json.loads(f.get("artifact_ids", "[]"))
                table.add_row(
                    f["finding_number"],
                    f"[{sev_color}]{sev}[/{sev_color}]",
                    f.get("status", ""),
                    f.get("title", "")[:50],
                    f.get("source", ""),
                    str(len(art_ids)),
                )
            console.print(table)

        finally:
            await conn.close()

    run_sync(_run())


@findings_group.command("get")
@click.argument("finding_id")
@click.pass_context
def findings_get(ctx: click.Context, finding_id: str) -> None:
    """Show details of a specific finding."""
    container = get_container_or_fail(ctx)
    if container:
        return proxy_command(container, ["findings", "get", finding_id])

    from defair.services import finding_service

    async def _run() -> None:
        db_path = ctx.obj["db_path"]
        conn = await get_initialized_connection(db_path)
        try:
            f = await finding_service.get_finding(conn, finding_id)
            if f is None:
                console.print(f"[red]✗[/red] Finding not found: {finding_id}")
                ctx.exit(1)
                return

            sev = f.get("severity", "")
            sev_color = {"critical": "red", "high": "yellow", "medium": "blue"}.get(sev, "dim")

            console.print(f"\n[cyan bold]{f['finding_number']}[/cyan bold] — {f['title']}")
            console.print(f"  Severity:   [{sev_color}]{sev}[/{sev_color}]")
            console.print(f"  Confidence: {f.get('confidence', '')}")
            console.print(f"  Status:     {f.get('status', '')}")
            console.print(f"  Source:     {f.get('source', '')}")
            console.print(f"  Created:    {f.get('created_at', '')}")

            if f.get("description"):
                console.print(f"\n  [bold]Description:[/bold]\n  {f['description']}")

            mitre_tactics = json.loads(f.get("mitre_tactics", "[]"))
            if mitre_tactics:
                console.print(f"\n  [bold]MITRE Tactics:[/bold] {', '.join(mitre_tactics)}")

            mitre_techniques = json.loads(f.get("mitre_techniques", "[]"))
            if mitre_techniques:
                console.print(f"  [bold]MITRE Techniques:[/bold] {', '.join(mitre_techniques)}")

            art_ids = json.loads(f.get("artifact_ids", "[]"))
            if art_ids:
                console.print(f"\n  [bold]Linked Artifacts:[/bold] {len(art_ids)}")
                for aid in art_ids[:10]:
                    console.print(f"    • {aid}")
                if len(art_ids) > 10:
                    console.print(f"    ... and {len(art_ids) - 10} more")

            det_refs = json.loads(f.get("detection_refs", "[]"))
            if det_refs:
                console.print("\n  [bold]Detection Rules:[/bold]")
                for ref in det_refs[:5]:
                    console.print(f"    • {ref}")

        finally:
            await conn.close()

    run_sync(_run())


@findings_group.command("create")
@click.option("--case", "case_id", required=True, help="Case ID or case number.")
@click.option("--title", required=True, help="Finding title.")
@click.option("--description", default="", help="Finding description.")
@click.option(
    "--severity", default="medium",
    type=click.Choice(["informational", "low", "medium", "high", "critical"]),
)
@click.pass_context
def findings_create(
    ctx: click.Context,
    case_id: str,
    title: str,
    description: str,
    severity: str,
) -> None:
    """Manually create a finding."""
    container = get_container_or_fail(ctx)
    if container:
        cmd = [
            "findings", "create",
            "--case", case_id,
            "--title", title,
            "--severity", severity,
        ]
        if description:
            cmd.extend(["--description", description])
        return proxy_command(container, cmd)

    from defair.services import finding_service
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

            result = await finding_service.create_finding(
                conn,
                case_id=case.id,
                title=title,
                description=description,
                severity=severity,
                source="manual",
            )

            console.print(
                f"[green]✓[/green] Finding created: "
                f"[cyan]{result['finding_number']}[/cyan] — {title}"
            )

        finally:
            await conn.close()

    run_sync(_run())
