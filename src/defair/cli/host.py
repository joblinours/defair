"""CLI commands for the host profile (``defair host profile``)."""

from __future__ import annotations

import json

import click
from rich.console import Console
from rich.table import Table

from defair.cli.proxy import get_container_or_fail, proxy_command
from defair.database import get_initialized_connection, run_sync

console = Console()


@click.group("host")
def host_group() -> None:
    """Host profile of an evidence (hostname, OS, users, network, software)."""


@host_group.command("profile")
@click.option("--case", "case_id", required=True, help="Case number (CASE-YYYY-NNN), name or ID.")
@click.option("--evidence", "evidence_id", default=None, help="Evidence (default: the case's first).")
@click.option("--refresh", is_flag=True, help="Rebuild it now instead of showing the stored one.")
@click.option("--json", "as_json", is_flag=True, help="JSON output.")
@click.pass_context
def host_profile(ctx: click.Context, case_id: str, evidence_id: str | None, refresh: bool,
                 as_json: bool) -> None:
    """Show the host profile, each fact with its source."""
    container = get_container_or_fail(ctx)
    if container:
        cmd = ["host", "profile", "--case", case_id]
        if evidence_id:
            cmd.extend(["--evidence", evidence_id])
        if refresh:
            cmd.append("--refresh")
        if as_json:
            cmd.append("--json")
        return proxy_command(container, cmd)

    from defair.services import host_profile_service

    async def _run() -> None:
        conn = await get_initialized_connection(ctx.obj["db_path"])
        try:
            profile = await host_profile_service.get_host_profile(conn, case_id, evidence_id, refresh=refresh)
        except ValueError as e:
            console.print(f"[red]✗[/red] {e}")
            ctx.exit(1)
            return
        finally:
            await conn.close()
        if as_json:
            click.echo(json.dumps(profile, indent=2, default=str))
            return
        table = Table(title=f"Host profile — {profile.get('evidence')} ({profile.get('artifact')})")
        table.add_column("Field", style="cyan")
        table.add_column("Value", overflow="fold")
        table.add_column("Source", style="dim")
        for name, entry in profile["fields"].items():
            value = entry["value"]
            if isinstance(value, list):
                shown = ", ".join(str(v.get("name") or v.get("device") or v.get("computer") or v)
                                  if isinstance(v, dict) else str(v) for v in value[:15])
                value = f"{len(entry['value'])} — {shown}" + (" …" if len(entry["value"]) > 15 else "")
            table.add_row(name, str(value), ", ".join([entry["source"], *entry.get("also", [])]))
        console.print(table)
        for conflict in profile.get("conflicts", []):
            console.print(f"[yellow]⚠ {conflict['field']}[/yellow]: {conflict['value']!r} "
                          f"({conflict['source']}) ≠ kept {conflict['kept']!r} ({conflict['kept_source']})")

    run_sync(_run())
