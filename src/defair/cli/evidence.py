"""CLI commands for evidence management."""

from __future__ import annotations

import click
from rich.console import Console

from defair.database import get_initialized_connection, run_sync
from defair.services import evidence_service

console = Console()


@click.group("evidence")
def evidence_group() -> None:
    """Manage forensic evidence (add, list, verify)."""


@evidence_group.command("add")
@click.argument("case_id")
@click.argument("path", type=click.Path(exists=True))
@click.option("--type", "evidence_type", default="other",
              type=click.Choice(["disk_image", "memory_dump", "logs", "triage_archive", "pcap", "other"]),
              help="Type of evidence.")
@click.pass_context
def evidence_add(ctx: click.Context, case_id: str, path: str, evidence_type: str) -> None:
    """Register a new piece of evidence in a case.

    Computes SHA-256 hash and stores metadata. The original file is never modified.
    """
    db_path = ctx.obj["db_path"]

    console.print(f"[dim]Hashing {path}...[/dim]")

    async def _run() -> None:
        conn = await get_initialized_connection(db_path)
        try:
            evidence = await evidence_service.add_evidence(conn, case_id, path, evidence_type)
        finally:
            await conn.close()

        console.print(f"[green]✓[/green] Evidence registered: [cyan]{evidence.evidence_number}[/cyan]")
        console.print(f"  File:     {evidence.filename}")
        console.print(f"  Path:     {evidence.original_path}")
        console.print(f"  Type:     {evidence.type}")
        console.print(f"  Size:     {_format_size(evidence.size_bytes)}")
        console.print(f"  SHA-256:  {evidence.sha256}")
        console.print(f"  Case:     {case_id}")
        console.print(f"  ID:       {evidence.id}")

    run_sync(_run())


def _format_size(size_bytes: int | None) -> str:
    """Format file size in human-readable form."""
    if size_bytes is None:
        return "unknown"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"
