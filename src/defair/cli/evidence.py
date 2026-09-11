"""CLI commands for evidence management."""

from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

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


@evidence_group.command("list")
@click.option("--case", "case_id", default=None, help="Filter by case ID or case number.")
@click.pass_context
def evidence_list(ctx: click.Context, case_id: str | None) -> None:
    """List registered evidence items."""
    db_path = ctx.obj["db_path"]

    async def _run() -> None:
        conn = await get_initialized_connection(db_path)
        try:
            items = await evidence_service.list_evidence(conn, case_id)
        finally:
            await conn.close()

        if not items:
            console.print("[dim]No evidence registered.[/dim]")
            return

        table = Table(title="Evidence")
        table.add_column("Evidence #", style="cyan")
        table.add_column("Filename")
        table.add_column("Type")
        table.add_column("Size")
        table.add_column("SHA-256", max_width=16)
        table.add_column("Case ID", max_width=16)

        for e in items:
            table.add_row(
                e.evidence_number,
                e.filename,
                e.type.value,
                _format_size(e.size_bytes),
                (e.sha256 or "")[:16] + "…" if e.sha256 and len(e.sha256) > 16 else (e.sha256 or ""),
                e.case_id[:16] + "…",
            )

        console.print(table)

    run_sync(_run())


@evidence_group.command("get")
@click.argument("evidence_id")
@click.pass_context
def evidence_get(ctx: click.Context, evidence_id: str) -> None:
    """Get details of a specific evidence item by ID or evidence number."""
    db_path = ctx.obj["db_path"]

    async def _run() -> None:
        conn = await get_initialized_connection(db_path)
        try:
            evidence = await evidence_service.get_evidence(conn, evidence_id)
        finally:
            await conn.close()

        if evidence is None:
            console.print(f"[red]Evidence not found:[/red] {evidence_id}")
            raise SystemExit(1)

        console.print(f"[cyan]{evidence.evidence_number}[/cyan]")
        console.print(f"  ID:       {evidence.id}")
        console.print(f"  File:     {evidence.filename}")
        console.print(f"  Path:     {evidence.original_path}")
        console.print(f"  Type:     {evidence.type.value}")
        console.print(f"  Size:     {_format_size(evidence.size_bytes)}")
        console.print(f"  SHA-256:  {evidence.sha256}")
        console.print(f"  Case:     {evidence.case_id}")
        console.print(f"  Added:    {evidence.registered_at.isoformat()}")

    run_sync(_run())


@evidence_group.command("verify")
@click.argument("evidence_id")
@click.pass_context
def evidence_verify(ctx: click.Context, evidence_id: str) -> None:
    """Verify evidence integrity by re-computing SHA-256.

    Compares the current file hash against the stored hash from registration.
    """
    db_path = ctx.obj["db_path"]

    async def _run() -> None:
        conn = await get_initialized_connection(db_path)
        try:
            result = await evidence_service.verify_evidence(conn, evidence_id)
        finally:
            await conn.close()

        status = result["status"]
        if status == "ok":
            console.print(f"[green]✓ VERIFIED[/green] — {result['evidence_number']} ({result['filename']})")
            console.print(f"  SHA-256: {result['original_sha256']}")
        elif status == "missing":
            console.print(f"[red]✗ FILE MISSING[/red] — {result['evidence_number']} ({result['filename']})")
            console.print(f"  Expected at: {result.get('message', '')}")
        elif status == "mismatch":
            console.print(f"[red]✗ INTEGRITY FAILURE[/red] — {result['evidence_number']} ({result['filename']})")
            console.print(f"  Original SHA-256:  {result['original_sha256']}")
            console.print(f"  Current SHA-256:   {result['current_sha256']}")
            console.print("[red bold]  ⚠ Evidence has been modified![/red bold]")

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
