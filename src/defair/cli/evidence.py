"""CLI commands for evidence management."""

from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

from defair.cli.proxy import get_container_or_fail, proxy_command
from defair.database import get_initialized_connection, run_sync
from defair.services import evidence_service

console = Console()


@click.group("evidence")
def evidence_group() -> None:
    """Manage forensic evidence (add, list, verify)."""


@evidence_group.command("add")
@click.argument("case_id")
@click.argument("path")
@click.option("--type", "evidence_type", default="other",
              type=click.Choice(["disk_image", "memory_dump", "logs", "triage_archive", "collection",
                                 "pcap", "other"]),
              help="Type of evidence.")
@click.pass_context
def evidence_add(ctx: click.Context, case_id: str, path: str, evidence_type: str) -> None:
    """Register a new piece of evidence in a case.

    PATH is a file or a collection folder inside the container (e.g.
    /evidence/disk.E01, /evidence/kape_output). Files are SHA-256 hashed,
    folders get a tree hash. The source format is detected. The original is
    never modified.
    """
    container = get_container_or_fail(ctx)
    if container:
        cmd = ["evidence", "add", case_id, path, "--type", evidence_type]
        return proxy_command(container, cmd)

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
        console.print(f"  Source:   {evidence.source_kind}")
        needs = evidence.source_info.get("needs") or []
        if needs:
            console.print(f"  [yellow]Needs:    {', '.join(needs)} (see `defair evidence prepare`)[/yellow]")
        console.print(f"  Case:     {case_id}")
        console.print(f"  ID:       {evidence.id}")

    run_sync(_run())


@evidence_group.command("list")
@click.option("--case", "case_id", default=None, help="Filter by case ID or case number.")
@click.pass_context
def evidence_list(ctx: click.Context, case_id: str | None) -> None:
    """List registered evidence items."""
    container = get_container_or_fail(ctx)
    if container:
        cmd = ["evidence", "list"]
        if case_id:
            cmd.extend(["--case", case_id])
        return proxy_command(container, cmd)

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
    container = get_container_or_fail(ctx)
    if container:
        return proxy_command(container, ["evidence", "get", evidence_id])

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
    container = get_container_or_fail(ctx)
    if container:
        return proxy_command(container, ["evidence", "verify", evidence_id])

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


PASSWORD_ENV = "DEFAIR_EVIDENCE_PASSWORD"
PASSPHRASE_ENV = "DEFAIR_KEY_PASSPHRASE"


@evidence_group.command("prepare")
@click.argument("evidence_id")
@click.option("--password", envvar=PASSWORD_ENV, default=None,
              help=f"Archive password (or ${PASSWORD_ENV}).")
@click.option("--private-key", default=None,
              help="PEM private key for DFIR-ORC / Generaptor (e.g. /keys/orc.pem).")
@click.option("--passphrase", envvar=PASSPHRASE_ENV, default=None,
              help=f"Private key passphrase (or ${PASSPHRASE_ENV}).")
@click.option("--force", is_flag=True, help="Prepare again even if already prepared.")
@click.option("--json", "as_json", is_flag=True, help="JSON output.")
@click.pass_context
def evidence_prepare(
    ctx: click.Context,
    evidence_id: str,
    password: str | None,
    private_key: str | None,
    passphrase: str | None,
    force: bool,
    as_json: bool,
) -> None:
    """Make evidence usable by the tools.

    Collections on disk are used in place; archives are extracted, DFIR-ORC /
    Generaptor collections decrypted, disk images carved with Dissect — into
    /workspace/sources/EVD-NNN/ with a manifest of every derived file.
    Secrets are never stored, logged or passed on a command line.
    """
    container = get_container_or_fail(ctx)
    if container:
        cmd = ["evidence", "prepare", evidence_id]
        if private_key:
            cmd.extend(["--private-key", private_key])
        if force:
            cmd.append("--force")
        if as_json:
            cmd.append("--json")
        env = {k: v for k, v in ((PASSWORD_ENV, password), (PASSPHRASE_ENV, passphrase)) if v}
        return proxy_command(container, cmd, env=env)

    import json

    from defair.config import ExtractionConfig
    from defair.sources.archives import ExtractionLimits
    from defair.sources.prepare import PreparationError, Secrets, prepare_evidence

    config = ctx.obj["config"]
    extraction = getattr(config, "extraction", ExtractionConfig())

    async def _run() -> None:
        conn = await get_initialized_connection(ctx.obj["db_path"])
        try:
            prepared = await prepare_evidence(
                conn, evidence_id,
                Secrets(password=password, private_key=private_key, passphrase=passphrase),
                limits=ExtractionLimits(extraction.max_bytes, extraction.max_files),
                force=force,
            )
        except (PreparationError, FileNotFoundError) as e:
            console.print(f"[red]✗[/red] {e}")
            raise SystemExit(1)
        finally:
            await conn.close()

        if as_json:
            click.echo(json.dumps(prepared, indent=2, default=str))
            return
        console.print(f"[green]✓[/green] Evidence prepared: [cyan]{prepared['evidence_number']}[/cyan]")
        console.print(f"  Source:    {prepared['source']['kind']} → {prepared['kind']}")
        console.print(f"  Platform:  {prepared['platform']}")
        console.print(f"  Root:      {prepared.get('root') or prepared['base']}")
        if prepared.get("derived"):
            console.print(f"  Derived:   {prepared['derived_files']} files (manifest: {prepared.get('manifest')})")
        if prepared.get("host", {}).get("hostname"):
            console.print(f"  Hostname:  {prepared['host']['hostname']}")
        for selector, paths in sorted(prepared["selectors"].items()):
            if selector != "root":
                console.print(f"  {selector:14} {len(paths)} location(s)")

    run_sync(_run())
