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
@click.option("--case", "case_id", required=True, help="Case number (CASE-YYYY-NNN), name or ID.")
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
@click.option("--case", "case_id", default=None,
              help="Case (number, name or ID) the finding must belong to.")
@click.option("--all", "show_all", is_flag=True, help="Show every match, not only the first 10.")
@click.option("--json", "as_json", is_flag=True, help="JSON output (finding + every match).")
@click.pass_context
def findings_get(ctx: click.Context, finding_id: str, case_id: str | None, show_all: bool,
                 as_json: bool) -> None:
    """Show a finding: rule, rule file, and for every match the evidence file,
    event / offset and the exact pattern or field values that hit the rule."""
    container = get_container_or_fail(ctx)
    if container:
        cmd = ["findings", "get", finding_id]
        if case_id:
            cmd.extend(["--case", case_id])
        if show_all:
            cmd.append("--all")
        if as_json:
            cmd.append("--json")
        return proxy_command(container, cmd)

    from defair.services import finding_service

    async def _run() -> dict:
        conn = await get_initialized_connection(ctx.obj["db_path"])
        try:
            return await finding_service.get_finding_detail(
                conn, finding_id, case_id=case_id, limit=None if (show_all or as_json) else 10,
                raw=as_json,
            )
        finally:
            await conn.close()

    try:
        f = run_sync(_run())
    except ValueError as e:
        console.print(f"[red]✗[/red] {e}")
        raise SystemExit(1)
    if as_json:
        click.echo(json.dumps(f, indent=2, default=str))
        return
    _print_finding(f)


def _print_finding(f: dict) -> None:
    from rich.markup import escape

    sev = f.get("severity", "")
    sev_color = {"critical": "red", "high": "yellow", "medium": "blue"}.get(sev, "dim")
    console.print(f"\n[cyan bold]{f['finding_number']}[/cyan bold] — {escape(f['title'])}")
    console.print(f"  Severity:   [{sev_color}]{sev}[/{sev_color}]   Confidence: {f.get('confidence', '')}"
                  f"   Status: {f.get('status', '')}   Source: {f.get('source', '')}")
    console.print(f"  Created:    {f.get('created_at', '')}")
    if f.get("description"):
        console.print(f"\n  [bold]Description[/bold]\n  {escape(f['description'])}")
    if f.get("mitre_techniques") or f.get("mitre_tactics"):
        console.print(f"\n  [bold]MITRE[/bold] {', '.join(f.get('mitre_tactics', []) + f.get('mitre_techniques', []))}")

    for ref in f.get("detection_refs") or []:
        if not isinstance(ref, dict):
            console.print(f"\n  [bold]Rule[/bold] {escape(str(ref))}")
            continue
        origin = " · ".join(x for x in (ref.get("engine"), ref.get("source"),
                                         f"@ {ref['ref']}" if ref.get("ref") else None,
                                         ref.get("license")) if x)
        console.print(f"\n  [bold]Rule[/bold] {escape(ref.get('rule') or '')}  [dim]{escape(origin)}[/dim]")
        if ref.get("rule_id"):
            console.print(f"    id:     {ref['rule_id']}")
        if ref.get("rule_path"):
            console.print(f"    file:   {escape(ref['rule_path'])}")
            if ref.get("source") and ref.get("file"):
                console.print(f"    view:   defair rules show {ref['source']} '{escape(ref['file'])}'")
        if ref.get("reference"):
            console.print(f"    ref:    {escape(ref['reference'])}")

    total = f.get("matches_total", 0)
    shown = len(f.get("matches") or [])
    more = f" — showing {shown}, use --all" if shown < total else ""
    console.print(f"\n  [bold]Matches ({total}{more})[/bold]")
    for m in f.get("matches") or []:
        if m.get("error"):
            console.print(f"    {m.get('artifact_id')}: {m['error']}")
            continue
        head = "  ".join(x for x in (m.get("artifact"), m.get("timestamp"), m.get("hostname")) if x)
        console.print(f"\n    [cyan]{escape(head)}[/cyan]")
        path = m.get("evidence_path") or m.get("reported_path")
        if path:
            found = "" if m.get("evidence_path") else "  [yellow](not found in the container)[/yellow]"
            console.print(f"      file:    {escape(path)}{found}")
        if m.get("file_sha256"):
            console.print(f"      sha256:  {m['file_sha256']}")
        event = m.get("event") or {}
        if event:
            console.print("      event:   " + escape("  ".join(f"{k}={v}" for k, v in event.items()
                                                            if k not in ("Level", "RuleID"))))
        for field in m.get("matched_fields") or []:
            console.print(f"      matched: {escape(str(field))}")
        for pat in m.get("matched_patterns") or []:
            if "offset" in pat:
                console.print(f"      matched: {escape(pat['identifier'])} = {escape(pat['value'])} "
                              f"@ offset {pat['offset']} (0x{pat['offset']:x})")
            else:
                console.print(f"      matched: {escape(pat.get('raw', ''))}")
        if m.get("artifact"):
            console.print(f"      inspect: defair artifacts get {m['artifact']}")


@findings_group.command("create")
@click.option("--case", "case_id", required=True, help="Case number (CASE-YYYY-NNN), name or ID.")
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
