"""CLI command for threat hunting (Hayabusa, or Chainsaw with the pinned Sigma store)."""

from __future__ import annotations

import click
from rich.console import Console

from defair.cli.proxy import get_container_or_fail, proxy_command
from defair.database import get_initialized_connection, run_sync

console = Console()


@click.command("hunt")
@click.argument("input_path")
@click.option("--case", "case_id", required=True, help="Case number (CASE-YYYY-NNN), name or ID.")
@click.option("--evidence", "evidence_id", default=None, help="Evidence ID.")
@click.option(
    "--profile", default="standard",
    type=click.Choice(["minimal", "standard", "verbose", "all-field-info", "super-verbose"]),
    help="Hayabusa output profile.",
)
@click.option("--output", "output_dir", default="/workspace/analysis", help="Output directory.")
@click.option("--engine", default="hayabusa", type=click.Choice(["hayabusa", "chainsaw"]),
              help="Hunting engine (chainsaw uses the pinned DEFAIR Sigma store).")
@click.option("--rule-profile", default="precise", type=click.Choice(["precise", "broad"]),
              help="Chainsaw: rule profile of the pinned store.")
@click.option("--min-severity", default="medium",
              type=click.Choice(["informational", "low", "medium", "high", "critical"]),
              help="Chainsaw: lowest severity that becomes a finding.")
@click.pass_context
def hunt_cmd(
    ctx: click.Context,
    input_path: str,
    case_id: str,
    evidence_id: str | None,
    profile: str,
    output_dir: str,
    engine: str,
    rule_profile: str,
    min_severity: str,
) -> None:
    """Hunt for threats in EVTX evidence using Hayabusa + Sigma rules.

    Runs Hayabusa detection, normalizes results, and auto-creates
    findings from high/critical alerts.

    Examples:
      defair hunt /evidence/logs/ --case CASE-2026-001
      defair hunt /evidence/logs/ --case CASE-2026-001 --profile verbose
      defair hunt /evidence/logs/ --case CASE-2026-001 --engine chainsaw --rule-profile broad
    """
    container = get_container_or_fail(ctx)
    if container:
        cmd = ["hunt", input_path, "--case", case_id, "--profile", profile]
        if engine != "hayabusa":
            cmd.extend(["--engine", engine, "--rule-profile", rule_profile,
                        "--min-severity", min_severity])
        if evidence_id:
            cmd.extend(["--evidence", evidence_id])
        if output_dir != "/workspace/analysis":
            cmd.extend(["--output", output_dir])
        return proxy_command(container, cmd)

    from defair.services import hunting_service
    from defair.services.case_service import get_case
    from defair.services.evidence_service import get_evidence as get_ev

    async def _run() -> None:
        db_path = ctx.obj["db_path"]
        conn = await get_initialized_connection(db_path)
        try:
            # Resolve case
            case = await get_case(conn, case_id)
            if case is None:
                console.print(f"[red]✗[/red] Case not found: {case_id}")
                ctx.exit(1)
                return
            resolved_case_id = case.id

            # Resolve evidence
            resolved_evidence_id = evidence_id
            if evidence_id:
                ev = await get_ev(conn, evidence_id)
                if ev is None:
                    console.print(f"[red]✗[/red] Evidence not found: {evidence_id}")
                    ctx.exit(1)
                    return
                resolved_evidence_id = ev.id

            result = await hunting_service.hunt_evtx(
                conn,
                input_path=input_path,
                case_id=resolved_case_id,
                evidence_id=resolved_evidence_id,
                profile=profile,
                output_base=output_dir,
                engine=engine,
                rule_profile=rule_profile,
                min_severity=min_severity,
            )

            # Display results
            status = result.get("status", "unknown")
            if status == "completed":
                console.print(f"[green]✓[/green] Hunt completed: [cyan]{result['run_number']}[/cyan]")
            else:
                console.print(f"[red]✗[/red] Hunt {status}: [cyan]{result.get('run_number', 'N/A')}[/cyan]")

            console.print(f"  Duration:   {result.get('duration_seconds', 0):.1f}s")
            console.print(f"  Detections: {result.get('artifacts_produced', 0)}")
            console.print(f"  Findings:   {result.get('findings_created', 0)}")

            if result.get("findings"):
                console.print("\n[bold]Findings:[/bold]")
                for f in result["findings"]:
                    sev = f.get("severity", "?")
                    sev_color = {"critical": "red", "high": "yellow"}.get(sev, "dim")
                    console.print(
                        f"  [{sev_color}]{sev.upper()}[/{sev_color}] "
                        f"[cyan]{f['finding_number']}[/cyan] — {f['title']}"
                    )

        finally:
            await conn.close()

    run_sync(_run())
