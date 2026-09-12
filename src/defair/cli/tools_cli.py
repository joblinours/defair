"""CLI commands for tool management and analysis."""

from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

from defair.cli.proxy import get_container_or_fail, proxy_command
from defair.database import get_initialized_connection, run_sync

console = Console()


@click.group("tools")
def tools_group() -> None:
    """Manage forensic tools (list, health check)."""


@tools_group.command("list")
@click.option("--available-only", is_flag=True, help="Show only available tools.")
@click.pass_context
def tools_list(ctx: click.Context, available_only: bool) -> None:
    """List all registered forensic tools."""
    container = get_container_or_fail(ctx)
    if container:
        cmd = ["tools", "list"]
        if available_only:
            cmd.append("--available-only")
        return proxy_command(container, cmd)

    from defair.tools.registry import get_default_registry

    registry = get_default_registry()
    manifests = registry.list_available() if available_only else registry.list_all()

    if not manifests:
        console.print("[dim]No tools registered.[/dim]")
        return

    table = Table(title="Forensic Tools")
    table.add_column("Name", style="cyan")
    table.add_column("Display Name", style="bold")
    table.add_column("Category")
    table.add_column("Status")
    table.add_column("SANS Categories", max_width=30)

    for m in manifests:
        # Check availability
        tool = registry.get(m.name)
        avail = tool.is_available() if tool else False
        status_str = "[green]✓ available[/green]" if avail else "[red]✗ missing[/red]"

        table.add_row(
            m.name,
            m.display_name,
            m.category.value,
            status_str,
            ", ".join(m.sans_categories[:3]) if m.sans_categories else "-",
        )

    console.print(table)


@tools_group.command("info")
@click.argument("tool_name")
@click.pass_context
def tools_info(ctx: click.Context, tool_name: str) -> None:
    """Show detailed information about a specific tool."""
    container = get_container_or_fail(ctx)
    if container:
        return proxy_command(container, ["tools", "info", tool_name])

    from defair.tools.registry import get_default_registry

    registry = get_default_registry()
    tool = registry.get(tool_name)

    if tool is None:
        console.print(f"[red]✗[/red] Unknown tool: {tool_name}")
        raise SystemExit(1)

    m = tool.manifest()
    avail = tool.is_available()

    console.print(f"[cyan bold]{m.display_name}[/cyan bold] ({m.name})")
    console.print(f"  Vendor:       {m.vendor}")
    console.print(f"  Description:  {m.description}")
    console.print(f"  Category:     {m.category.value}")
    console.print(f"  Runtime:      {m.runtime}")
    console.print(f"  Command:      {m.command}")
    console.print(f"  Available:    {'[green]yes[/green]' if avail else '[red]no[/red]'}")
    console.print(f"  Timeout:      {m.timeout}s")
    console.print(f"  Capabilities: {', '.join(m.capabilities)}")
    console.print(f"  Input types:  {', '.join(m.input_types)}")
    console.print(f"  Output:       {', '.join(m.output_formats)}")
    console.print(f"  Artifacts:    {', '.join(m.artifact_types)}")
    console.print(f"  SANS cats:    {', '.join(m.sans_categories)}")


@tools_group.command("health")
@click.pass_context
def tools_health(ctx: click.Context) -> None:
    """Check availability of all forensic tools."""
    container = get_container_or_fail(ctx)
    if container:
        return proxy_command(container, ["tools", "health"])

    from defair.tools.registry import get_default_registry

    registry = get_default_registry()
    health = registry.health_check()

    available = sum(1 for v in health.values() if v)
    total = len(health)

    console.print(f"\n[bold]Tool Health Check[/bold] — {available}/{total} available\n")

    for name, ok in sorted(health.items()):
        icon = "[green]✓[/green]" if ok else "[red]✗[/red]"
        console.print(f"  {icon} {name}")


# -----------------------------------------------------------------------
# Discover command
# -----------------------------------------------------------------------


@click.command("discover")
@click.argument("evidence_path")
@click.option("--no-recursive", is_flag=True, help="Don't search recursively.")
@click.pass_context
def discover_cmd(ctx: click.Context, evidence_path: str, no_recursive: bool) -> None:
    """Discover forensic artifacts in evidence.

    Scans the evidence path and identifies available artifacts,
    their types, and recommended tools.
    """
    container = get_container_or_fail(ctx)
    if container:
        cmd = ["discover", evidence_path]
        if no_recursive:
            cmd.append("--no-recursive")
        return proxy_command(container, cmd)

    from defair.services import discovery_service

    async def _run() -> None:
        result = await discovery_service.discover_artifacts(
            evidence_path, recursive=not no_recursive
        )

        console.print("\n[bold]Evidence Discovery[/bold]")
        console.print(f"  Path:      {result['evidence_path']}")
        console.print(f"  Platform:  [cyan]{result['platform']}[/cyan]")
        if result.get("hostname"):
            console.print(f"  Hostname:  {result['hostname']}")
        console.print(f"  Artifacts: {result['total_artifacts_found']}")

        if result["artifact_types"]:
            console.print("\n[bold]Artifact Types Found:[/bold]")
            table = Table()
            table.add_column("Type", style="cyan")
            table.add_column("Count")
            table.add_column("Recommended Tool")
            table.add_column("Description")

            for art_type, info in result["artifact_types"].items():
                table.add_row(
                    art_type,
                    str(info["count"]),
                    info.get("recommended_tool") or "-",
                    info.get("description", ""),
                )
            console.print(table)

        if result["recommended_tools"]:
            console.print("\n[bold]Recommended Analysis:[/bold]")
            for rec in result["recommended_tools"]:
                console.print(
                    f"  → [cyan]{rec['tool']}[/cyan] for {rec['artifact_type']} "
                    f"({rec['file_count']} files)"
                )

    run_sync(_run())


# -----------------------------------------------------------------------
# Analyze command
# -----------------------------------------------------------------------


@click.command("analyze")
@click.argument("tool_name")
@click.argument("input_path")
@click.option("--case", "case_id", required=True, help="Case ID.")
@click.option("--evidence", "evidence_id", default=None, help="Evidence ID.")
@click.option("--output", "output_dir", default="/workspace/analysis", help="Output directory.")
@click.option("--directory", is_flag=True, help="Input is a directory.")
@click.option("--normalize", is_flag=True, default=True, help="Normalize outputs to artifacts.")
@click.pass_context
def analyze_cmd(
    ctx: click.Context,
    tool_name: str,
    input_path: str,
    case_id: str,
    evidence_id: str | None,
    output_dir: str,
    directory: bool,
    normalize: bool,
) -> None:
    """Run a forensic tool against evidence.

    Examples:
      defair analyze mftecmd /evidence/$MFT --case CASE-2026-001
      defair analyze evtxecmd /evidence/logs/ --case CASE-2026-001 --directory
      defair analyze pecmd /evidence/Prefetch/ --case CASE-2026-001 --directory
    """
    container = get_container_or_fail(ctx)
    if container:
        cmd = ["analyze", tool_name, input_path, "--case", case_id]
        if evidence_id:
            cmd.extend(["--evidence", evidence_id])
        if output_dir != "/workspace/analysis":
            cmd.extend(["--output", output_dir])
        if directory:
            cmd.append("--directory")
        return proxy_command(container, cmd)

    from defair.services import analysis_service

    async def _run() -> None:
        db_path = ctx.obj["db_path"]
        conn = await get_initialized_connection(db_path)
        try:
            kwargs = {}
            if directory:
                kwargs["directory"] = True

            if normalize:
                result = await analysis_service.run_tool_and_normalize(
                    conn, tool_name, input_path, case_id,
                    evidence_id=evidence_id,
                    output_base=output_dir,
                    **kwargs,
                )
            else:
                tool_run = await analysis_service.run_tool(
                    conn, tool_name, input_path, case_id,
                    evidence_id=evidence_id,
                    output_base=output_dir,
                    **kwargs,
                )
                result = {
                    "run_number": tool_run.run_number,
                    "tool": tool_name,
                    "status": tool_run.status,
                    "exit_code": tool_run.exit_code,
                    "duration_seconds": tool_run.duration_seconds,
                    "output_files": len(tool_run.output_files),
                }

            # Display result
            status = result["status"]
            if status == "completed":
                console.print(f"[green]✓[/green] Analysis completed: [cyan]{result['run_number']}[/cyan]")
            else:
                console.print(f"[red]✗[/red] Analysis {status}: [cyan]{result['run_number']}[/cyan]")

            console.print(f"  Tool:      {result['tool']}")
            console.print(f"  Status:    {result['status']}")
            console.print(f"  Exit code: {result.get('exit_code', 'N/A')}")
            console.print(f"  Duration:  {result.get('duration_seconds', 0):.1f}s")
            console.print(f"  Outputs:   {result.get('output_files', 0)} files")
            if "artifacts_produced" in result:
                console.print(f"  Artifacts: {result['artifacts_produced']} normalized")

        finally:
            await conn.close()

    run_sync(_run())


# -----------------------------------------------------------------------
# Runs command (list tool runs)
# -----------------------------------------------------------------------


@click.group("runs")
def runs_group() -> None:
    """View analysis tool runs."""


@runs_group.command("list")
@click.option("--case", "case_id", default=None, help="Filter by case ID.")
@click.pass_context
def runs_list(ctx: click.Context, case_id: str | None) -> None:
    """List tool runs."""
    container = get_container_or_fail(ctx)
    if container:
        cmd = ["runs", "list"]
        if case_id:
            cmd.extend(["--case", case_id])
        return proxy_command(container, cmd)

    db_path = ctx.obj["db_path"]

    async def _run() -> None:
        conn = await get_initialized_connection(db_path)
        try:
            from defair.services import analysis_service
            runs = await analysis_service.list_tool_runs(conn, case_id)
        finally:
            await conn.close()

        if not runs:
            console.print("[dim]No tool runs found.[/dim]")
            return

        table = Table(title="Tool Runs")
        table.add_column("Run #", style="cyan")
        table.add_column("Tool")
        table.add_column("Status")
        table.add_column("Duration")
        table.add_column("Case", max_width=16)

        for r in runs:
            status_style = "green" if r["status"] == "completed" else "red"
            duration = f"{r['duration_seconds']:.1f}s" if r.get("duration_seconds") else "-"
            table.add_row(
                r["run_number"],
                r["tool_name"],
                f"[{status_style}]{r['status']}[/{status_style}]",
                duration,
                r["case_id"][:16],
            )
        console.print(table)

    run_sync(_run())


# -----------------------------------------------------------------------
# Artifacts command
# -----------------------------------------------------------------------


@click.group("artifacts")
def artifacts_group() -> None:
    """View normalized forensic artifacts."""


@artifacts_group.command("list")
@click.option("--case", "case_id", default=None, help="Filter by case ID.")
@click.option("--category", default=None, help="Filter by SANS category.")
@click.option("--type", "artifact_type", default=None, help="Filter by artifact type.")
@click.option("--limit", default=50, help="Max results.")
@click.pass_context
def artifacts_list(
    ctx: click.Context,
    case_id: str | None,
    category: str | None,
    artifact_type: str | None,
    limit: int,
) -> None:
    """List normalized artifacts."""
    container = get_container_or_fail(ctx)
    if container:
        cmd = ["artifacts", "list"]
        if case_id:
            cmd.extend(["--case", case_id])
        if category:
            cmd.extend(["--category", category])
        if artifact_type:
            cmd.extend(["--type", artifact_type])
        cmd.extend(["--limit", str(limit)])
        return proxy_command(container, cmd)

    db_path = ctx.obj["db_path"]

    async def _run() -> None:
        conn = await get_initialized_connection(db_path)
        try:
            from defair.services import analysis_service
            arts = await analysis_service.list_artifacts(
                conn, case_id=case_id, category=category,
                artifact_type=artifact_type, limit=limit,
            )
        finally:
            await conn.close()

        if not arts:
            console.print("[dim]No artifacts found.[/dim]")
            return

        table = Table(title=f"Artifacts ({len(arts)})")
        table.add_column("#", style="cyan")
        table.add_column("Type")
        table.add_column("Category")
        table.add_column("Timestamp")
        table.add_column("Description", max_width=40)
        table.add_column("Tool")

        for a in arts:
            table.add_row(
                a["artifact_number"],
                a["artifact_type"].split(".")[-1],
                a["category"],
                (a.get("timestamp") or "-")[:19],
                (a.get("description") or "")[:40],
                a.get("source_tool", ""),
            )
        console.print(table)

    run_sync(_run())
