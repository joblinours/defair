"""CLI commands for tool management and analysis."""

from __future__ import annotations

import json

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
        source = result.get("source") or {}
        console.print(f"  Source:    [cyan]{source.get('kind', 'unknown')}[/cyan]"
                      + (f" (needs: {', '.join(source['needs'])})" if source.get("needs") else ""))
        if source.get("root"):
            console.print(f"  Root:      {source['root']}")
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
@click.option("--case", "case_id", required=True, help="Case number (CASE-YYYY-NNN), name or ID.")
@click.option("--evidence", "evidence_id", default=None, help="Evidence ID.")
@click.option("--output", "output_dir", default="/workspace/analysis", help="Output directory.")
@click.option("--directory", is_flag=True, help="Input is a directory.")
@click.option("--normalize", is_flag=True, default=True, help="Normalize outputs to artifacts.")
@click.option(
    "--no-logs/--with-logs", "no_logs", default=True,
    help="Skip transaction log replay (--nl). Default: skip. Use --with-logs on dirty hives for complete data.",
)
@click.option(
    "--option", "-O", "options", multiple=True,
    help="Tool option as key=value (must be declared in the tool manifest).",
)
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
    no_logs: bool,
    options: tuple[str, ...],
) -> None:
    """Run a forensic tool against evidence.

    Examples:
      defair analyze mftecmd /evidence/$MFT --case CASE-2026-001
      defair analyze evtxecmd /evidence/logs/ --case CASE-2026-001 --directory
      defair analyze recmd /evidence/NTUSER.DAT --case CASE-2026-001 --with-logs
      defair analyze hayabusa /evidence/logs --case CASE-2026-001 -O min_level=high
    """
    from defair.services.analysis_service import parse_option_pairs, validate_tool_request

    try:
        tool_options = validate_tool_request(
            tool_name, input_path, parse_option_pairs(options), strict_paths=False,
        )
    except ValueError as e:
        console.print(f"[red]✗[/red] {e}")
        raise SystemExit(2)

    container = get_container_or_fail(ctx)
    if container:
        cmd = ["analyze", tool_name, input_path, "--case", case_id]
        if evidence_id:
            cmd.extend(["--evidence", evidence_id])
        if output_dir != "/workspace/analysis":
            cmd.extend(["--output", output_dir])
        if directory:
            cmd.append("--directory")
        if not no_logs:
            cmd.append("--with-logs")
        for opt in options:
            cmd.extend(["--option", opt])
        return proxy_command(container, cmd)

    from defair.services import analysis_service
    from defair.services.case_service import get_case
    from defair.services.evidence_service import get_evidence as get_ev

    async def _run() -> None:
        db_path = ctx.obj["db_path"]
        conn = await get_initialized_connection(db_path)
        try:
            # Resolve case_number (CASE-YYYY-NNN) to case UUID
            resolved_case_id = case_id
            case = await get_case(conn, case_id)
            if case is None:
                console.print(f"[red]✗[/red] Case not found: {case_id}")
                ctx.exit(1)
                return
            resolved_case_id = case.id

            # Resolve evidence_number (EVD-NNN) to evidence UUID
            resolved_evidence_id = evidence_id
            if evidence_id:
                ev = await get_ev(conn, evidence_id)
                if ev is None:
                    console.print(f"[red]✗[/red] Evidence not found: {evidence_id}")
                    ctx.exit(1)
                    return
                resolved_evidence_id = ev.id

            kwargs = dict(tool_options)
            if directory:
                kwargs["directory"] = True
            kwargs["no_logs"] = no_logs

            if normalize:
                result = await analysis_service.run_tool_and_normalize(
                    conn, tool_name, input_path, resolved_case_id,
                    evidence_id=resolved_evidence_id,
                    output_base=output_dir,
                    **kwargs,
                )
            else:
                tool_run = await analysis_service.run_tool(
                    conn, tool_name, input_path, resolved_case_id,
                    evidence_id=resolved_evidence_id,
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
@click.option("--case", "case_id", default=None, help="Filter by case (number, name or ID).")
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
@click.option("--case", "case_id", default=None, help="Filter by case (number, name or ID).")
@click.option("--type", "artifact_type", default=None, help="Artifact type (substring, e.g. evtx.logon).")
@click.option("--category", default=None, help="SANS category (program_execution, persistence…).")
@click.option("--tool", default=None, help="Source tool (evtxecmd, mftecmd, raijin…).")
@click.option("--contains", default=None, help="Text in description, message, path or any data field.")
@click.option("--host", "hostname", default=None, help="Hostname (substring).")
@click.option("--user", "username", default=None, help="Username (substring).")
@click.option("--severity", default=None, help="Severity.")
@click.option("--since", default=None, help="From this time (ISO, e.g. 2024-12-01T10:00).")
@click.option("--until", default=None, help="Until this time (ISO).")
@click.option("--run", default=None, help="Produced by this tool run (RUN-NNN).")
@click.option("--asc", "ascending", is_flag=True, help="Oldest first (default: newest first).")
@click.option("--limit", default=50, help="Max results.")
@click.option("--offset", default=0, help="Skip this many results (paging).")
@click.option("--json", "as_json", is_flag=True, help="JSON output (full data).")
@click.pass_context
def artifacts_list(ctx: click.Context, case_id, artifact_type, category, tool, contains, hostname,
                   username, severity, since, until, run, ascending, limit, offset, as_json) -> None:
    """List / search normalized artifacts (see `artifacts get ART-NNN` for one)."""
    filters = {"case_id": case_id, "artifact_type": artifact_type, "category": category,
               "tool": tool, "contains": contains, "hostname": hostname, "username": username,
               "severity": severity, "since": since, "until": until, "run": run}
    container = get_container_or_fail(ctx)
    if container:
        flags = {"case_id": "--case", "artifact_type": "--type", "category": "--category",
                 "tool": "--tool", "contains": "--contains", "hostname": "--host",
                 "username": "--user", "severity": "--severity", "since": "--since",
                 "until": "--until", "run": "--run"}
        cmd = ["artifacts", "list"]
        for key, value in filters.items():
            if value:
                cmd.extend([flags[key], value])
        cmd.extend(["--limit", str(limit), "--offset", str(offset)])
        if ascending:
            cmd.append("--asc")
        if as_json:
            cmd.append("--json")
        return proxy_command(container, cmd)

    from rich.markup import escape

    from defair.services import artifact_service

    async def _run() -> dict:
        conn = await get_initialized_connection(ctx.obj["db_path"])
        try:
            return await artifact_service.search_artifacts(
                conn, order="asc" if ascending else "desc", limit=limit, offset=offset, **filters)
        finally:
            await conn.close()

    try:
        result = run_sync(_run())
    except ValueError as e:
        console.print(f"[red]✗[/red] {e}")
        raise SystemExit(1)
    if as_json:
        click.echo(json.dumps(result, indent=2, default=str))
        return
    if not result["items"]:
        console.print("[yellow]No artifacts found.[/yellow]")
        return

    first, last = offset + 1, offset + len(result["items"])
    table = Table(title=f"Artifacts {first}-{last} of {result['total']}")
    table.add_column("#", style="cyan", no_wrap=True)
    table.add_column("Type")
    table.add_column("Timestamp", no_wrap=True)
    table.add_column("Host")
    table.add_column("Description")
    table.add_column("Tool")
    for a in result["items"]:
        table.add_row(
            a["artifact_number"],
            (a["artifact_type"] or "").removeprefix("windows."),
            (a.get("timestamp") or "")[:23],
            escape(a.get("hostname") or ""),
            escape((a.get("description") or "")[:80]),
            a.get("source_tool", ""),
        )
    console.print(table)
    if last < result["total"]:
        console.print(f"[dim]Next page: --offset {last}   ·   Details: defair artifacts get ART-NNN[/dim]")


@artifacts_group.command("get")
@click.argument("artifact")
@click.option("--case", "case_id", default=None, help="Case the artifact must belong to.")
@click.option("--context", "context_minutes", type=float, default=None,
              help="Also show the case timeline ± this many minutes around it.")
@click.option("--no-raw", is_flag=True, help="Do not read the raw source (EVTX event / hex dump).")
@click.option("--json", "as_json", is_flag=True, help="JSON output.")
@click.pass_context
def artifacts_get(ctx: click.Context, artifact: str, case_id: str | None,
                  context_minutes: float | None, no_raw: bool, as_json: bool) -> None:
    """Everything about one artifact (ART-NNN): all fields and data, provenance,
    tool run, findings, the evidence file, the full EVTX event or YARA hex
    context, and optionally the surrounding timeline."""
    container = get_container_or_fail(ctx)
    if container:
        cmd = ["artifacts", "get", artifact]
        if case_id:
            cmd.extend(["--case", case_id])
        if context_minutes:
            cmd.extend(["--context", str(context_minutes)])
        if no_raw:
            cmd.append("--no-raw")
        if as_json:
            cmd.append("--json")
        return proxy_command(container, cmd)

    from defair.services import artifact_service

    async def _run() -> dict:
        conn = await get_initialized_connection(ctx.obj["db_path"])
        try:
            return await artifact_service.get_artifact(
                conn, artifact, case_id=case_id, context_minutes=context_minutes, raw=not no_raw)
        finally:
            await conn.close()

    try:
        result = run_sync(_run())
    except ValueError as e:
        console.print(f"[red]✗[/red] {e}")
        raise SystemExit(1)
    if as_json:
        click.echo(json.dumps(result, indent=2, default=str))
        return
    _print_artifact(result)


def _print_artifact(result: dict) -> None:
    from rich.markup import escape

    a = result["artifact"]
    console.print(f"\n[cyan bold]{a['artifact_number']}[/cyan bold] — {escape(a['artifact_type'])}"
                  f"  [dim]({a.get('category')})[/dim]")
    rows = [
        ("Timestamp", " ".join(x for x in (a.get("timestamp"), f"({a['timestamp_desc']})" if a.get("timestamp_desc") else None) if x)),
        ("Host", a.get("hostname")), ("User", a.get("username")), ("Severity", a.get("severity")),
        ("Tool", a.get("source_tool")), ("Source", a.get("source_file")),
        ("Description", a.get("description")), ("Message", a.get("message") if a.get("message") != a.get("description") else None),
        ("Tags", ", ".join(a.get("tags") or [])),
    ]
    for label, value in rows:
        if value:
            console.print(f"  {label + ':':<13}{escape(str(value))}")

    run = result.get("tool_run")
    if run:
        console.print(f"\n  [bold]Produced by[/bold] {run['run_number']} {run['tool_name']} "
                      f"{run.get('tool_version') or ''} ({run.get('status')})")
        if run.get("input_path"):
            console.print(f"    input:  {escape(run['input_path'])}")
        console.print(f"    output: {escape(run.get('output_path') or '')}")
    if result.get("normalized_file"):
        console.print(f"    jsonl:  {escape(result['normalized_file']['path'])}")
    for f in result.get("findings") or []:
        console.print(f"  [bold]Finding[/bold] {f['finding_number']} [{f['severity']}] {escape(f['title'])}")

    match = result.get("match")
    if match:
        console.print("\n  [bold]Detection[/bold]")
        for key in ("engine", "rule", "rule_file", "evidence_path", "reported_path", "file_sha256"):
            if match.get(key):
                console.print(f"    {key + ':':<15}{escape(str(match[key]))}")
        if match.get("event"):
            console.print("    event:         " + escape("  ".join(f"{k}={v}" for k, v in match["event"].items())))
        for field in match.get("matched_fields") or []:
            console.print(f"    matched:       {escape(str(field))}")
        for pat in match.get("matched_patterns") or []:
            if "offset" in pat:
                console.print(f"    matched:       {escape(pat['identifier'])} = {escape(pat['value'])} @ {pat['offset']} (0x{pat['offset']:x})")

    console.print("\n  [bold]Data[/bold]")
    console.print(escape(json.dumps(a.get("data") or {}, indent=2, ensure_ascii=False, default=str)))

    raw = result.get("raw") or {}
    if raw.get("evtx_event"):
        event = raw["evtx_event"]
        console.print(f"\n  [bold]Full EVTX event[/bold] (record {event['record_id']}, {event.get('timestamp')})")
        for key, value in event["fields"].items():
            console.print(f"    {escape(str(key)):<24} {escape(str(value))}")
    for dump in raw.get("hex_context") or []:
        console.print(f"\n  [bold]Hex context[/bold] {escape(str(dump.get('identifier', '')))} @ {dump['offset']} (match in [..])")
        for line in dump.get("hex") or []:
            console.print(f"    {escape(line)}")
    if raw.get("error"):
        console.print(f"\n  [yellow]{escape(raw['error'])}[/yellow]")

    if result.get("context"):
        console.print("\n  [bold]Timeline context[/bold]")
        for c in result["context"]:
            mark = "→" if c["artifact_number"] == a["artifact_number"] else " "
            console.print(f"  {mark} {c['artifact_number']:<11}{(c.get('timestamp') or '')[:23]:<24}"
                          f"{(c.get('artifact_type') or '').removeprefix('windows.'):<32}"
                          f"{escape((c.get('description') or '')[:60])}")
