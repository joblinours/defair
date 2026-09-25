"""CLI commands for container orchestration."""

from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

from defair.database import run_sync
from defair.services import container_service

console = Console()


@click.group("container")
def container_group() -> None:
    """Manage DEFAIR forensic containers."""


@container_group.command("create")
@click.option("--case", "case_id", default=None, help="Case ID/number to associate.")
@click.option("--name", default=None, help="Container name (auto-generated if omitted).")
@click.option("--image", default=container_service.DEFAULT_IMAGE, help="Docker image to use.")
@click.option("--evidence", "-e", multiple=True, help="Evidence path(s) to mount read-only.")
@click.option("--workspace", default=None, help="Custom workspace path.")
@click.option("--keys", "keys_path", default=None,
              help="Host directory of private keys (DFIR-ORC / Generaptor), mounted read-only at /keys.")
@click.option("--start/--no-start", default=True, help="Start container after creation.")
@click.pass_context
def container_create(
    ctx: click.Context,
    case_id: str | None,
    name: str | None,
    image: str,
    evidence: tuple[str, ...],
    workspace: str | None,
    keys_path: str | None,
    start: bool,
) -> None:
    """Create a new forensic container.

    One container per investigation — evidence is mounted read-only,
    workspace is persistent.
    """

    async def _run() -> None:
        try:
            info = await container_service.create_container(
                case_id=case_id,
                name=name,
                image=image,
                evidence_paths=list(evidence) if evidence else None,
                workspace=workspace,
                policy=ctx.obj["config"].container,
                keys_path=keys_path,
            )
        except ConnectionError as e:
            console.print(f"[red]✗ Docker error:[/red] {e}")
            raise SystemExit(1)
        except (FileNotFoundError, PermissionError, ValueError) as e:
            console.print(f"[red]✗[/red] {e}")
            raise SystemExit(1)

        console.print(f"[green]✓[/green] Container created: [cyan]{info.name}[/cyan]")
        console.print(f"  ID:        {info.container_id}")
        console.print(f"  Image:     {info.image}")
        console.print(f"  Status:    {info.status}")
        if info.case_id:
            console.print(f"  Case:      {info.case_id}")
        console.print(f"  Workspace: {info.workspace}")
        if info.evidence_mounts:
            console.print(f"  Evidence:  {', '.join(info.evidence_mounts)}")

        if start:
            started = await container_service.start_container(info.name)
            console.print(f"  [green]▶ Started[/green] ({started.status})")

    run_sync(_run())


@container_group.command("list")
@click.option("--all/--running", "all_states", default=True, help="Show all or only running.")
@click.option("--case", "case_id", default=None, help="Filter by case ID/number.")
def container_list(all_states: bool, case_id: str | None) -> None:
    """List DEFAIR forensic containers."""

    async def _run() -> None:
        try:
            containers = await container_service.list_containers(
                all_states=all_states, case_id=case_id
            )
        except ConnectionError as e:
            console.print(f"[red]✗ Docker error:[/red] {e}")
            raise SystemExit(1)

        if not containers:
            console.print("[dim]No DEFAIR containers found.[/dim]")
            return

        table = Table(title="DEFAIR Containers")
        table.add_column("Name", style="cyan")
        table.add_column("Status")
        table.add_column("Image")
        table.add_column("Case")
        table.add_column("Workspace", max_width=30)

        for c in containers:
            status_style = "green" if c.status == "running" else "yellow"
            table.add_row(
                c.name,
                f"[{status_style}]{c.status}[/{status_style}]",
                c.image,
                c.case_id or "-",
                c.workspace or "-",
            )

        console.print(table)

    run_sync(_run())


@container_group.command("start")
@click.argument("name")
def container_start(name: str) -> None:
    """Start a stopped DEFAIR container."""

    async def _run() -> None:
        try:
            info = await container_service.start_container(name)
            console.print(f"[green]▶[/green] Container started: [cyan]{info.name}[/cyan] ({info.status})")
        except (ConnectionError, ValueError, RuntimeError) as e:
            console.print(f"[red]✗[/red] {e}")
            raise SystemExit(1)

    run_sync(_run())


@container_group.command("stop")
@click.argument("name")
@click.option("--timeout", default=10, help="Seconds to wait before killing.")
def container_stop(name: str, timeout: int) -> None:
    """Stop a running DEFAIR container."""

    async def _run() -> None:
        try:
            info = await container_service.stop_container(name, timeout=timeout)
            console.print(f"[yellow]■[/yellow] Container stopped: [cyan]{info.name}[/cyan]")
        except (ConnectionError, ValueError) as e:
            console.print(f"[red]✗[/red] {e}")
            raise SystemExit(1)

    run_sync(_run())


@container_group.command("remove")
@click.argument("name")
@click.option("--force", is_flag=True, help="Force removal even if running.")
@click.confirmation_option(prompt="Are you sure you want to remove this container?")
def container_remove(name: str, force: bool) -> None:
    """Remove a DEFAIR container."""

    async def _run() -> None:
        try:
            result = await container_service.remove_container(name, force=force)
            console.print(f"[red]✗[/red] Container removed: [cyan]{result['name']}[/cyan]")
        except (ConnectionError, ValueError) as e:
            console.print(f"[red]✗[/red] {e}")
            raise SystemExit(1)

    run_sync(_run())


@container_group.command("exec")
@click.argument("name")
@click.argument("command", nargs=-1, required=True)
@click.option("--workdir", "-w", default=None, help="Working directory inside the container.")
def container_exec(name: str, command: tuple[str, ...], workdir: str | None) -> None:
    """Execute a command inside a running DEFAIR container.

    Example: defair container exec defair-case-2026-001 ls -la /evidence
    """

    async def _run() -> None:
        cmd = " ".join(command)
        try:
            result = await container_service.exec_in_container(
                name, cmd, workdir=workdir
            )
        except (ConnectionError, ValueError, RuntimeError) as e:
            console.print(f"[red]✗[/red] {e}")
            raise SystemExit(1)

        if result["stdout"]:
            console.print(result["stdout"], end="")
        if result["stderr"]:
            console.print(f"[red]{result['stderr']}[/red]", end="")

        if result["exit_code"] != 0:
            console.print(f"\n[dim]Exit code: {result['exit_code']}[/dim]")
            raise SystemExit(result["exit_code"])

    run_sync(_run())


@container_group.command("shell")
@click.argument("name")
@click.option("--shell", "shell_bin", default="bash", help="Shell to run inside the container.")
def container_shell(name: str, shell_bin: str) -> None:
    """Open an interactive shell in a running DEFAIR container.

    For analysts only — this is never exposed through MCP.
    Evidence stays read-only under /evidence.
    """
    import os

    async def _resolve() -> container_service.ContainerInfo | None:
        return await container_service.get_container(name)

    try:
        info = run_sync(_resolve())
    except ConnectionError as e:
        console.print(f"[red]✗ Docker error:[/red] {e}")
        raise SystemExit(1)
    if info is None:
        console.print(f"[red]✗[/red] DEFAIR container not found: {name}")
        raise SystemExit(1)
    if info.status != "running":
        console.print(
            f"[red]✗[/red] Container '{info.name}' is not running ({info.status}). "
            f"Start it with: defair container start {info.name}"
        )
        raise SystemExit(1)

    os.execvp("docker", shell_command(info.name, shell_bin))


def shell_command(container_name: str, shell_bin: str = "bash") -> list[str]:
    """Build the docker CLI invocation for an interactive container shell."""
    return ["docker", "exec", "-it", "-w", "/workspace", container_name, shell_bin]


@container_group.command("logs")
@click.argument("name")
@click.option("--tail", default=100, help="Number of lines from the end.")
def container_logs(name: str, tail: int) -> None:
    """Show logs from a DEFAIR container."""

    async def _run() -> None:
        try:
            logs = await container_service.container_logs(name, tail=tail)
            if logs.strip():
                console.print(logs, end="")
            else:
                console.print("[dim]No logs available.[/dim]")
        except (ConnectionError, ValueError) as e:
            console.print(f"[red]✗[/red] {e}")
            raise SystemExit(1)

    run_sync(_run())


@container_group.command("get")
@click.argument("name")
def container_get(name: str) -> None:
    """Get details of a DEFAIR container."""

    async def _run() -> None:
        try:
            info = await container_service.get_container(name)
        except ConnectionError as e:
            console.print(f"[red]✗ Docker error:[/red] {e}")
            raise SystemExit(1)

        if info is None:
            console.print(f"[red]Container not found:[/red] {name}")
            raise SystemExit(1)

        status_style = "green" if info.status == "running" else "yellow"
        console.print(f"[cyan]{info.name}[/cyan]")
        console.print(f"  ID:        {info.container_id}")
        console.print(f"  Status:    [{status_style}]{info.status}[/{status_style}]")
        console.print(f"  Image:     {info.image}")
        if info.case_id:
            console.print(f"  Case:      {info.case_id}")
        console.print(f"  Workspace: {info.workspace}")
        if info.evidence_mounts:
            for mount in info.evidence_mounts:
                console.print(f"  Evidence:  {mount} (read-only)")
        console.print(f"  Created:   {info.created}")

    run_sync(_run())
