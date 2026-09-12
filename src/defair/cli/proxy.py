"""Proxy helper — forwards CLI commands to a DEFAIR container via docker exec."""

from __future__ import annotations

import sys

import click
from rich.console import Console

from defair.database import run_sync
from defair.services import container_service

console = Console()


def get_container_or_fail(ctx: click.Context) -> str | None:
    """Get the target container name from context.

    Returns the container name if in proxy mode (host),
    or None if running inside a container (direct mode).

    Raises SystemExit if on host without -c flag.
    """
    container_name = ctx.obj.get("container")
    inside = ctx.obj.get("inside_container", False)

    if container_name:
        return container_name

    if inside:
        # Inside a container — run locally
        return None

    # On host without -c flag — error
    console.print(
        "[red]✗[/red] No container specified. "
        "Use [cyan]-c <container>[/cyan] to target a forensic container:\n\n"
        "  defair -c defair-case-2026-001 case create \"My case\"\n"
        "  defair -c defair-case-2026-001 cases list\n\n"
        "Or set DEFAIR_CONTAINER environment variable.\n"
        "Use [cyan]defair container list[/cyan] to see available containers."
    )
    raise SystemExit(1)


def proxy_command(container_name: str, command_args: list[str]) -> None:
    """Execute a defair command inside a container.

    Args:
        container_name: Target container name.
        command_args: The defair subcommand + args (e.g. ["case", "create", "My case"]).
    """
    full_cmd = ["defair", *command_args]

    async def _run() -> None:
        try:
            result = await container_service.exec_in_container(
                container_name,
                full_cmd,
            )
        except (ConnectionError, ValueError, RuntimeError) as e:
            console.print(f"[red]✗[/red] {e}")
            raise SystemExit(1)

        if result["stdout"]:
            # Print raw stdout (it already has Rich formatting from inside)
            click.echo(result["stdout"], nl=False)
        if result["stderr"]:
            click.echo(result["stderr"], nl=False, err=True)

        if result["exit_code"] != 0:
            sys.exit(result["exit_code"])

    run_sync(_run())
