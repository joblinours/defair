"""CLI commands for the detection rule supply chain."""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from defair.cli.proxy import get_container_or_fail, proxy_command

console = Console()


@click.group("rules")
def rules_group() -> None:
    """Pinned YARA / Sigma rule sets: status, verification, conflicts.

    Sources are declared in src/defair/rules/sources.yaml and pinned (tag or
    commit + per-file SHA-256) in src/defair/rules/lock/.
    """


def _proxy_if_host(ctx: click.Context, args: list[str]) -> bool:
    container = ctx.obj.get("container")
    if container or not ctx.obj.get("inside_container"):
        container = get_container_or_fail(ctx)
        if container:
            proxy_command(container, args)
            return True
    return False


@rules_group.command("status")
@click.option("--store", default=None, help="Rule store (default /opt/defair/rules).")
@click.option("--verify", is_flag=True, help="Also verify every file against the lock.")
@click.option("--json", "as_json", is_flag=True, help="JSON output.")
@click.pass_context
def rules_status(ctx: click.Context, store: str | None, verify: bool, as_json: bool) -> None:
    """Show pinned rule sources and their installation state."""
    if _proxy_if_host(ctx, ["rules", "status", *(["--verify"] if verify else []),
                            *(["--json"] if as_json else [])]):
        return
    from defair.services.rules_service import ruleset_info

    info = ruleset_info(store, verify=verify)
    if as_json:
        click.echo(json.dumps(info, indent=2))
        return

    table = Table(title=f"Rule sources — lock {info['lock_generated_at'][:19]}")
    for col in ("Source", "Engine", "Ref", "Files", "License", "Profiles", "Installed"):
        table.add_column(col)
    for s in info["sources"]:
        table.add_row(
            s["id"], s["engine"], s["ref"][:12], str(s["files"]), s["license"] or "?",
            ", ".join(s["profiles"]), "[green]yes[/green]" if s["installed"] else "[red]no[/red]",
        )
    console.print(table)
    if "integrity" in info:
        color = "green" if info["integrity"] == "ok" else "red"
        console.print(f"Integrity: [{color}]{info['integrity']}[/{color}]")


@rules_group.command("verify")
@click.option("--store", default=None, help="Rule store (default /opt/defair/rules).")
@click.pass_context
def rules_verify(ctx: click.Context, store: str | None) -> None:
    """Verify every installed rule file against the pinned lock."""
    if _proxy_if_host(ctx, ["rules", "verify"]):
        return
    from defair.services.rules_service import verify_rules

    result = verify_rules(store)
    for source_id, r in result["sources"].items():
        bad = {k: len(r[k]) for k in ("missing", "extra", "modified") if r[k]}
        mark = "[red]✗[/red]" if bad else "[green]✓[/green]"
        console.print(f"{mark} {source_id}: {r['files']} files {bad or ''}")
    if not result["ok"]:
        raise SystemExit(1)


@rules_group.command("conflicts")
@click.option("--store", default=None, help="Rule store (default /opt/defair/rules).")
@click.option("--profile", type=click.Choice(["precise", "broad"]), default=None)
@click.pass_context
def rules_conflicts(ctx: click.Context, store: str | None, profile: str | None) -> None:
    """Show duplicate / conflicting rules across sources (JSON)."""
    if _proxy_if_host(ctx, ["rules", "conflicts", *(["--profile", profile] if profile else [])]):
        return
    from defair.services.rules_service import rule_conflicts

    click.echo(json.dumps(rule_conflicts(store, profile), indent=2))


@rules_group.command("lock")
@click.option("--refresh", is_flag=True, required=True,
              help="Resolve every source to its newest release/commit (network).")
def rules_lock(refresh: bool) -> None:
    """Re-pin all rule sources (maintainers; commit the result)."""
    from defair.rules.lock import refresh_lock

    lock = refresh_lock()
    for s in lock.sources:
        console.print(f"[green]✓[/green] {s.id:18} {s.ref[:12]:12} {s.files:5} files  {s.license}")


@rules_group.command("sync")
@click.option("--dest", required=True, type=click.Path(path_type=Path), help="Rule store to install into.")
def rules_sync(dest: Path) -> None:
    """Download the pinned rule sets and install them, verified (image build)."""
    from defair.rules.sync import sync_rules

    result = sync_rules(dest)
    for source_id, s in result["sources"].items():
        console.print(f"[green]✓[/green] {source_id:18} {s['ref'][:12]:12} {s['files']:5} files")
    console.print(f"Conflicts: {json.dumps(result['conflicts'])}")
