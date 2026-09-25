"""CLI: analysis profiles and profile runs (PRUN-NNN)."""

from __future__ import annotations

import asyncio
import json

import click
from rich.console import Console
from rich.table import Table

from defair.cli.proxy import get_container_or_fail, proxy_command
from defair.database import get_initialized_connection, run_sync

console = Console()

PASSWORD_ENV = "DEFAIR_EVIDENCE_PASSWORD"
PASSPHRASE_ENV = "DEFAIR_KEY_PASSPHRASE"


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------


@click.group("profile")
def profile_group() -> None:
    """Declarative analysis profiles (windows-triage, windows-full, ransomware…)."""


@profile_group.command("list")
@click.option("--json", "as_json", is_flag=True, help="JSON output.")
def profile_list(as_json: bool) -> None:
    """List available profiles."""
    from defair.orchestrator.profile import list_profiles

    profiles = list_profiles()
    if as_json:
        click.echo(json.dumps(profiles, indent=2))
        return
    table = Table(title="Analysis profiles")
    table.add_column("Profile", style="cyan")
    table.add_column("Platforms")
    table.add_column("Steps")
    table.add_column("Description")
    for p in profiles:
        table.add_row(p["name"], ", ".join(p["platforms"]), str(len(p["steps"])), p["description"].strip())
    console.print(table)


@profile_group.command("show")
@click.argument("name")
def profile_show(name: str) -> None:
    """Show a profile's steps as JSON (tools, inputs, fallbacks, dependencies)."""
    from defair.orchestrator.profile import load_profile

    try:
        profile = load_profile(name)
    except ValueError as e:
        console.print(f"[red]✗[/red] {e}")
        raise SystemExit(1)
    click.echo(json.dumps(profile.model_dump(exclude_defaults=True), indent=2))


# ---------------------------------------------------------------------------
# Profile runs
# ---------------------------------------------------------------------------


@click.group("run")
def run_group() -> None:
    """Profile runs: one command runs a whole investigation profile.

    Runs execute in the background inside the container; follow them with
    `defair run status PRUN-NNN`.
    """


def _db(ctx: click.Context) -> str:
    return ctx.obj["db_path"]


def _echo(result: dict, as_json: bool) -> None:
    if as_json:
        click.echo(json.dumps(result, indent=2, default=str))
        return
    color = {"completed": "green", "failed": "red", "cancelled": "yellow"}.get(result["status"], "cyan")
    console.print(f"[bold]{result['run_number']}[/bold] — profile [cyan]{result['profile']}[/cyan] "
                  f"(engine {result['engine']}) — [{color}]{result['status']}[/{color}]")
    if result.get("error"):
        console.print(f"  [red]{result['error']}[/red]")
    for step in result.get("step_details") or []:
        tools = ", ".join(sorted({t["tool"] for t in step.get("tool_runs", []) if t.get("tool")}))
        console.print(f"  {step['status']:>11}  {step['id']:<12} {tools} "
                      f"{step.get('artifacts', '') or ''} {step.get('error') or ''}")
    if result.get("manifest"):
        console.print(f"  Manifest: {result['manifest']}")


@run_group.command("start")
@click.option("--case", "case_id", required=True, help="Case number (CASE-YYYY-NNN), name or ID.")
@click.option("--evidence", "evidence", required=True,
              help="Evidence number (EVD-NNN), or a path to register first.")
@click.option("--profile", default="auto", show_default=True,
              help="Profile name, or 'auto' (chosen from the detected platform).")
@click.option("--engine", default="auto", type=click.Choice(["auto", "ez", "dissect"]),
              show_default=True, help="auto: EZ Tools then fallbacks; ez: no Dissect; dissect: Dissect plugins.")
@click.option("--password", envvar=PASSWORD_ENV, default=None, help=f"Archive password (or ${PASSWORD_ENV}).")
@click.option("--private-key", default=None, help="PEM key for DFIR-ORC / Generaptor (under /keys).")
@click.option("--passphrase", envvar=PASSPHRASE_ENV, default=None, help=f"Key passphrase (or ${PASSPHRASE_ENV}).")
@click.option("--wait", is_flag=True, help="Run in the foreground and wait for the result.")
@click.option("--json", "as_json", is_flag=True, help="JSON output.")
@click.pass_context
def run_start(ctx, case_id, evidence, profile, engine, password, private_key, passphrase,
              wait, as_json) -> None:
    """Prepare an evidence and run an analysis profile on it."""
    container = get_container_or_fail(ctx)
    if container:
        cmd = ["run", "start", "--case", case_id, "--evidence", evidence,
               "--profile", profile, "--engine", engine]
        if private_key:
            cmd.extend(["--private-key", private_key])
        if wait:
            cmd.append("--wait")
        if as_json:
            cmd.append("--json")
        env = {k: v for k, v in ((PASSWORD_ENV, password), (PASSPHRASE_ENV, passphrase)) if v}
        return proxy_command(container, cmd, env=env)

    from defair.orchestrator import runs
    from defair.services import evidence_service

    config = ctx.obj["config"]
    secrets = {"password": password, "private_key": private_key, "passphrase": passphrase}

    async def _create() -> dict:
        conn = await get_initialized_connection(_db(ctx))
        try:
            ev = await evidence_service.get_evidence(conn, evidence)
            if ev is None:  # a path: register it first
                ev = await evidence_service.add_evidence(conn, case_id, evidence)
            return await runs.create_run(
                conn, case_id, ev.id, profile, engine,
                params={"secrets": [k for k, v in secrets.items() if v]},
            )
        finally:
            await conn.close()

    try:
        run = run_sync(_create())
    except (ValueError, FileNotFoundError) as e:
        console.print(f"[red]✗[/red] {e}")
        raise SystemExit(1)

    if not wait:
        pid = runs.spawn_worker(run["run_number"], _db(ctx), secrets)
        result = {"run_number": run["run_number"], "status": "started", "pid": pid,
                  "profile": profile, "engine": engine,
                  "follow": f"defair run status {run['run_number']}"}
        if as_json:
            click.echo(json.dumps(result, indent=2))
        else:
            console.print(f"[green]✓[/green] {run['run_number']} started in the background "
                          f"(profile {profile}, engine {engine})")
            console.print(f"  Follow: defair run status {run['run_number']}")
        return

    _execute(ctx, run["run_number"], secrets, resume=False, as_json=as_json, config=config)


def _execute(ctx, run_number: str, secrets: dict, resume: bool, as_json: bool, config) -> None:
    from defair.orchestrator import runs

    orch = config.orchestrator

    async def _go() -> dict:
        conn = await get_initialized_connection(_db(ctx))
        try:
            return await runs.execute_run(
                conn, run_number, secrets, resume=resume,
                max_parallel=orch.max_parallel, default_timeout=orch.default_timeout,
                default_retries=orch.default_retries,
            )
        finally:
            await conn.close()

    result = asyncio.run(_go())
    _echo(result, as_json)
    if result["status"] in ("failed", "cancelled"):
        raise SystemExit(1)


@run_group.command("worker", hidden=True)
@click.argument("run_number")
@click.option("--secrets-file", default=None)
@click.option("--resume", is_flag=True)
@click.pass_context
def run_worker(ctx, run_number: str, secrets_file: str | None, resume: bool) -> None:
    """Internal: execute a run (spawned detached by `run start`)."""
    from defair.orchestrator.runs import read_secrets_file

    _execute(ctx, run_number, read_secrets_file(secrets_file), resume, as_json=True,
             config=ctx.obj["config"])


def _simple(ctx: click.Context, args: list[str], coro_factory, as_json: bool, renderer=None) -> None:
    container = get_container_or_fail(ctx)
    if container:
        return proxy_command(container, args + (["--json"] if as_json else []))

    async def _go():
        conn = await get_initialized_connection(_db(ctx))
        try:
            return await coro_factory(conn)
        finally:
            await conn.close()

    try:
        result = run_sync(_go())
    except ValueError as e:
        console.print(f"[red]✗[/red] {e}")
        raise SystemExit(1)
    if as_json or renderer is None:
        click.echo(json.dumps(result, indent=2, default=str))
    else:
        renderer(result)


@run_group.command("status")
@click.argument("run")
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def run_status_cmd(ctx, run: str, as_json: bool) -> None:
    """Status of a profile run (steps, tools, errors, manifest)."""
    from defair.orchestrator import runs

    _simple(ctx, ["run", "status", run], lambda c: runs.run_status(c, run), as_json,
            lambda r: _echo(r, False))


@run_group.command("list")
@click.option("--case", "case_id", default=None)
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def run_list(ctx, case_id: str | None, as_json: bool) -> None:
    """List profile runs."""
    from defair.orchestrator import runs

    def render(items: list[dict]) -> None:
        table = Table(title="Profile runs")
        for col in ("Run", "Profile", "Engine", "Status", "Steps", "Started"):
            table.add_column(col)
        for r in items:
            steps = ", ".join(f"{k}:{v}" for k, v in sorted(r["steps"].items()))
            table.add_row(r["run_number"], r["profile"], r["engine"], r["status"], steps,
                          (r["started_at"] or "")[:19])
        console.print(table)

    args = ["run", "list", *(["--case", case_id] if case_id else [])]
    _simple(ctx, args, lambda c: runs.list_runs(c, case_id), as_json, render)


@run_group.command("cancel")
@click.argument("run")
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def run_cancel(ctx, run: str, as_json: bool) -> None:
    """Cancel a running profile run (running tools are stopped)."""
    from defair.orchestrator import runs

    _simple(ctx, ["run", "cancel", run], lambda c: runs.cancel_run(c, run), as_json,
            lambda r: _echo(r, False))


@run_group.command("resume")
@click.argument("run")
@click.option("--password", envvar=PASSWORD_ENV, default=None)
@click.option("--private-key", default=None)
@click.option("--passphrase", envvar=PASSPHRASE_ENV, default=None)
@click.option("--wait", is_flag=True)
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def run_resume(ctx, run: str, password, private_key, passphrase, wait: bool, as_json: bool) -> None:
    """Resume a failed / cancelled run: completed steps are not re-run."""
    container = get_container_or_fail(ctx)
    if container:
        cmd = ["run", "resume", run, *(["--private-key", private_key] if private_key else []),
               *(["--wait"] if wait else []), *(["--json"] if as_json else [])]
        env = {k: v for k, v in ((PASSWORD_ENV, password), (PASSPHRASE_ENV, passphrase)) if v}
        return proxy_command(container, cmd, env=env)

    from defair.orchestrator import runs

    async def _check() -> dict:
        conn = await get_initialized_connection(_db(ctx))
        try:
            return await runs.run_status(conn, run)
        finally:
            await conn.close()

    current = run_sync(_check())
    if current["status"] in runs.ACTIVE:
        console.print(f"[red]✗[/red] {current['run_number']} is still {current['status']}")
        raise SystemExit(1)
    secrets = {"password": password, "private_key": private_key, "passphrase": passphrase}
    if wait:
        _execute(ctx, current["run_number"], secrets, resume=True, as_json=as_json,
                 config=ctx.obj["config"])
        return
    pid = runs.spawn_worker(current["run_number"], _db(ctx), secrets, resume=True)
    result = {"run_number": current["run_number"], "status": "resumed", "pid": pid}
    click.echo(json.dumps(result, indent=2)) if as_json else console.print(
        f"[green]✓[/green] {current['run_number']} resumed in the background")
