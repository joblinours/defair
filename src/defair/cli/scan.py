"""CLI commands for mass scanning (YARA + Sigma) with Raijin."""

from __future__ import annotations

import functools

import click
from rich.console import Console

from defair.cli.proxy import get_container_or_fail, proxy_command
from defair.database import get_initialized_connection, run_sync

console = Console()

SEVERITIES = ["informational", "low", "medium", "high", "critical"]


@click.group("scan")
def scan_group():
    """Mass scan evidence with YARA and Sigma rules (Raijin).

    Rules come from the pinned, verified rule store (see `defair rules status`).
    Profiles: `precise` (YARA Forge core + SigmaHQ core) or `broad` (every source).
    Custom rules: mount /rules/yara/ and /rules/sigma/ (tagged provenance: custom).
    """


def _scan_options(fn):
    @click.argument("input_path")
    @click.option("--case", "case_id", required=True, help="Case ID or case number.")
    @click.option("--evidence", "evidence_id", default=None, help="Evidence ID.")
    @click.option("--profile", default="broad", type=click.Choice(["precise", "broad"]),
                  show_default=True, help="Rule profile.")
    @click.option("--min-severity", default="medium", type=click.Choice(SEVERITIES),
                  show_default=True, help="Lowest severity that becomes a finding.")
    @click.option("--yara-rules-dir", default=None, help="Custom YARA rules directory.")
    @click.option("--sigma-rules-dir", default=None, help="Custom Sigma rules directory.")
    @click.option("--executables-only", is_flag=True,
                  help="YARA-scan only executables/scripts instead of every file.")
    @click.pass_context
    @functools.wraps(fn)
    def wrapper(ctx, **kwargs):
        return fn(ctx, **kwargs)
    return wrapper


def _run_scan(ctx: click.Context, mode: str, label: str, **opts) -> None:
    container = get_container_or_fail(ctx)
    if container:
        cmd = ["scan", ctx.info_name, opts["input_path"], "--case", opts["case_id"],
               "--profile", opts["profile"], "--min-severity", opts["min_severity"]]
        if opts["evidence_id"]:
            cmd.extend(["--evidence", opts["evidence_id"]])
        for key in ("yara_rules_dir", "sigma_rules_dir"):
            if opts.get(key):
                cmd.extend([f"--{key.replace('_', '-')}", opts[key]])
        if opts["executables_only"]:
            cmd.append("--executables-only")
        return proxy_command(container, cmd)

    from defair.services import scanning_service

    async def _run() -> None:
        conn = await get_initialized_connection(ctx.obj["db_path"])
        try:
            result = await scanning_service.scan(
                conn,
                input_path=opts["input_path"],
                case_id=opts["case_id"],
                mode=mode,
                profile=opts["profile"],
                evidence_id=opts["evidence_id"],
                yara_rules_dir=opts.get("yara_rules_dir"),
                sigma_rules_dir=opts.get("sigma_rules_dir"),
                min_severity=opts["min_severity"],
                all_files=not opts["executables_only"],
            )
        except Exception as e:  # noqa: BLE001 — surface rule integrity errors cleanly
            console.print(f"[red]✗ {label} scan refused:[/red] {e}")
            raise SystemExit(1)
        finally:
            await conn.close()

        if result.get("status") == "completed":
            console.print(f"[green]✓[/green] {label} scan completed: [cyan]{result['run_number']}[/cyan]")
            console.print(f"  Profile:          {result['profile']}")
            console.print(f"  Matches:          {result.get('artifacts_produced', 0)}")
            console.print(f"  Findings created: {result.get('findings_created', 0)}")
        else:
            console.print(f"[red]✗[/red] {label} scan {result.get('status')}: {result.get('run_number')}")
            raise SystemExit(1)

    run_sync(_run())


@scan_group.command("yara")
@_scan_options
def scan_yara_cmd(ctx: click.Context, **opts) -> None:
    """Scan every file under INPUT_PATH with YARA rules."""
    _run_scan(ctx, "yara", "YARA", **opts)


@scan_group.command("sigma")
@_scan_options
def scan_sigma_cmd(ctx: click.Context, **opts) -> None:
    """Scan EVTX / Linux logs under INPUT_PATH with Sigma rules.

    KAPE, Velociraptor and plain-mount layouts are detected automatically.
    """
    _run_scan(ctx, "sigma", "Sigma", **opts)


@scan_group.command("evidence")
@_scan_options
def scan_evidence_cmd(ctx: click.Context, **opts) -> None:
    """Scan INPUT_PATH with YARA and Sigma in a single pass."""
    _run_scan(ctx, "all", "YARA + Sigma", **opts)
