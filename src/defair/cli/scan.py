"""CLI commands for mass scanning (YARA + Sigma)."""

from __future__ import annotations

import click
from rich.console import Console

from defair.cli.proxy import get_container_or_fail, proxy_command
from defair.database import get_initialized_connection, run_sync

console = Console()


@click.group("scan")
def scan_group():
    """Mass scan evidence with YARA and Sigma rules."""


@scan_group.command("yara")
@click.argument("input_path")
@click.option("--case", "case_id", required=True, help="Case ID or case number.")
@click.option("--evidence", "evidence_id", default=None, help="Evidence ID.")
@click.option("--rules-dir", default=None, help="Additional YARA rules directory.")
@click.option("--timeout", "file_timeout", default=60, type=int, help="Per-file timeout (seconds).")
@click.option("--max-size", default=100, type=int, help="Max file size in MB to scan.")
@click.pass_context
def scan_yara_cmd(
    ctx: click.Context,
    input_path: str,
    case_id: str,
    evidence_id: str | None,
    rules_dir: str | None,
    file_timeout: int,
    max_size: int,
) -> None:
    """Scan files with YARA rules.

    Scans INPUT_PATH (file or directory) against built-in and custom YARA rules.
    Creates findings for each matching rule.

    Built-in rules: /opt/yara/rules/
    Custom rules:   /rules/yara/ (mount your own)
    """
    container = get_container_or_fail(ctx)
    if container:
        cmd = ["scan", "yara", input_path, "--case", case_id,
               "--timeout", str(file_timeout), "--max-size", str(max_size)]
        if evidence_id:
            cmd.extend(["--evidence", evidence_id])
        if rules_dir:
            cmd.extend(["--rules-dir", rules_dir])
        return proxy_command(container, cmd)

    from defair.services import scanning_service

    async def _run() -> None:
        db_path = ctx.obj["db_path"]
        conn = await get_initialized_connection(db_path)
        try:
            result = await scanning_service.scan_yara(
                conn,
                input_path=input_path,
                case_id=case_id,
                evidence_id=evidence_id,
                rules_dir=rules_dir,
                file_timeout=file_timeout,
                max_file_size=max_size * 1024 * 1024,
            )

            status = result.get("status", "unknown")
            artifacts = result.get("artifact_count", 0)
            findings = result.get("findings_created", 0)

            if status == "completed":
                console.print("✓ YARA scan completed", style="green")
                console.print(f"  Matches: {artifacts}")
                console.print(f"  Findings created: {findings}")
            else:
                console.print(f"✗ YARA scan {status}", style="red")
                raise SystemExit(1)
        finally:
            await conn.close()

    run_sync(_run())


@scan_group.command("sigma")
@click.argument("input_path")
@click.option("--case", "case_id", required=True, help="Case ID or case number.")
@click.option("--evidence", "evidence_id", default=None, help="Evidence ID.")
@click.option("--rules-dir", default=None, help="Custom Sigma rules directory.")
@click.option("--min-level", default="medium",
              type=click.Choice(["informational", "low", "medium", "high", "critical"]),
              help="Minimum detection level.")
@click.pass_context
def scan_sigma_cmd(
    ctx: click.Context,
    input_path: str,
    case_id: str,
    evidence_id: str | None,
    rules_dir: str | None,
    min_level: str,
) -> None:
    """Scan EVTX files with Sigma rules via Hayabusa.

    Scans all EVTX files in INPUT_PATH against Sigma detection rules.
    Creates findings for high/critical detections.

    Built-in rules: /opt/hayabusa/rules/
    Custom rules:   /rules/sigma/ (mount your own)
    """
    container = get_container_or_fail(ctx)
    if container:
        cmd = ["scan", "sigma", input_path, "--case", case_id,
               "--min-level", min_level]
        if evidence_id:
            cmd.extend(["--evidence", evidence_id])
        if rules_dir:
            cmd.extend(["--rules-dir", rules_dir])
        return proxy_command(container, cmd)

    from defair.services import scanning_service

    async def _run() -> None:
        db_path = ctx.obj["db_path"]
        conn = await get_initialized_connection(db_path)
        try:
            result = await scanning_service.scan_sigma(
                conn,
                input_path=input_path,
                case_id=case_id,
                evidence_id=evidence_id,
                rules_dir=rules_dir,
                min_level=min_level,
            )

            status = result.get("status", "unknown")
            artifacts = result.get("artifact_count", 0)
            findings = result.get("findings_created", 0)

            if status == "completed":
                console.print("✓ Sigma scan completed", style="green")
                console.print(f"  Detections: {artifacts}")
                console.print(f"  Findings created: {findings}")
            else:
                console.print(f"✗ Sigma scan {status}", style="red")
                raise SystemExit(1)
        finally:
            await conn.close()

    run_sync(_run())
