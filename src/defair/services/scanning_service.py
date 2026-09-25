"""Scanning service — mass YARA and Sigma scanning with Raijin.

One engine (Raijin, vendored in engines/raijin) for both modes. Rules come
from the pinned, verified rule store (see ``defair.rules``); every finding
carries the provenance of the rule that produced it.
"""

from __future__ import annotations

import json

import aiosqlite
import structlog

from defair.services import analysis_service, finding_service

log = structlog.get_logger(component="scanning")

SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]
PROVENANCE_KEYS = ("source", "repo", "ref", "file", "file_sha256", "license", "provenance")


async def scan(
    conn: aiosqlite.Connection,
    input_path: str,
    case_id: str,
    mode: str = "all",
    profile: str = "broad",
    evidence_id: str | None = None,
    yara_rules_dir: str | None = None,
    sigma_rules_dir: str | None = None,
    min_severity: str = "medium",
    all_files: bool = True,
    output_base: str = "/workspace/analysis",
) -> dict:
    """Scan evidence with Raijin and create findings from matches.

    Args:
        conn: Database connection.
        input_path: File or directory to scan.
        case_id: Case ID or case number.
        mode: "yara", "sigma" or "all" (single pass).
        profile: Rule profile — "precise" (YARA Forge core + SigmaHQ core)
            or "broad" (every pinned source).
        evidence_id: Optional evidence ID.
        yara_rules_dir / sigma_rules_dir: Custom rule directories
            (default /rules/yara, /rules/sigma), tagged ``provenance: custom``.
        min_severity: Lowest severity that becomes a finding.
        all_files: YARA-scan every file (not only executables/scripts).
        output_base: Base output directory.

    Returns:
        Run summary with artifacts produced and findings created.
    """
    options: dict = {"mode": mode, "profile": profile, "all_files": all_files}
    if yara_rules_dir:
        options["yara_rules_dir"] = yara_rules_dir
    if sigma_rules_dir:
        options["sigma_rules_dir"] = sigma_rules_dir

    result = await analysis_service.run_tool_and_normalize(
        conn,
        tool_name="raijin",
        input_path=input_path,
        case_id=case_id,
        evidence_id=evidence_id,
        output_base=output_base,
        **options,
    )

    findings_created = 0
    if result.get("artifacts_produced", 0) > 0:
        findings_created = await auto_create_findings(
            conn, result["case_id"], result["run_id"], min_severity=min_severity,
        )
    result["findings_created"] = findings_created
    result["mode"] = mode
    result["profile"] = profile
    return result


async def scan_yara(conn: aiosqlite.Connection, input_path: str, case_id: str, **kwargs) -> dict:
    """YARA-only scan (see :func:`scan`)."""
    return await scan(conn, input_path, case_id, mode="yara", **kwargs)


async def scan_sigma(conn: aiosqlite.Connection, input_path: str, case_id: str, **kwargs) -> dict:
    """Sigma-only scan of EVTX / Linux logs (see :func:`scan`)."""
    return await scan(conn, input_path, case_id, mode="sigma", **kwargs)


async def auto_create_findings(
    conn: aiosqlite.Connection,
    case_id: str,
    run_id: str,
    min_severity: str = "medium",
    tool: str = "raijin",
) -> int:
    """Create one finding per matching rule of a Raijin (or Chainsaw) run.

    Artifacts are grouped by (engine, rule source, rule id or name); the
    finding takes the highest severity of its matches and lists the rule's
    provenance in ``detection_refs``.
    """
    threshold = SEVERITY_ORDER.index(min_severity) if min_severity in SEVERITY_ORDER else 2
    cursor = await conn.execute(
        """SELECT id, severity, data FROM artifacts
        WHERE case_id = ? AND run_id = ? AND source_tool = ?""",
        (case_id, run_id, tool),
    )
    rows = await cursor.fetchall()

    groups: dict[tuple, list[dict]] = {}
    for row in rows:
        data = json.loads(row["data"]) if row["data"] else {}
        rule = data.get("rule") or {}
        key = (data.get("engine"), rule.get("source"), rule.get("id") or rule.get("name"))
        groups.setdefault(key, []).append({"id": row["id"], "severity": row["severity"], "data": data})

    count = 0
    for (engine, _source, _rule_key), artifacts in groups.items():
        severities = [a["severity"] for a in artifacts if a["severity"] in SEVERITY_ORDER]
        best = max(severities, key=SEVERITY_ORDER.index, default="medium")
        if SEVERITY_ORDER.index(best) < threshold:
            continue

        first = artifacts[0]["data"]
        rule = first.get("rule") or {}
        name = rule.get("name") or "unknown"
        label = "YARA" if engine == "yara" else "Sigma"

        targets = sorted({
            a["data"].get("file_name") or a["data"].get("host_path") or "" for a in artifacts
        } - {""})
        description = f"{label} rule '{name}' matched {len(artifacts)} time(s)"
        if targets:
            description += f" in: {', '.join(targets[:5])}"
            if len(targets) > 5:
                description += f" (and {len(targets) - 5} more)"
        if first.get("rule_description"):
            description += f"\n\n{first['rule_description']}"

        techniques = sorted({t for a in artifacts for t in a["data"].get("mitre_techniques", [])})
        ref = {
            "engine": engine,
            "rule": name,
            "rule_id": rule.get("id"),
            "match_count": len(artifacts),
            "author": first.get("author"),
            "reference": first.get("reference"),
            **{k: rule.get(k) for k in PROVENANCE_KEYS if rule.get(k)},
        }
        if rule.get("also_in"):
            ref["also_in"] = rule["also_in"]

        await finding_service.create_finding(
            conn,
            case_id=case_id,
            title=f"{label}: {name}",
            description=description,
            severity=best,
            confidence="high" if engine == "yara" else "medium",
            source=f"{tool}-{engine}",
            mitre_techniques=techniques,
            artifact_ids=[a["id"] for a in artifacts],
            detection_refs=[ref],
        )
        count += 1

    log.info("scan_findings_created", run_id=run_id, findings=count, groups=len(groups))
    return count
