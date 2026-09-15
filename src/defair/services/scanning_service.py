"""Scanning service — mass YARA and Sigma rule scanning.

Orchestrates mass scanning of evidence with YARA rules (file-based)
and Sigma rules via Hayabusa (EVTX-based).
"""

from __future__ import annotations

import json

import aiosqlite
import structlog

from defair.services import analysis_service, finding_service

log = structlog.get_logger(component="scanning")


async def scan_yara(
    conn: aiosqlite.Connection,
    input_path: str,
    case_id: str,
    evidence_id: str | None = None,
    rules_dir: str | None = None,
    output_base: str = "/workspace/analysis",
    **kwargs,
) -> dict:
    """Run YARA mass scan on files and create findings from matches.

    Args:
        conn: Database connection.
        input_path: File or directory to scan.
        case_id: Case ID.
        evidence_id: Optional evidence ID.
        rules_dir: Additional custom rules directory.
        output_base: Base output directory.
        **kwargs: Passed to YaraTool (file_timeout, max_file_size).

    Returns:
        Summary dict with scan results and findings created.
    """
    tool_kwargs = dict(kwargs)
    if rules_dir:
        tool_kwargs["rules_dir"] = rules_dir

    result = await analysis_service.run_tool_and_normalize(
        conn,
        tool_name="yara",
        input_path=input_path,
        case_id=case_id,
        evidence_id=evidence_id,
        output_base=output_base,
        **tool_kwargs,
    )

    # Auto-create findings from YARA matches
    findings_created = 0
    if result.get("artifact_count", 0) > 0:
        findings_created = await _auto_create_findings_from_yara(
            conn, case_id, result.get("run_id", ""),
        )

    result["findings_created"] = findings_created
    return result


async def scan_sigma(
    conn: aiosqlite.Connection,
    input_path: str,
    case_id: str,
    evidence_id: str | None = None,
    rules_dir: str | None = None,
    min_level: str = "medium",
    output_base: str = "/workspace/analysis",
) -> dict:
    """Run Sigma mass scan via Hayabusa on EVTX files.

    This wraps the existing Hayabusa tool with Sigma-focused defaults:
    - Scans all EVTX files in the input path
    - Uses verbose profile to capture more Sigma details
    - Creates findings from high/critical detections

    Args:
        conn: Database connection.
        input_path: Directory containing EVTX files.
        case_id: Case ID.
        evidence_id: Optional evidence ID.
        rules_dir: Custom Sigma rules directory.
        min_level: Minimum detection level (default: medium).
        output_base: Base output directory.

    Returns:
        Summary dict with scan results and findings created.
    """
    tool_kwargs: dict = {
        "profile": "verbose",
        "min_level": min_level,
    }
    if rules_dir:
        tool_kwargs["rules_dir"] = rules_dir

    result = await analysis_service.run_tool_and_normalize(
        conn,
        tool_name="hayabusa",
        input_path=input_path,
        case_id=case_id,
        evidence_id=evidence_id,
        output_base=output_base,
        **tool_kwargs,
    )

    # Auto-create findings from Sigma detections
    findings_created = 0
    if result.get("artifact_count", 0) > 0:
        findings_created = await finding_service.auto_create_findings_from_hayabusa(
            conn, case_id, result.get("run_id", ""),
        )

    result["findings_created"] = findings_created
    return result


async def _auto_create_findings_from_yara(
    conn: aiosqlite.Connection,
    case_id: str,
    run_id: str,
) -> int:
    """Create findings from YARA matches, grouped by rule name.

    Groups matches by RuleName, creates one Finding per rule with
    all matched files as artifact_ids.
    """
    # Get all YARA artifacts from this run
    cursor = await conn.execute(
        """SELECT id, description, severity, data
        FROM artifacts
        WHERE case_id = ? AND source_tool = 'yara'
        AND data LIKE ?
        ORDER BY severity DESC""",
        (case_id, f"%{run_id}%" if run_id else "%"),
    )
    rows = await cursor.fetchall()

    if not rows:
        return 0

    # Group by rule name
    by_rule: dict[str, list[dict]] = {}
    for row in rows:
        data = json.loads(row[3]) if row[3] else {}
        rule_name = data.get("rule_name", "unknown")
        if rule_name not in by_rule:
            by_rule[rule_name] = []
        by_rule[rule_name].append({
            "id": row[0],
            "description": row[1],
            "severity": row[2],
            "data": data,
        })

    # Create one finding per rule
    count = 0
    for rule_name, artifacts in by_rule.items():
        # Use the highest severity from all matches
        severity_order = ["critical", "high", "medium", "low", "informational"]
        severities = [a["severity"] for a in artifacts if a["severity"]]
        best_severity = "medium"
        for s in severity_order:
            if s in severities:
                best_severity = s
                break

        # Collect affected files
        affected_files = list({
            a["data"].get("file_name", "") for a in artifacts if a["data"].get("file_name")
        })
        artifact_ids = [a["id"] for a in artifacts]

        description = (
            f"YARA rule '{rule_name}' matched {len(artifacts)} file(s): "
            f"{', '.join(affected_files[:5])}"
        )
        if len(affected_files) > 5:
            description += f" (and {len(affected_files) - 5} more)"

        # Extract reference/author from first match
        first_data = artifacts[0]["data"]

        await finding_service.create_finding(
            conn,
            case_id=case_id,
            title=f"YARA: {rule_name}",
            description=description,
            severity=best_severity,
            confidence="high",
            source="yara",
            artifact_ids=artifact_ids,
            detection_refs=[{
                "rule": rule_name,
                "author": first_data.get("author", ""),
                "reference": first_data.get("reference", ""),
                "match_count": len(artifacts),
            }],
        )
        count += 1

    return count
