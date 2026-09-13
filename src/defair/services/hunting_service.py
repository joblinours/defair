"""Hunting service — orchestrates threat hunting workflows.

Combines tool execution (Hayabusa) with finding auto-creation.
This is the high-level entry point for detection workflows.
"""

from __future__ import annotations

import aiosqlite
import structlog

from defair.services import analysis_service
from defair.services.finding_service import auto_create_findings_from_hayabusa

log = structlog.get_logger(component="hunting_service")


async def hunt_evtx(
    conn: aiosqlite.Connection,
    input_path: str,
    case_id: str,
    evidence_id: str | None = None,
    profile: str = "standard",
    output_base: str = "/workspace/analysis",
) -> dict:
    """Run Hayabusa threat hunting on EVTX evidence.

    1. Execute Hayabusa via analysis_service
    2. Normalize detections into artifacts
    3. Auto-create findings from high/critical alerts

    Args:
        conn: DB connection.
        input_path: Path to EVTX directory.
        case_id: Case ID.
        evidence_id: Optional evidence ID.
        profile: Hayabusa output profile.
        output_base: Base output directory.

    Returns:
        Summary with run details, detections, and findings.
    """
    # Step 1+2: Run Hayabusa and normalize
    result = await analysis_service.run_tool_and_normalize(
        conn,
        tool_name="hayabusa",
        input_path=input_path,
        case_id=case_id,
        evidence_id=evidence_id,
        output_base=output_base,
        directory=True,
        profile=profile,
    )

    # Step 3: Auto-create findings from high/critical detections
    findings = []
    if result.get("status") == "completed" and result.get("run_id"):
        findings = await auto_create_findings_from_hayabusa(
            conn, case_id, result["run_id"],
        )

    result["findings_created"] = len(findings)
    result["findings"] = findings

    log.info(
        "hunt_completed",
        case_id=case_id,
        detections=result.get("artifacts_produced", 0),
        findings=len(findings),
    )

    return result
