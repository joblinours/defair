"""Hunting service — orchestrates threat hunting workflows.

Combines tool execution (Hayabusa, or Chainsaw with the pinned Sigma store)
with finding auto-creation. This is the high-level entry point for
detection workflows.
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
    engine: str = "hayabusa",
    rule_profile: str = "precise",
    min_severity: str = "medium",
) -> dict:
    """Run threat hunting on EVTX evidence (Hayabusa by default).

    ``engine="chainsaw"`` hunts with Chainsaw and the pinned Sigma rule store
    instead (see :func:`hunt_chainsaw`).

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
    if engine == "chainsaw":
        return await hunt_chainsaw(conn, input_path, case_id, evidence_id=evidence_id,
                                   rule_profile=rule_profile, min_severity=min_severity,
                                   output_base=output_base)
    if engine != "hayabusa":
        raise ValueError(f"Unknown hunting engine '{engine}' (hayabusa, chainsaw)")

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
    # Use resolved UUID from run_tool_and_normalize result
    resolved_case_id = result.get("case_id", case_id)
    findings = []
    if result.get("status") == "completed" and result.get("run_id"):
        findings = await auto_create_findings_from_hayabusa(
            conn, resolved_case_id, result["run_id"],
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


async def hunt_chainsaw(
    conn: aiosqlite.Connection,
    input_path: str,
    case_id: str,
    evidence_id: str | None = None,
    rule_profile: str = "precise",
    min_severity: str = "medium",
    sigma_rules_dir: str | None = None,
    output_base: str = "/workspace/analysis",
) -> dict:
    """Hunt EVTX with Chainsaw and the pinned Sigma store; one finding per rule."""
    from defair.services.scanning_service import auto_create_findings

    options: dict = {"profile": rule_profile}
    if sigma_rules_dir:
        options["sigma_rules_dir"] = sigma_rules_dir
    result = await analysis_service.run_tool_and_normalize(
        conn, tool_name="chainsaw", input_path=input_path, case_id=case_id,
        evidence_id=evidence_id, output_base=output_base, **options,
    )
    findings = 0
    if result.get("status") == "completed" and result.get("artifacts_produced", 0):
        findings = await auto_create_findings(
            conn, result["case_id"], result["run_id"], min_severity=min_severity, tool="chainsaw",
        )
    result["findings_created"] = findings
    result["engine"] = "chainsaw"
    result["rule_profile"] = rule_profile
    log.info("hunt_completed", engine="chainsaw", case_id=case_id,
             detections=result.get("artifacts_produced", 0), findings=findings)
    return result
