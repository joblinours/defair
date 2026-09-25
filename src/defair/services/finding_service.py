"""Finding service — CRUD and auto-creation of investigation findings.

Findings group related detections into actionable conclusions.
The auto-create function processes Hayabusa detections and groups
high/critical alerts by rule title into findings with MITRE mapping.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import aiosqlite
import structlog

from defair.models.finding import (
    FindingStatus,
    generate_finding_number,
)

log = structlog.get_logger(component="finding_service")


async def _next_finding_number(conn: aiosqlite.Connection) -> str:
    """Generate the next finding number."""
    cursor = await conn.execute(
        "SELECT MAX(CAST(SUBSTR(finding_number, 5) AS INTEGER)) FROM findings"
    )
    row = await cursor.fetchone()
    return generate_finding_number((row[0] or 0) + 1)


async def _insert_finding(conn: aiosqlite.Connection, values: tuple) -> None:
    await conn.execute(
        """INSERT INTO findings
        (id, finding_number, case_id, title, description,
         severity, confidence, status, source,
         mitre_tactics, mitre_techniques, artifact_ids, detection_refs,
         created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        values,
    )
    await conn.commit()


async def create_finding(
    conn: aiosqlite.Connection,
    case_id: str,
    title: str,
    description: str = "",
    severity: str = "medium",
    confidence: str = "medium",
    source: str = "",
    mitre_tactics: list[str] | None = None,
    mitre_techniques: list[str] | None = None,
    artifact_ids: list[str] | None = None,
    detection_refs: list[str] | None = None,
) -> dict:
    """Create a new finding."""
    from uuid import uuid4

    from defair.database import db_lock
    from defair.services.case_service import resolve_case_id

    case_id = await resolve_case_id(conn, case_id)
    finding_id = uuid4().hex
    now = datetime.now(UTC).isoformat()

    async with db_lock(conn):
        finding_number = await _next_finding_number(conn)
        await _insert_finding(conn, (
            finding_id, finding_number, case_id, title, description,
            severity, confidence, FindingStatus.OPEN.value, source,
            json.dumps(mitre_tactics or []),
            json.dumps(mitre_techniques or []),
            json.dumps(artifact_ids or []),
            json.dumps(detection_refs or []),
            now, now,
        ))

    log.info("finding_created", finding_number=finding_number, title=title)
    return {
        "id": finding_id,
        "finding_number": finding_number,
        "case_id": case_id,
        "title": title,
        "severity": severity,
        "status": "open",
    }


async def list_findings(
    conn: aiosqlite.Connection,
    case_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """List findings with optional filters."""
    query = "SELECT * FROM findings WHERE 1=1"
    params: list = []

    if case_id:
        from defair.services.case_service import resolve_case_id

        case_id = await resolve_case_id(conn, case_id)
        query += " AND case_id = ?"
        params.append(case_id)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if status:
        query += " AND status = ?"
        params.append(status)

    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    cursor = await conn.execute(query, params)
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_finding(
    conn: aiosqlite.Connection,
    finding_id_or_number: str,
) -> dict | None:
    """Get a finding by ID or finding number."""
    cursor = await conn.execute(
        "SELECT * FROM findings WHERE id = ? OR finding_number = ?",
        (finding_id_or_number, finding_id_or_number),
    )
    row = await cursor.fetchone()
    if row is None:
        return None
    return dict(row)


async def update_finding_status(
    conn: aiosqlite.Connection,
    finding_id_or_number: str,
    status: str,
) -> dict | None:
    """Update a finding's status."""
    finding = await get_finding(conn, finding_id_or_number)
    if finding is None:
        return None

    now = datetime.now(UTC).isoformat()
    await conn.execute(
        "UPDATE findings SET status = ?, updated_at = ? WHERE id = ?",
        (status, now, finding["id"]),
    )
    await conn.commit()

    finding["status"] = status
    finding["updated_at"] = now
    log.info("finding_status_updated", id=finding["id"], status=status)
    return finding


async def correlate_artifact(
    conn: aiosqlite.Connection,
    finding_id_or_number: str,
    artifact_id: str,
) -> dict | None:
    """Link an artifact to an existing finding."""
    finding = await get_finding(conn, finding_id_or_number)
    if finding is None:
        return None

    artifact_ids = json.loads(finding.get("artifact_ids", "[]"))
    if artifact_id not in artifact_ids:
        artifact_ids.append(artifact_id)

    now = datetime.now(UTC).isoformat()
    await conn.execute(
        "UPDATE findings SET artifact_ids = ?, updated_at = ? WHERE id = ?",
        (json.dumps(artifact_ids), now, finding["id"]),
    )
    await conn.commit()

    finding["artifact_ids"] = json.dumps(artifact_ids)
    return finding


async def auto_create_findings_from_hayabusa(
    conn: aiosqlite.Connection,
    case_id: str,
    run_id: str,
) -> list[dict]:
    """Auto-create findings from Hayabusa high/critical detections.

    Groups detections by rule_title and creates one finding per group,
    linking all matching artifact IDs and extracting MITRE data.

    Args:
        conn: DB connection.
        case_id: Case ID.
        run_id: Tool run ID that produced the Hayabusa artifacts.

    Returns:
        List of created findings.
    """
    # Fetch all Hayabusa alerts for this run
    cursor = await conn.execute(
        """SELECT id, artifact_type, severity, data
        FROM artifacts
        WHERE run_id = ?
          AND source_tool = 'hayabusa'
          AND severity IN ('critical', 'high')
        ORDER BY timestamp ASC""",
        (run_id,),
    )
    rows = await cursor.fetchall()

    if not rows:
        log.info("no_high_severity_hayabusa_detections", run_id=run_id)
        return []

    # Group by rule_title
    groups: dict[str, dict] = {}
    for row in rows:
        data = json.loads(row["data"]) if isinstance(row["data"], str) else row["data"]
        rule_title = data.get("rule_title", "Unknown")

        if rule_title not in groups:
            groups[rule_title] = {
                "severity": row["severity"],
                "artifact_ids": [],
                "mitre_tactics": set(),
                "mitre_techniques": set(),
                "detection_refs": set(),
                "count": 0,
            }

        g = groups[rule_title]
        g["artifact_ids"].append(row["id"])
        g["count"] += 1

        # Elevate severity if any detection is critical
        if row["severity"] == "critical":
            g["severity"] = "critical"

        # Collect MITRE data
        tactics = data.get("mitre_tactics", "")
        if tactics:
            for t in tactics.split(","):
                t = t.strip()
                if t:
                    g["mitre_tactics"].add(t)

        tags = data.get("mitre_tags", "")
        if tags:
            for t in tags.split(","):
                t = t.strip()
                if t:
                    g["mitre_techniques"].add(t)

        rule_file = data.get("rule_file", "")
        if rule_file:
            g["detection_refs"].add(rule_file)

    # Create one finding per group
    created = []
    for rule_title, g in groups.items():
        finding = await create_finding(
            conn,
            case_id=case_id,
            title=rule_title,
            description=f"Hayabusa detected {g['count']} occurrence(s) of: {rule_title}",
            severity=g["severity"],
            confidence="high" if g["count"] > 1 else "medium",
            source="hayabusa",
            mitre_tactics=sorted(g["mitre_tactics"]),
            mitre_techniques=sorted(g["mitre_techniques"]),
            artifact_ids=g["artifact_ids"],
            detection_refs=sorted(g["detection_refs"]),
        )
        created.append(finding)

    log.info(
        "findings_auto_created",
        count=len(created),
        from_detections=len(rows),
        run_id=run_id,
    )
    return created
