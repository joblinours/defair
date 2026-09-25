"""Host profile — who / what the analysed machine was, with a source per fact.

Assembled from what DEFAIR already knows about an evidence:

- Dissect's view of the system (``host_info`` recorded at preparation, or read
  now from the image / collection): hostname, domain, OS, version,
  architecture, timezone, install date, users, IPs — plus installed
  applications;
- registry artifacts in the case (RECmd / Dissect): time zone, network
  profiles, USB devices, services;
- EVTX artifacts: the computer names that appear in the logs.

Every field keeps where it came from (``dissect:<field>``, ``ART-NNN``,
``evtx``). When two sources disagree, the first one is the value and the
others are listed under ``conflicts`` — nothing is overwritten silently.
The profile is stored as one ``windows.system.host_profile`` artifact per
evidence (deterministic id: recomputing it replaces it).
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime

import aiosqlite
import structlog

log = structlog.get_logger(component="host_profile")

HOST_FIELDS = ("hostname", "domain", "os", "version", "architecture", "timezone", "install_date")
MAX_APPLICATIONS = 1000


def _add(profile: dict, field: str, value, source: str) -> None:
    """Record one observed value; a different value from another source is a conflict."""
    if value in (None, "", [], {}):
        return
    fields = profile["fields"]
    if field not in fields:
        fields[field] = {"value": value, "source": source}
        return
    if _same(fields[field]["value"], value):
        fields[field].setdefault("also", []).append(source)
        return
    profile["conflicts"].append({"field": field, "value": value, "source": source,
                                 "kept": fields[field]["value"], "kept_source": fields[field]["source"]})


def _same(a, b) -> bool:
    if isinstance(a, str) and isinstance(b, str):
        return a.strip().lower() == b.strip().lower()
    return a == b


def dissect_host(target_path: str) -> dict:
    """Host facts + installed applications read with Dissect (best effort)."""
    from defair.sources.image import host_info

    try:
        from dissect.target import Target
    except ImportError:
        return {}
    try:
        target = Target.open(target_path)
    except Exception as e:  # noqa: BLE001 — not every source is a Dissect target
        log.info("host_profile_dissect_unavailable", target=target_path, error=str(e))
        return {}
    info = host_info(target)
    applications = []
    try:
        for record in target.applications():
            applications.append({
                "name": getattr(record, "name", None),
                "version": getattr(record, "version", None),
                "publisher": getattr(record, "author", None) or getattr(record, "publisher", None),
                "installed": str(getattr(record, "ts_installed", "") or "") or None,
                "key_modified": str(getattr(record, "ts_modified", "") or "") or None,
                "type": getattr(record, "type", None),
                "path": str(getattr(record, "path", "") or "") or None,
            })
            if len(applications) >= MAX_APPLICATIONS:
                break
    except Exception as e:  # noqa: BLE001 — plugin absent for this OS / damaged hive
        log.info("host_profile_applications_unavailable", error=str(e))
    info["applications"] = applications
    return info


async def _registry_facts(conn, case_id: str, evidence_id: str | None, profile: dict) -> None:
    where = "case_id = ?" + (" AND (evidence_id = ? OR evidence_id IS NULL)" if evidence_id else "")
    params = [case_id, evidence_id] if evidence_id else [case_id]

    cursor = await conn.execute(
        f"SELECT artifact_number, data FROM artifacts WHERE {where} "
        "AND artifact_type = 'windows.registry.timezone' ORDER BY artifact_number LIMIT 5", params)
    for number, data in await cursor.fetchall():
        value = (json.loads(data or "{}")).get("value_data")
        if value:
            _add(profile, "timezone_registry", value, number)

    networks = []
    cursor = await conn.execute(
        f"SELECT artifact_number, description, timestamp FROM artifacts WHERE {where} "
        "AND artifact_type = 'windows.registry.network_profile' ORDER BY timestamp LIMIT 200", params)
    for number, description, timestamp in await cursor.fetchall():
        networks.append({"name": description, "last_write": timestamp, "artifact": number})
    _add(profile, "network_profiles", networks, "registry")

    usb = []
    cursor = await conn.execute(
        f"SELECT artifact_number, description, timestamp FROM artifacts WHERE {where} "
        "AND artifact_type IN ('windows.registry.usb_device', 'windows.evtx.usb_device') "
        "ORDER BY timestamp LIMIT 200", params)
    for number, description, timestamp in await cursor.fetchall():
        usb.append({"device": description, "time": timestamp, "artifact": number})
    _add(profile, "usb_devices", usb, "registry/evtx")

    cursor = await conn.execute(
        f"SELECT COUNT(*) FROM artifacts WHERE {where} AND artifact_type = 'windows.registry.service'",
        params)
    services = (await cursor.fetchone())[0]
    if services:
        _add(profile, "services_in_registry", services, "registry")

    cursor = await conn.execute(
        f"SELECT hostname, COUNT(*) AS n FROM artifacts WHERE {where} "
        "AND artifact_type LIKE 'windows.evtx.%' AND hostname IS NOT NULL AND hostname != '' "
        "GROUP BY hostname ORDER BY n DESC LIMIT 10", params)
    computers = [{"computer": h, "events": n} for h, n in await cursor.fetchall()]
    if computers:
        profile["evtx_computers"] = computers
        # the EVTX Computer is a FQDN: its first label is the hostname
        _add(profile, "hostname", computers[0]["computer"].split(".")[0], "evtx")


async def build_host_profile(
    conn: aiosqlite.Connection,
    case_id: str,
    evidence_id: str | None = None,
    live: bool = True,
) -> dict:
    """Assemble (and store) the host profile of one evidence.

    Args:
        case_id: Case number, name or id.
        evidence_id: Evidence number / id; the case's first evidence when omitted.
        live: Also read the evidence with Dissect now (collections, and fields
            missing from the preparation record).
    """
    from defair.services.case_service import resolve_case_id
    from defair.services.evidence_service import get_evidence, list_evidence

    case_id = await resolve_case_id(conn, case_id)
    evidence = await get_evidence(conn, evidence_id) if evidence_id else None
    if evidence is None:
        items = await list_evidence(conn, case_id=case_id)
        if evidence_id or not items:
            raise ValueError(f"Evidence not found: {evidence_id}" if evidence_id else "Case has no evidence")
        evidence = items[0]

    profile: dict = {"evidence": evidence.evidence_number, "fields": {}, "conflicts": [],
                     "generated_at": datetime.now(UTC).isoformat()}
    prepared = evidence.prepared or {}
    for field in HOST_FIELDS + ("users", "ips"):
        _add(profile, field, (prepared.get("host") or {}).get(field), f"dissect:{field} (prepare)")

    if live and prepared:
        from defair.orchestrator.steps import dissect_target

        try:
            target = dissect_target(prepared)
        except (KeyError, TypeError):
            target = None
        if target:
            live_info = await asyncio.to_thread(dissect_host, target)
            for field in HOST_FIELDS + ("users", "ips"):
                _add(profile, field, live_info.get(field), f"dissect:{field}")
            _add(profile, "applications", live_info.get("applications"), "dissect:applications")

    await _registry_facts(conn, case_id, evidence.id, profile)
    profile["summary"] = {k: v["value"] for k, v in profile["fields"].items()
                          if not isinstance(v["value"], list)}
    profile["artifact"] = await _store(conn, case_id, evidence, profile)
    return profile


async def _store(conn: aiosqlite.Connection, case_id: str, evidence, profile: dict) -> str:
    from defair.database import db_lock
    from defair.normalizers.pipeline import artifact_id, bulk_insert, next_artifact_sequence

    art_id = artifact_id(evidence.id, "host_profile")
    summary = profile["summary"]
    async with db_lock(conn):
        cursor = await conn.execute("SELECT artifact_number FROM artifacts WHERE id = ?", (art_id,))
        row = await cursor.fetchone()
        number = row[0] if row else f"ART-{await next_artifact_sequence(conn):03d}"
        await bulk_insert(conn, [{
            "id": art_id,
            "artifact_number": number,
            "case_id": case_id,
            "evidence_id": evidence.id,
            "artifact_type": "windows.system.host_profile",
            "category": "system_info",
            "source_tool": "defair",
            "source_file": evidence.original_path,
            "hostname": summary.get("hostname"),
            "description": f"Host profile: {summary.get('hostname') or 'unknown host'} "
                           f"({summary.get('version') or summary.get('os') or 'unknown OS'})",
            "message": None,
            "data": profile,
            "provenance": {"tool": "host_profile", "evidence_id": evidence.id,
                           "sources": sorted({v["source"] for v in profile["fields"].values()})},
            "record_key": f"host_profile:{evidence.evidence_number}",
            "created_at": datetime.now(UTC).isoformat(),
        }])
    return number


async def get_host_profile(conn: aiosqlite.Connection, case_id: str, evidence_id: str | None = None,
                           refresh: bool = False) -> dict:
    """The stored profile, built on first use (or on ``refresh``)."""
    from defair.services.case_service import resolve_case_id
    from defair.services.evidence_service import get_evidence

    if not refresh:
        resolved = await resolve_case_id(conn, case_id)
        params: list = [resolved]
        clause = ""
        if evidence_id:
            evidence = await get_evidence(conn, evidence_id)
            if evidence is None:
                raise ValueError(f"Evidence not found: {evidence_id}")
            clause = " AND evidence_id = ?"
            params.append(evidence.id)
        cursor = await conn.execute(
            "SELECT artifact_number, data FROM artifacts WHERE case_id = ? "
            f"AND artifact_type = 'windows.system.host_profile'{clause} ORDER BY created_at DESC LIMIT 1",
            params)
        row = await cursor.fetchone()
        if row:
            return {**json.loads(row[1]), "artifact": row[0]}
    return await build_host_profile(conn, case_id, evidence_id)
