"""Evidence service — async operations for forensic evidence management.

This is the shared service layer called by both CLI and MCP.
Evidence is always treated as read-only — only metadata and hashes are stored.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import aiosqlite
import structlog

from defair.models.evidence import Evidence, EvidenceType, generate_evidence_number

log = structlog.get_logger(component="evidence_service")

# Chunk size for hashing large files (8 KB)
_HASH_CHUNK_SIZE = 8192


async def add_evidence(
    conn: aiosqlite.Connection,
    case_id: str,
    path: str | Path,
    evidence_type: str = "other",
) -> Evidence:
    """Register a new piece of evidence in a case.

    A file is hashed (SHA-256); a directory — a triage collection — gets a
    tree hash (see :func:`compute_tree_hash`). The source format is detected
    and stored. The original is never modified or copied.
    """
    from defair.sources.detect import detect_source

    file_path = Path(path).resolve()

    if not file_path.exists():
        raise FileNotFoundError(f"Evidence file not found: {file_path}")
    is_dir = file_path.is_dir()
    if is_dir and evidence_type == "other":
        evidence_type = EvidenceType.COLLECTION.value

    # Verify case exists (UUID, case number or name)
    from defair.services.case_service import resolve_case_id

    resolved_case_id = await resolve_case_id(conn, case_id)

    # Compute SHA-256 / tree hash (offloaded to a thread for large evidence)
    if is_dir:
        sha256, size_bytes = await asyncio.to_thread(compute_tree_hash, file_path)
    else:
        sha256 = await asyncio.to_thread(_compute_sha256, file_path)
        size_bytes = file_path.stat().st_size
    source = await asyncio.to_thread(detect_source, file_path)

    # Get next evidence number
    cursor = await conn.execute(
        "SELECT evidence_number FROM evidence ORDER BY evidence_number DESC LIMIT 1"
    )
    row = await cursor.fetchone()
    if row:
        last_seq = int(row["evidence_number"].split("-")[-1])
        sequence = last_seq + 1
    else:
        sequence = 1

    evidence = Evidence(
        evidence_number=generate_evidence_number(sequence),
        case_id=resolved_case_id,
        type=EvidenceType(evidence_type),
        original_path=str(file_path),
        filename=file_path.name,
        size_bytes=size_bytes,
        sha256=sha256,
        source_kind=source.kind,
        source_info=source.model_dump(),
        registered_at=datetime.now(UTC),
    )

    await conn.execute(
        """INSERT INTO evidence
           (id, evidence_number, case_id, type, original_path, filename,
            size_bytes, sha256, read_only, registered_at, source_kind, source_info)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            evidence.id,
            evidence.evidence_number,
            evidence.case_id,
            evidence.type.value,
            evidence.original_path,
            evidence.filename,
            evidence.size_bytes,
            evidence.sha256,
            1,  # read_only = True
            evidence.registered_at.isoformat(),
            evidence.source_kind,
            json.dumps(evidence.source_info),
        ),
    )
    await conn.commit()

    log.info(
        "evidence_added",
        evidence_id=evidence.id,
        evidence_number=evidence.evidence_number,
        case_id=resolved_case_id,
        filename=evidence.filename,
        sha256=sha256,
        size_bytes=size_bytes,
    )
    return evidence


async def list_evidence(
    conn: aiosqlite.Connection,
    case_id: str | None = None,
) -> list[Evidence]:
    """List all evidence, optionally filtered by case.

    Args:
        conn: Database connection.
        case_id: If provided, only return evidence for this case (ID or case_number).
    """
    if case_id:
        # Resolve case_id (UUID, case number or name)
        from defair.services.case_service import resolve_case_id

        resolved_case_id = await resolve_case_id(conn, case_id)

        cursor = await conn.execute(
            "SELECT * FROM evidence WHERE case_id = ? ORDER BY registered_at DESC",
            (resolved_case_id,),
        )
    else:
        cursor = await conn.execute(
            "SELECT * FROM evidence ORDER BY registered_at DESC"
        )

    rows = await cursor.fetchall()
    return [_row_to_evidence(row) for row in rows]


async def get_evidence(
    conn: aiosqlite.Connection,
    evidence_id: str,
) -> Evidence | None:
    """Get a specific evidence item by ID or evidence number.

    Args:
        conn: Database connection.
        evidence_id: Evidence UUID or evidence number (e.g. "EVD-001").
    """
    cursor = await conn.execute(
        "SELECT * FROM evidence WHERE id = ? OR evidence_number = ?",
        (evidence_id, evidence_id),
    )
    row = await cursor.fetchone()
    if row is None:
        return None
    return _row_to_evidence(row)


async def verify_evidence(
    conn: aiosqlite.Connection,
    evidence_id: str,
) -> dict:
    """Verify evidence integrity by re-computing SHA-256 and comparing.

    Args:
        conn: Database connection.
        evidence_id: Evidence UUID or evidence number (e.g. "EVD-001").

    Returns:
        Dict with keys: evidence_number, filename, original_sha256,
        current_sha256, verified (bool), status ("ok" | "mismatch" | "missing").
    """
    evidence = await get_evidence(conn, evidence_id)
    if evidence is None:
        raise ValueError(f"Evidence not found: {evidence_id}")

    file_path = Path(evidence.original_path)
    result = {
        "evidence_number": evidence.evidence_number,
        "evidence_id": evidence.id,
        "filename": evidence.filename,
        "original_sha256": evidence.sha256,
    }

    if not file_path.exists():
        log.warning(
            "evidence_file_missing",
            evidence_id=evidence.id,
            path=str(file_path),
        )
        result.update(
            current_sha256=None,
            verified=False,
            status="missing",
            message=f"File not found: {file_path}",
        )
        return result

    if file_path.is_dir():
        current_sha256, _ = await asyncio.to_thread(compute_tree_hash, file_path)
    else:
        current_sha256 = await asyncio.to_thread(_compute_sha256, file_path)
    verified = current_sha256 == evidence.sha256

    if verified:
        log.info(
            "evidence_verified",
            evidence_id=evidence.id,
            status="ok",
        )
        result.update(
            current_sha256=current_sha256,
            verified=True,
            status="ok",
            message="Integrity verified — SHA-256 matches.",
        )
    else:
        log.warning(
            "evidence_integrity_mismatch",
            evidence_id=evidence.id,
            original_sha256=evidence.sha256,
            current_sha256=current_sha256,
        )
        result.update(
            current_sha256=current_sha256,
            verified=False,
            status="mismatch",
            message="INTEGRITY FAILURE — SHA-256 does not match!",
        )

    return result


def _row_to_evidence(row: aiosqlite.Row) -> Evidence:
    """Convert a database row to an Evidence model."""
    return Evidence(
        id=row["id"],
        evidence_number=row["evidence_number"],
        case_id=row["case_id"],
        type=EvidenceType(row["type"]),
        original_path=row["original_path"],
        filename=row["filename"],
        size_bytes=row["size_bytes"],
        sha256=row["sha256"],
        read_only=bool(row["read_only"]),
        source_kind=_col(row, "source_kind"),
        source_info=json.loads(_col(row, "source_info") or "{}"),
        prepared=json.loads(_col(row, "prepared") or "{}"),
        registered_at=datetime.fromisoformat(row["registered_at"]),
    )


def _col(row: aiosqlite.Row, name: str):
    return row[name] if name in row.keys() else None  # noqa: SIM118 — sqlite Row, not a dict


def compute_tree_hash(root: Path) -> tuple[str, int]:
    """Integrity hash of a directory tree.

    SHA-256 over the sorted lines ``<relative path>\0<file sha256>\n`` —
    any added, removed, renamed or modified file changes it. Returns the hash
    and the total size in bytes.
    """
    lines = []
    total = 0
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        lines.append(f"{rel}\0{_compute_sha256(path)}\n")
        total += path.stat().st_size
    h = hashlib.sha256()
    for line in lines:
        h.update(line.encode("utf-8", errors="surrogateescape"))
    return h.hexdigest(), total


def _compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 hash of a file using chunked reading."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(_HASH_CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()
