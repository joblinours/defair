"""Evidence service — async operations for forensic evidence management.

This is the shared service layer called by both CLI and MCP.
Evidence is always treated as read-only — only metadata and hashes are stored.
"""

from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timezone
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

    Computes SHA-256 hash of the file and stores metadata.
    The original file is never modified or copied.
    """
    file_path = Path(path).resolve()

    if not file_path.exists():
        raise FileNotFoundError(f"Evidence file not found: {file_path}")
    if not file_path.is_file():
        raise ValueError(f"Evidence path is not a file: {file_path}")

    # Verify case exists
    cursor = await conn.execute("SELECT id FROM cases WHERE id = ? OR case_number = ?", (case_id, case_id))
    case_row = await cursor.fetchone()
    if case_row is None:
        raise ValueError(f"Case not found: {case_id}")
    resolved_case_id = case_row["id"]

    # Compute SHA-256 (offloaded to thread for large files)
    sha256 = await asyncio.to_thread(_compute_sha256, file_path)
    size_bytes = file_path.stat().st_size

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
        registered_at=datetime.now(timezone.utc),
    )

    await conn.execute(
        """INSERT INTO evidence
           (id, evidence_number, case_id, type, original_path, filename,
            size_bytes, sha256, read_only, registered_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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


def _compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 hash of a file using chunked reading."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(_HASH_CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()
