"""Case service — async CRUD operations for forensic cases.

This is the shared service layer called by both CLI and MCP.
No business logic should live in the CLI or MCP layers.
"""

from __future__ import annotations

from datetime import UTC, datetime

import aiosqlite
import structlog

from defair.models.case import Case, CaseStatus, generate_case_number

log = structlog.get_logger(component="case_service")


async def create_case(
    conn: aiosqlite.Connection,
    name: str,
    description: str = "",
) -> Case:
    """Create a new forensic case with an auto-generated case number."""
    now = datetime.now(UTC)
    year = now.year

    # Get next sequence number for the current year
    cursor = await conn.execute(
        "SELECT case_number FROM cases WHERE case_number LIKE ? ORDER BY case_number DESC LIMIT 1",
        (f"CASE-{year:04d}-%",),
    )
    row = await cursor.fetchone()

    if row:
        # Extract sequence from "CASE-YYYY-NNN"
        last_seq = int(row["case_number"].split("-")[-1])
        sequence = last_seq + 1
    else:
        sequence = 1

    case = Case(
        case_number=generate_case_number(year, sequence),
        name=name,
        description=description,
        status=CaseStatus.ACTIVE,
        created_at=now,
        updated_at=now,
    )

    await conn.execute(
        """INSERT INTO cases (id, case_number, name, description, status, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            case.id,
            case.case_number,
            case.name,
            case.description,
            case.status.value,
            case.created_at.isoformat(),
            case.updated_at.isoformat(),
        ),
    )
    await conn.commit()

    log.info("case_created", case_id=case.id, case_number=case.case_number, name=name)
    return case


async def list_cases(conn: aiosqlite.Connection) -> list[Case]:
    """List all forensic cases, ordered by creation date descending."""
    cursor = await conn.execute(
        "SELECT * FROM cases ORDER BY created_at DESC"
    )
    rows = await cursor.fetchall()
    return [_row_to_case(row) for row in rows]


async def _find_case_row(conn: aiosqlite.Connection, ref: str) -> aiosqlite.Row | None:
    """Find a case by UUID, case number (CASE-YYYY-NNN) or name.

    Names match case-insensitively; a name shared by several cases is refused
    (use the case number) rather than silently picking one.
    """
    ref = (ref or "").strip()
    cursor = await conn.execute(
        "SELECT * FROM cases WHERE id = ? OR case_number = ?", (ref, ref.upper())
    )
    row = await cursor.fetchone()
    if row is not None:
        return row
    cursor = await conn.execute("SELECT * FROM cases WHERE lower(name) = lower(?)", (ref,))
    rows = await cursor.fetchall()
    if len(rows) > 1:
        numbers = ", ".join(r["case_number"] for r in rows)
        raise ValueError(f"Several cases are named '{ref}' ({numbers}): use the case number")
    return rows[0] if rows else None


async def get_case(
    conn: aiosqlite.Connection,
    case_id_or_number: str,
) -> Case | None:
    """Get a case by its internal ID, case number (CASE-YYYY-NNN) or name."""
    row = await _find_case_row(conn, case_id_or_number)
    return _row_to_case(row) if row is not None else None


async def resolve_case_id(
    conn: aiosqlite.Connection,
    case_id_or_number: str,
) -> str:
    """Resolve a case UUID, case number (CASE-YYYY-NNN) or case name to the UUID.

    Raises:
        ValueError: If the case cannot be found (or the name is ambiguous).
    """
    row = await _find_case_row(conn, case_id_or_number)
    if row is None:
        raise ValueError(f"Case not found: {case_id_or_number}")
    return row["id"]


def _row_to_case(row: aiosqlite.Row) -> Case:
    """Convert a database row to a Case model."""
    return Case(
        id=row["id"],
        case_number=row["case_number"],
        name=row["name"],
        description=row["description"],
        status=CaseStatus(row["status"]),
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
    )
