"""Search service — IOC search across all artifacts.

Searches for indicators of compromise (IP, hash, domain, filename, etc.)
across artifact descriptions, data JSON, hostnames, usernames, and source files.
"""

from __future__ import annotations

import aiosqlite
import structlog

log = structlog.get_logger(component="search_service")


async def search_ioc(
    conn: aiosqlite.Connection,
    case_id: str,
    value: str,
    limit: int = 200,
) -> dict:
    """Search for an IOC value across all artifacts in a case.

    Searches: description, data (JSON), hostname, username, source_file.

    Args:
        conn: DB connection.
        case_id: Case to search.
        value: IOC value to look for.
        limit: Max results.

    Returns:
        Dict with ioc, matches, match_count, tools_matched.
    """
    from defair.services.case_service import resolve_case_id

    case_id = await resolve_case_id(conn, case_id)

    like = f"%{value}%"

    cursor = await conn.execute(
        """SELECT * FROM artifacts
        WHERE case_id = ?
          AND (
            description LIKE ?
            OR data LIKE ?
            OR hostname LIKE ?
            OR username LIKE ?
            OR source_file LIKE ?
          )
        ORDER BY timestamp ASC
        LIMIT ?""",
        (case_id, like, like, like, like, like, limit),
    )
    rows = await cursor.fetchall()
    matches = [dict(r) for r in rows]

    # Collect unique tools
    tools_matched = sorted({m["source_tool"] for m in matches if m.get("source_tool")})

    result = {
        "ioc": value,
        "matches": matches,
        "match_count": len(matches),
        "tools_matched": tools_matched,
    }

    log.info(
        "ioc_search_completed",
        ioc=value,
        match_count=len(matches),
        case_id=case_id,
    )
    return result
