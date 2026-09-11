"""DEFAIR MCP server — FastMCP-based forensic tools.

Exposes forensic capabilities as MCP tools. Each tool calls the same
Service Layer used by the CLI — no business logic lives here.

Transport: stdio (standard for Claude Desktop / Claude Code integration).
"""

from __future__ import annotations

from pathlib import Path

import aiosqlite
from fastmcp import FastMCP

from defair.config import load_config
from defair.database import get_initialized_connection
from defair.logging import configure_logging, get_logger, new_correlation_id
from defair.services import case_service

# Initialize config and logging
_config = load_config()
configure_logging(_config.logging)
log = get_logger("mcp_server")

# Create MCP server
mcp = FastMCP(
    "defair",
    instructions=(
        "DEFAIR — Digital Forensics & Incident Response platform. "
        "Use these tools to manage forensic cases, register evidence, "
        "and conduct investigations. All operations are traced and reproducible."
    ),
)

# Lazy database connection
_db_conn: aiosqlite.Connection | None = None


async def _get_db() -> aiosqlite.Connection:
    """Get or create the database connection (lazy init)."""
    global _db_conn
    if _db_conn is None:
        db_path = Path(_config.storage.database)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        _db_conn = await get_initialized_connection(db_path)
        log.info("database_connected", db_path=str(db_path))
    return _db_conn


# ---------------------------------------------------------------------------
# MCP Tools — Case management
# ---------------------------------------------------------------------------


@mcp.tool()
async def list_cases() -> list[dict]:
    """List all forensic cases.

    Returns a list of cases with their case number, name, status,
    and creation date. Cases are ordered by creation date (newest first).
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="list_cases", correlation_id=cid)

    conn = await _get_db()
    cases = await case_service.list_cases(conn)
    return [c.model_dump(mode="json") for c in cases]


@mcp.tool()
async def create_case(name: str, description: str = "") -> dict:
    """Create a new forensic investigation case.

    Args:
        name: Name of the case (e.g. "Incident host-01 ransomware").
        description: Optional longer description of the case.

    Returns:
        The created case with its auto-generated case number (CASE-YYYY-NNN).
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="create_case", correlation_id=cid, name=name)

    conn = await _get_db()
    case = await case_service.create_case(conn, name, description)
    return case.model_dump(mode="json")


@mcp.tool()
async def get_case(case_id: str) -> dict | None:
    """Get details of a specific forensic case.

    Args:
        case_id: The case number (e.g. "CASE-2026-001") or internal UUID.

    Returns:
        The case details, or None if not found.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="get_case", correlation_id=cid, case_id=case_id)

    conn = await _get_db()
    case = await case_service.get_case(conn, case_id)
    if case is None:
        return None
    return case.model_dump(mode="json")


def main() -> None:
    """Entry point for the DEFAIR MCP server (stdio transport)."""
    log.info("mcp_server_starting", transport="stdio")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
