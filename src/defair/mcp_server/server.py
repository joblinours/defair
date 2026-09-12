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
from defair.services import case_service, container_service, evidence_service

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


# ---------------------------------------------------------------------------
# MCP Tools — Evidence management
# ---------------------------------------------------------------------------


@mcp.tool()
async def register_evidence(
    case_id: str,
    path: str,
    evidence_type: str = "other",
) -> dict:
    """Register a new piece of evidence in a forensic case.

    Computes SHA-256 hash of the file and stores metadata.
    The original file is never modified or copied.

    Args:
        case_id: Case number (e.g. "CASE-2026-001") or UUID.
        path: Absolute path to the evidence file.
        evidence_type: Type of evidence — one of: disk_image, memory_dump,
                       logs, triage_archive, pcap, other.

    Returns:
        The registered evidence with its hash, evidence number, and metadata.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="register_evidence", correlation_id=cid,
             case_id=case_id, path=path)

    conn = await _get_db()
    evidence = await evidence_service.add_evidence(conn, case_id, path, evidence_type)
    return evidence.model_dump(mode="json")


@mcp.tool()
async def list_evidence(case_id: str | None = None) -> list[dict]:
    """List registered evidence items.

    Args:
        case_id: Optional — filter by case number (e.g. "CASE-2026-001") or UUID.
                 If omitted, returns all evidence across all cases.

    Returns:
        List of evidence items with their metadata and hashes.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="list_evidence", correlation_id=cid,
             case_id=case_id)

    conn = await _get_db()
    items = await evidence_service.list_evidence(conn, case_id)
    return [e.model_dump(mode="json") for e in items]


@mcp.tool()
async def get_evidence(evidence_id: str) -> dict | None:
    """Get details of a specific evidence item.

    Args:
        evidence_id: Evidence number (e.g. "EVD-001") or internal UUID.

    Returns:
        Evidence details with metadata and hash, or None if not found.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="get_evidence", correlation_id=cid,
             evidence_id=evidence_id)

    conn = await _get_db()
    evidence = await evidence_service.get_evidence(conn, evidence_id)
    if evidence is None:
        return None
    return evidence.model_dump(mode="json")


@mcp.tool()
async def verify_evidence(evidence_id: str) -> dict:
    """Verify evidence integrity by re-computing its SHA-256 hash.

    Compares the current file hash against the hash stored at registration.
    This is a critical forensic operation to detect evidence tampering.

    Args:
        evidence_id: Evidence number (e.g. "EVD-001") or internal UUID.

    Returns:
        Verification result with status ("ok", "mismatch", or "missing"),
        original and current SHA-256 hashes, and a human-readable message.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="verify_evidence", correlation_id=cid,
             evidence_id=evidence_id)

    conn = await _get_db()
    return await evidence_service.verify_evidence(conn, evidence_id)


# ---------------------------------------------------------------------------
# MCP Tools — Container orchestration
# ---------------------------------------------------------------------------


@mcp.tool()
async def create_container(
    case_id: str | None = None,
    name: str | None = None,
    image: str = container_service.DEFAULT_IMAGE,
    evidence_paths: list[str] | None = None,
    start: bool = True,
) -> dict:
    """Create a new DEFAIR forensic container.

    Creates an isolated Docker container for a forensic investigation.
    Evidence is mounted read-only, workspace is persistent.

    Args:
        case_id: Case number (e.g. "CASE-2026-001") to associate.
        name: Container name (auto-generated from case_id if omitted).
        image: Docker image (default: ghcr.io/joblinours/defair:latest).
        evidence_paths: Host paths to mount as read-only evidence.
        start: Whether to start the container after creation (default: True).

    Returns:
        Container details (name, ID, status, workspace path).
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="create_container", correlation_id=cid,
             case_id=case_id)

    info = await container_service.create_container(
        case_id=case_id,
        name=name,
        image=image,
        evidence_paths=evidence_paths,
    )

    if start:
        info = await container_service.start_container(info.name)

    return info.to_dict()


@mcp.tool()
async def list_containers(
    all_states: bool = True,
    case_id: str | None = None,
) -> list[dict]:
    """List DEFAIR forensic containers.

    Args:
        all_states: Include stopped containers (default: True).
        case_id: Filter by case ID/number.

    Returns:
        List of containers with their status, image, and case association.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="list_containers", correlation_id=cid)

    containers = await container_service.list_containers(
        all_states=all_states, case_id=case_id
    )
    return [c.to_dict() for c in containers]


@mcp.tool()
async def get_container_info(name_or_id: str) -> dict | None:
    """Get details of a specific DEFAIR container.

    Args:
        name_or_id: Container name or ID.

    Returns:
        Container details, or None if not found.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="get_container_info", correlation_id=cid,
             name=name_or_id)

    info = await container_service.get_container(name_or_id)
    if info is None:
        return None
    return info.to_dict()


@mcp.tool()
async def start_container(name_or_id: str) -> dict:
    """Start a stopped DEFAIR forensic container.

    Args:
        name_or_id: Container name or ID.

    Returns:
        Updated container details with new status.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="start_container", correlation_id=cid,
             name=name_or_id)

    info = await container_service.start_container(name_or_id)
    return info.to_dict()


@mcp.tool()
async def stop_container(name_or_id: str, timeout: int = 10) -> dict:
    """Stop a running DEFAIR forensic container.

    Args:
        name_or_id: Container name or ID.
        timeout: Seconds to wait before killing (default: 10).

    Returns:
        Updated container details with new status.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="stop_container", correlation_id=cid,
             name=name_or_id)

    info = await container_service.stop_container(name_or_id, timeout=timeout)
    return info.to_dict()


@mcp.tool()
async def remove_container(name_or_id: str, force: bool = False) -> dict:
    """Remove a DEFAIR forensic container.

    Args:
        name_or_id: Container name or ID.
        force: Force removal even if running (default: False).

    Returns:
        Confirmation with the name of the removed container.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="remove_container", correlation_id=cid,
             name=name_or_id)

    return await container_service.remove_container(name_or_id, force=force)


@mcp.tool()
async def exec_in_container(
    name_or_id: str,
    command: str,
    workdir: str | None = None,
) -> dict:
    """Execute a command inside a running DEFAIR container.

    Use this to run forensic tools inside an isolated container.
    The container must be running.

    Args:
        name_or_id: Container name or ID.
        command: Shell command to execute (e.g. "ls -la /evidence").
        workdir: Working directory inside the container.

    Returns:
        Execution result with exit_code, stdout, and stderr.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="exec_in_container", correlation_id=cid,
             name=name_or_id, command=command)

    return await container_service.exec_in_container(
        name_or_id, command, workdir=workdir
    )


@mcp.tool()
async def container_logs(name_or_id: str, tail: int = 100) -> str:
    """Get logs from a DEFAIR forensic container.

    Args:
        name_or_id: Container name or ID.
        tail: Number of lines from the end (default: 100).

    Returns:
        Container log output as text.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="container_logs", correlation_id=cid,
             name=name_or_id)

    return await container_service.container_logs(name_or_id, tail=tail)


def main() -> None:
    """Entry point for the DEFAIR MCP server (stdio transport)."""
    log.info("mcp_server_starting", transport="stdio")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
