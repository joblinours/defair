"""DEFAIR MCP server — FastMCP-based forensic tools.

Exposes forensic capabilities as MCP tools. Case and evidence operations
are proxied into forensic containers via docker exec. Container management
runs directly on the host via Docker SDK.

Transport: stdio (standard for Claude Desktop / Claude Code integration).
"""

from __future__ import annotations

from fastmcp import FastMCP

from defair.config import load_config
from defair.logging import configure_logging, get_logger, new_correlation_id
from defair.services import container_service

# Initialize config and logging
_config = load_config()
configure_logging(_config.logging)
log = get_logger("mcp_server")

# Create MCP server
mcp = FastMCP(
    "defair",
    instructions=(
        "DEFAIR — Digital Forensics & Incident Response platform. "
        "Use these tools to manage forensic containers, cases, evidence, "
        "and conduct investigations. All case/evidence operations run "
        "inside isolated Docker containers. "
        "Typical workflow: create_container → create_case → register_evidence → analyze."
    ),
)


# ---------------------------------------------------------------------------
# Helper — proxy a defair command into a container and parse JSON output
# ---------------------------------------------------------------------------


async def _proxy_defair(container_name: str, args: list[str]) -> dict | list | str:
    """Execute a defair CLI command inside a container and return parsed output.

    Args:
        container_name: Target container.
        args: CLI args (e.g. ["case", "create", "My case", "--description", "..."]).

    Returns:
        Parsed JSON if the command outputs JSON, otherwise raw stdout text.
    """
    result = await container_service.exec_in_container(
        container_name,
        ["defair", *args],
    )

    if result["exit_code"] != 0:
        error_msg = result["stderr"] or result["stdout"] or "Command failed"
        raise RuntimeError(
            f"Command failed in container '{container_name}' (exit {result['exit_code']}): {error_msg}"
        )

    return result["stdout"]


# ---------------------------------------------------------------------------
# MCP Tools — Container orchestration (run on host)
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
        case_id: Case identifier for the container name (e.g. "CASE-2026-001").
                 This is just a label — the case will be created inside the container.
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


# ---------------------------------------------------------------------------
# MCP Tools — Case management (proxied into container)
# ---------------------------------------------------------------------------


@mcp.tool()
async def create_case(container: str, name: str, description: str = "") -> str:
    """Create a new forensic investigation case inside a container.

    Args:
        container: Container name (e.g. "defair-case-2026-001").
        name: Name of the case (e.g. "Incident host-01 ransomware").
        description: Optional longer description.

    Returns:
        Command output with the created case details.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="create_case", correlation_id=cid,
             container=container, name=name)

    cmd = ["case", "create", name]
    if description:
        cmd.extend(["--description", description])
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def list_cases(container: str) -> str:
    """List all forensic cases in a container.

    Args:
        container: Container name (e.g. "defair-case-2026-001").

    Returns:
        Table of cases with case number, name, status, and creation date.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="list_cases", correlation_id=cid,
             container=container)

    return await _proxy_defair(container, ["cases", "list"])


@mcp.tool()
async def get_case(container: str, case_id: str) -> str:
    """Get details of a specific forensic case.

    Args:
        container: Container name.
        case_id: The case number (e.g. "CASE-2026-001") or internal UUID.

    Returns:
        Case details.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="get_case", correlation_id=cid,
             container=container, case_id=case_id)

    return await _proxy_defair(container, ["case", "get", case_id])


# ---------------------------------------------------------------------------
# MCP Tools — Evidence management (proxied into container)
# ---------------------------------------------------------------------------


@mcp.tool()
async def register_evidence(
    container: str,
    case_id: str,
    path: str,
    evidence_type: str = "other",
) -> str:
    """Register a new piece of evidence in a forensic case.

    The path must be accessible inside the container (e.g. /evidence/disk.E01).
    Evidence files are mounted read-only when the container is created.

    Args:
        container: Container name.
        case_id: Case number (e.g. "CASE-2026-001") or UUID.
        path: Path to the evidence file INSIDE the container.
        evidence_type: Type — disk_image, memory_dump, logs, triage_archive, pcap, other.

    Returns:
        Registration details with SHA-256 hash.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="register_evidence", correlation_id=cid,
             container=container, case_id=case_id, path=path)

    return await _proxy_defair(
        container, ["evidence", "add", case_id, path, "--type", evidence_type]
    )


@mcp.tool()
async def list_evidence(container: str, case_id: str | None = None) -> str:
    """List registered evidence items in a container.

    Args:
        container: Container name.
        case_id: Optional — filter by case number or UUID.

    Returns:
        Table of evidence items.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="list_evidence", correlation_id=cid,
             container=container, case_id=case_id)

    cmd = ["evidence", "list"]
    if case_id:
        cmd.extend(["--case", case_id])
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def get_evidence(container: str, evidence_id: str) -> str:
    """Get details of a specific evidence item.

    Args:
        container: Container name.
        evidence_id: Evidence number (e.g. "EVD-001") or internal UUID.

    Returns:
        Evidence details with metadata and hash.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="get_evidence", correlation_id=cid,
             container=container, evidence_id=evidence_id)

    return await _proxy_defair(container, ["evidence", "get", evidence_id])


@mcp.tool()
async def verify_evidence(container: str, evidence_id: str) -> str:
    """Verify evidence integrity by re-computing its SHA-256 hash.

    Compares the current file hash against the hash stored at registration.
    Critical forensic operation to detect evidence tampering.

    Args:
        container: Container name.
        evidence_id: Evidence number (e.g. "EVD-001") or internal UUID.

    Returns:
        Verification result (ok, mismatch, or missing).
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="verify_evidence", correlation_id=cid,
             container=container, evidence_id=evidence_id)

    return await _proxy_defair(container, ["evidence", "verify", evidence_id])


def main() -> None:
    """Entry point for the DEFAIR MCP server (stdio transport)."""
    log.info("mcp_server_starting", transport="stdio")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
