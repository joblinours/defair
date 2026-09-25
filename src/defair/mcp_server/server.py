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


async def _proxy_defair(
    container_name: str,
    args: list[str],
    env: dict[str, str] | None = None,
) -> dict | list | str:
    """Execute a defair CLI command inside a container and return parsed output.

    Args:
        container_name: Target container.
        args: CLI args (e.g. ["case", "create", "My case", "--description", "..."]).
        env: Extra environment for the exec — secrets travel here, never in
            ``args`` (the command line is logged).

    Returns:
        Parsed JSON if the command outputs JSON, otherwise raw stdout text.
    """
    kwargs = {"env": env} if env else {}
    result = await container_service.exec_in_container(
        container_name,
        ["defair", *args],
        **kwargs,
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
    keys_path: str | None = None,
) -> dict:
    """Create a new DEFAIR forensic container.

    Creates an isolated Docker container for a forensic investigation.
    Evidence is mounted read-only, workspace is persistent.

    Args:
        case_id: Case identifier for the container name (e.g. "CASE-2026-001").
                 This is just a label — the case will be created inside the container.
        name: Container name (auto-generated from case_id if omitted).
        image: Docker image (default: ghcr.io/joblinours/defair:latest).
        evidence_paths: Host paths to mount as read-only evidence. Must be under
                        one of the configured evidence roots (container.evidence_roots).
        start: Whether to start the container after creation (default: True).
        keys_path: Host directory of private keys for encrypted DFIR-ORC /
                   Generaptor collections, mounted read-only at /keys. Must be
                   under container.key_roots.

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
        policy=_config.container,
        strict_evidence_roots=True,
        keys_path=keys_path,
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


# Arbitrary shell execution is opt-in (mcp.allow_exec). By default agents only
# get run_tool: registered tools, validated arguments, recorded as ToolRuns.
if _config.mcp.allow_exec:
    mcp.tool()(exec_in_container)


@mcp.tool()
async def run_tool(
    container: str,
    tool: str,
    input_path: str,
    case_id: str,
    evidence_id: str | None = None,
    options: dict | None = None,
    directory: bool = False,
) -> str:
    """Run a registered forensic tool inside a DEFAIR container.

    The safe alternative to a shell: only tools from the registry (see
    list_tools) can run, the input must be under /evidence, /workspace or
    /rules, and options must be declared in the tool manifest (see
    list_tools / tools info). Every execution is recorded as a ToolRun and
    its output normalized into artifacts.

    Args:
        container: Container name.
        tool: Registered tool name (e.g. "mftecmd", "hayabusa").
        input_path: File or directory inside the container.
        case_id: Case number.
        evidence_id: Optional evidence ID.
        options: Tool options, e.g. {"min_level": "high"} for hayabusa.
        directory: Input is a directory.

    Returns:
        Run summary (run number, status, artifacts produced).
    """
    from defair.services.analysis_service import validate_tool_request

    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="run_tool", correlation_id=cid,
             container=container, target_tool=tool, input_path=input_path)

    validated = validate_tool_request(tool, input_path, options, strict_paths=True)

    cmd = ["analyze", tool, input_path, "--case", case_id]
    if evidence_id:
        cmd.extend(["--evidence", evidence_id])
    if directory:
        cmd.append("--directory")
    for key, value in validated.items():
        rendered = str(value).lower() if isinstance(value, bool) else str(value)
        cmd.extend(["--option", f"{key}={rendered}"])
    return await _proxy_defair(container, cmd)


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

    The path must be accessible inside the container: a file (disk image,
    archive, EVTX…) or a collection folder (KAPE, Velociraptor, FastIR…).
    Files are SHA-256 hashed, folders get a tree hash; the source format is
    detected (see `needs` in the result: password / private_key).

    Args:
        container: Container name.
        case_id: Case number (e.g. "CASE-2026-001") or UUID.
        path: Path to the evidence file or folder INSIDE the container.
        evidence_type: Type — disk_image, memory_dump, logs, triage_archive,
                       collection, pcap, other (folders default to collection).

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


# ---------------------------------------------------------------------------
# MCP Tools — Discovery & Analysis (v0.2 — proxied into container)
# ---------------------------------------------------------------------------


@mcp.tool()
async def discover_evidence(container: str, evidence_path: str = "/evidence") -> str:
    """Discover forensic artifacts in evidence.

    Scans the evidence path inside a container to identify available
    Windows artifacts (registry, event logs, prefetch, MFT, etc.)
    and recommends which tools to run.

    Based on SANS FOR500 artifact categories:
    - Program Execution (Prefetch, Amcache, Shimcache, UserAssist, BAM/DAM)
    - File Download (MRU, Browser downloads, ADS Zone.Identifier)
    - File/Folder Opening (Shell Bags, LNK, Jump Lists, Recent Files)
    - Deleted File Knowledge (Recycle Bin, Thumbcache)
    - Network Activity (SRUM, WLAN logs, Network History)
    - External Device/USB (Registry keys, PnP events)
    - Account Usage (SAM, Event Logs, RDP)
    - Browser Usage (History, Cookies, Downloads)

    Args:
        container: Container name.
        evidence_path: Path to scan inside the container (default: /evidence).

    Returns:
        Discovery results with artifact types and recommended tools.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="discover_evidence", correlation_id=cid,
             container=container)

    return await _proxy_defair(container, ["discover", evidence_path])


@mcp.tool()
async def analyze_mft(
    container: str, input_path: str, case_id: str,
    evidence_id: str | None = None,
) -> str:
    """Analyze NTFS $MFT or $J (USN Journal) with MFTECmd.

    Extracts file metadata, MACB timestamps, paths, and sizes.
    Covers: file creation/modification/access/deletion timestamps.

    Args:
        container: Container name.
        input_path: Path to $MFT or $J inside the container.
        case_id: Case number.
        evidence_id: Optional evidence ID.

    Returns:
        Analysis result with run details and artifact count.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="analyze_mft", correlation_id=cid,
             container=container)

    cmd = ["analyze", "mftecmd", input_path, "--case", case_id]
    if evidence_id:
        cmd.extend(["--evidence", evidence_id])
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def analyze_evtx(
    container: str, input_path: str, case_id: str,
    evidence_id: str | None = None,
    directory: bool = False,
) -> str:
    """Analyze Windows Event Logs (.evtx) with EvtxECmd.

    Parses event logs with structured maps for logon events,
    process creation, service installs, RDP, PowerShell, Sysmon, etc.

    Args:
        container: Container name.
        input_path: Path to .evtx file or directory inside the container.
        case_id: Case number.
        evidence_id: Optional evidence ID.
        directory: True if input_path is a directory of .evtx files.

    Returns:
        Analysis result with parsed event count.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="analyze_evtx", correlation_id=cid,
             container=container)

    cmd = ["analyze", "evtxecmd", input_path, "--case", case_id]
    if evidence_id:
        cmd.extend(["--evidence", evidence_id])
    if directory:
        cmd.append("--directory")
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def analyze_registry(
    container: str, input_path: str, case_id: str,
    evidence_id: str | None = None,
    directory: bool = False,
    with_logs: bool = False,
) -> str:
    """Analyze Windows Registry hives with RECmd.

    Extracts UserAssist, MRU, ShellBags, USB devices, Run keys,
    services, BAM/DAM, network profiles, and more.

    Args:
        container: Container name.
        input_path: Path to registry hive(s) inside the container.
        case_id: Case number.
        evidence_id: Optional evidence ID (EVD-NNN or UUID).
        directory: True if input_path is a directory of hive files.
        with_logs: Replay transaction logs (.LOG1/.LOG2) for dirty hives.
                   Default False (skips logs to avoid Linux casing issues).
                   Set True when the hive is dirty and you need complete data.

    Returns:
        Analysis result with artifact count per category.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="analyze_registry", correlation_id=cid,
             container=container)

    cmd = ["analyze", "recmd", input_path, "--case", case_id]
    if evidence_id:
        cmd.extend(["--evidence", evidence_id])
    if directory:
        cmd.append("--directory")
    if with_logs:
        cmd.append("--with-logs")
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def analyze_prefetch(
    container: str, input_path: str, case_id: str,
    evidence_id: str | None = None,
    directory: bool = False,
) -> str:
    """Analyze Windows Prefetch files (cross-platform, no Windows API needed).

    Extracts program execution history: executable name, run count,
    last 8 run times, and referenced files/directories.

    Args:
        container: Container name.
        input_path: Path to .pf file or Prefetch directory.
        case_id: Case number.
        evidence_id: Optional evidence ID.
        directory: True if input_path is a directory.

    Returns:
        Analysis result with execution records.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="analyze_prefetch", correlation_id=cid,
             container=container)

    cmd = ["analyze", "prefetch", input_path, "--case", case_id]
    if evidence_id:
        cmd.extend(["--evidence", evidence_id])
    if directory:
        cmd.append("--directory")
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def analyze_amcache(
    container: str, input_path: str, case_id: str,
    evidence_id: str | None = None,
) -> str:
    """Analyze Amcache.hve with AmcacheParser.

    Extracts application execution records, SHA-1 hashes,
    file metadata, and driver information.

    Args:
        container: Container name.
        input_path: Path to Amcache.hve inside the container.
        case_id: Case number.
        evidence_id: Optional evidence ID.

    Returns:
        Analysis result with program entries.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="analyze_amcache", correlation_id=cid,
             container=container)

    cmd = ["analyze", "amcacheparser", input_path, "--case", case_id]
    if evidence_id:
        cmd.extend(["--evidence", evidence_id])
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def analyze_shimcache(
    container: str, input_path: str, case_id: str,
    evidence_id: str | None = None,
) -> str:
    """Analyze Shimcache / AppCompatCache with AppCompatCacheParser.

    Extracts file paths, modification times, and cache positions
    from the SYSTEM hive. Indicates OS interaction with executables.

    Args:
        container: Container name.
        input_path: Path to SYSTEM hive inside the container.
        case_id: Case number.
        evidence_id: Optional evidence ID.

    Returns:
        Analysis result with cache entries.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="analyze_shimcache", correlation_id=cid,
             container=container)

    cmd = ["analyze", "appcompatcacheparser", input_path, "--case", case_id]
    if evidence_id:
        cmd.extend(["--evidence", evidence_id])
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def analyze_lnk(
    container: str, input_path: str, case_id: str,
    evidence_id: str | None = None,
    directory: bool = False,
) -> str:
    """Analyze Windows LNK shortcut files with LECmd.

    Extracts target paths, timestamps, volume serial numbers,
    machine IDs, MAC addresses, and network share info.

    Args:
        container: Container name.
        input_path: Path to .lnk file or directory.
        case_id: Case number.
        evidence_id: Optional evidence ID.
        directory: True if input_path is a directory.

    Returns:
        Analysis result with shortcut details.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="analyze_lnk", correlation_id=cid,
             container=container)

    cmd = ["analyze", "lecmd", input_path, "--case", case_id]
    if evidence_id:
        cmd.extend(["--evidence", evidence_id])
    if directory:
        cmd.append("--directory")
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def analyze_jumplist(
    container: str, input_path: str, case_id: str,
    evidence_id: str | None = None,
    directory: bool = False,
) -> str:
    """Analyze Windows Jump Lists with JLECmd.

    Extracts recently/frequently accessed files per application
    from AutomaticDestinations and CustomDestinations.

    Args:
        container: Container name.
        input_path: Path to Jump List file or directory.
        case_id: Case number.
        evidence_id: Optional evidence ID.
        directory: True if input_path is a directory.

    Returns:
        Analysis result with jump list entries.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="analyze_jumplist", correlation_id=cid,
             container=container)

    cmd = ["analyze", "jlecmd", input_path, "--case", case_id]
    if evidence_id:
        cmd.extend(["--evidence", evidence_id])
    if directory:
        cmd.append("--directory")
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def analyze_recyclebin(
    container: str, input_path: str, case_id: str,
    evidence_id: str | None = None,
    directory: bool = False,
) -> str:
    """Analyze Recycle Bin ($I/$R files) with RBCmd.

    Extracts original filename, path, deletion timestamp,
    file size, and user SID.

    Args:
        container: Container name.
        input_path: Path to $I file or $Recycle.Bin directory.
        case_id: Case number.
        evidence_id: Optional evidence ID.
        directory: True if input_path is a directory.

    Returns:
        Analysis result with deleted file records.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="analyze_recyclebin", correlation_id=cid,
             container=container)

    cmd = ["analyze", "rbcmd", input_path, "--case", case_id]
    if evidence_id:
        cmd.extend(["--evidence", evidence_id])
    if directory:
        cmd.append("--directory")
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def analyze_shellbags(
    container: str, input_path: str, case_id: str,
    evidence_id: str | None = None,
    with_logs: bool = False,
) -> str:
    """Analyze ShellBags with SBECmd.

    Extracts folder browsing history, timestamps, and evidence
    of folder access (even for deleted folders).

    Args:
        container: Container name.
        input_path: Path to NTUSER.DAT or UsrClass.dat.
        case_id: Case number.
        evidence_id: Optional evidence ID (EVD-NNN or UUID).
        with_logs: Replay transaction logs (.LOG1/.LOG2) for dirty hives.
                   Default False (skips logs to avoid Linux casing issues).
                   Set True when the hive is dirty and you need complete data
                   (e.g. 14 shellbags without logs vs 18 with logs).

    Returns:
        Analysis result with folder access records.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="analyze_shellbags", correlation_id=cid,
             container=container)

    cmd = ["analyze", "sbecmd", input_path, "--case", case_id]
    if evidence_id:
        cmd.extend(["--evidence", evidence_id])
    if with_logs:
        cmd.append("--with-logs")
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def analyze_wintimeline(
    container: str, input_path: str, case_id: str,
    evidence_id: str | None = None,
) -> str:
    """Analyze Windows 10/11 Timeline with WxTCmd.

    Extracts activity history, app usage, focus times,
    and file access from ActivitiesCache.db.

    Args:
        container: Container name.
        input_path: Path to ActivitiesCache.db.
        case_id: Case number.
        evidence_id: Optional evidence ID.

    Returns:
        Analysis result with timeline activities.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="analyze_wintimeline", correlation_id=cid,
             container=container)

    cmd = ["analyze", "wxtcmd", input_path, "--case", case_id]
    if evidence_id:
        cmd.extend(["--evidence", evidence_id])
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def analyze_sqlite(
    container: str, input_path: str, case_id: str,
    evidence_id: str | None = None,
    directory: bool = False,
) -> str:
    """Analyze SQLite databases (browsers, SRUM, etc.) with SQLECmd.

    Parses Chrome/Firefox/Edge history, downloads, cookies, sessions,
    and other SQLite-based forensic artifacts.

    Args:
        container: Container name.
        input_path: Path to SQLite database or directory.
        case_id: Case number.
        evidence_id: Optional evidence ID.
        directory: True if input_path is a directory.

    Returns:
        Analysis result with browser/app artifacts.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="analyze_sqlite", correlation_id=cid,
             container=container)

    cmd = ["analyze", "sqlecmd", input_path, "--case", case_id]
    if evidence_id:
        cmd.extend(["--evidence", evidence_id])
    if directory:
        cmd.append("--directory")
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def analyze_srum(
    container: str, input_path: str, case_id: str,
    evidence_id: str | None = None,
    registry_hive: str | None = None,
) -> str:
    """Analyze SRUM (System Resource Usage Monitor) with SrumECmd.

    Extracts per-application network usage (bytes sent/received),
    app timelines, energy usage, and push notification data.

    Args:
        container: Container name.
        input_path: Path to SRUDB.dat inside the container.
        case_id: Case number.
        evidence_id: Optional evidence ID.
        registry_hive: Path to SOFTWARE hive for SID resolution.

    Returns:
        Analysis result with resource usage data.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="analyze_srum", correlation_id=cid,
             container=container)

    cmd = ["analyze", "srumecmd", input_path, "--case", case_id]
    if evidence_id:
        cmd.extend(["--evidence", evidence_id])
    if registry_hive:
        cmd.extend(["--option", f"registry_hive={registry_hive}"])
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def analyze_usn(
    container: str, input_path: str, case_id: str,
    evidence_id: str | None = None,
    mft_path: str | None = None,
) -> str:
    """Analyze the NTFS USN journal ($Extend/$UsnJrnl:$J) with MFTECmd.

    Every file creation, rename, data overwrite, security change and deletion
    the journal still holds (days to weeks on a busy volume), with the update
    reasons — ransomware mass renames, tool drops and cleanup show up here.

    Args:
        container: Container name.
        input_path: Path to the $J file inside the container.
        case_id: Case number.
        evidence_id: Optional evidence ID.
        mft_path: Path to the $MFT, to resolve each record's parent folder.

    Returns:
        Analysis result (artifact type windows.usn.journal_entry).
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="analyze_usn", correlation_id=cid, container=container)

    cmd = ["analyze", "mftecmd", input_path, "--case", case_id]
    if evidence_id:
        cmd.extend(["--evidence", evidence_id])
    if mft_path:
        cmd.extend(["--option", f"mft_path={mft_path}"])
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def analyze_ual(
    container: str, input_path: str, case_id: str,
    evidence_id: str | None = None,
) -> str:
    """Analyze User Access Logging databases (Windows Server) with SumECmd.

    UAL keeps up to three years of "which client IP / user reached which
    server role" (file server, RDP, IIS, DHCP…) with first / last access and
    access counts — key evidence of lateral movement towards a server.

    Args:
        container: Container name.
        input_path: The Sum directory (Windows/System32/LogFiles/Sum).
        case_id: Case number.
        evidence_id: Optional evidence ID.

    Returns:
        Analysis result (windows.ual.client_access, role_access, dns, virtual_machine).
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="analyze_ual", correlation_id=cid, container=container)

    cmd = ["analyze", "sumecmd", input_path, "--case", case_id]
    if evidence_id:
        cmd.extend(["--evidence", evidence_id])
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def list_tools(container: str) -> str:
    """List available forensic tools in a container.

    Shows all registered tools with their availability status.

    Args:
        container: Container name.

    Returns:
        Table of tools with name, category, and availability.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="list_tools", correlation_id=cid,
             container=container)

    return await _proxy_defair(container, ["tools", "list"])


@mcp.tool()
async def tools_health(container: str) -> str:
    """Check health/availability of all forensic tools in a container.

    Args:
        container: Container name.

    Returns:
        Health status of each tool (available or missing).
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="tools_health", correlation_id=cid,
             container=container)

    return await _proxy_defair(container, ["tools", "health"])


@mcp.tool()
async def list_tool_runs(container: str, case_id: str | None = None) -> str:
    """List analysis tool runs in a container.

    Args:
        container: Container name.
        case_id: Optional — filter by case.

    Returns:
        Table of tool runs with status and duration.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="list_tool_runs", correlation_id=cid,
             container=container)

    cmd = ["runs", "list"]
    if case_id:
        cmd.extend(["--case", case_id])
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def list_artifacts(
    container: str,
    case_id: str | None = None,
    category: str | None = None,
    artifact_type: str | None = None,
    tool: str | None = None,
    contains: str | None = None,
    hostname: str | None = None,
    username: str | None = None,
    severity: str | None = None,
    since: str | None = None,
    until: str | None = None,
    run: str | None = None,
    oldest_first: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> str:
    """Search normalized artifacts (JSON, paginated). Use get_artifact for one.

    Args:
        container: Container name.
        case_id: Case number, name or ID.
        category: SANS category (program_execution, persistence, account_usage…).
        artifact_type: Type substring (e.g. "evtx.logon", "prefetch").
        tool: Source tool (evtxecmd, mftecmd, raijin, hayabusa…).
        contains: Text searched in description, message, path and every data field.
        hostname / username: Substring filters.
        severity: Severity filter.
        since / until: ISO 8601 time bounds.
        run: Only artifacts of this tool run (RUN-NNN).
        oldest_first: Chronological order (default newest first).
        limit / offset: Paging.

    Returns:
        JSON {total, offset, limit, items[]} with full artifact data.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="list_artifacts", correlation_id=cid, container=container)
    cmd = ["artifacts", "list", "--json", "--limit", str(limit), "--offset", str(offset)]
    for flag, value in (("--case", case_id), ("--category", category), ("--type", artifact_type),
                        ("--tool", tool), ("--contains", contains), ("--host", hostname),
                        ("--user", username), ("--severity", severity), ("--since", since),
                        ("--until", until), ("--run", run)):
        if value:
            cmd.extend([flag, value])
    if oldest_first:
        cmd.append("--asc")
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def get_artifact(
    container: str,
    artifact: str,
    context_minutes: float | None = None,
    raw: bool = True,
) -> str:
    """Deep-inspect one artifact (ART-NNN).

    Returns every field and the full normalized data, provenance (tool, pinned
    version, RUN-NNN, input), the findings referencing it, the evidence file
    resolved to its real path, and — for detections — what matched: event
    (EventID / RecordID / Computer) and field values for Sigma, identifier /
    value / offset for YARA. With raw=True the complete EVTX event is read
    from the log, or a hex dump around each YARA match. context_minutes adds
    the case timeline around the artifact.

    Args:
        container: Container name.
        artifact: Artifact number (ART-NNN) or id.
        context_minutes: Also return artifacts ± this many minutes around it.
        raw: Read the raw source (EVTX event / YARA hex context).
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="get_artifact", correlation_id=cid, container=container,
             artifact=artifact)
    cmd = ["artifacts", "get", artifact, "--json"]
    if context_minutes:
        cmd.extend(["--context", str(context_minutes)])
    if not raw:
        cmd.append("--no-raw")
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def get_finding(container: str, finding: str, case_id: str | None = None) -> str:
    """One finding with every match explained.

    For each linked artifact: evidence file (real path in the container),
    event (EventID / RecordID) or offset, and the exact pattern / field
    values that hit the rule — with the raw EVTX event or YARA hex context.
    Each rule gives its file in the rule store (see show_rule).

    Args:
        container: Container name.
        finding: Finding number (FND-NNN).
        case_id: Optional case the finding must belong to.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="get_finding", correlation_id=cid, container=container,
             finding=finding)
    cmd = ["findings", "get", finding, "--json"]
    if case_id:
        cmd.extend(["--case", case_id])
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def show_rule(container: str, source: str, path: str) -> str:
    """Content of a detection rule (YARA / Sigma) from the verified rule store.

    Args:
        container: Container name.
        source: Rule source id (e.g. sigmahq_core, yaraforge_full) — from get_finding.
        path: Rule file path inside that source — from get_finding.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="show_rule", correlation_id=cid, container=container)
    return await _proxy_defair(container, ["rules", "show", source, path])


# ---------------------------------------------------------------------------
# MCP Tools — v0.3: Hunting, Timeline, Findings, Search
# ---------------------------------------------------------------------------


@mcp.tool()
async def hunt_evtx(
    container: str,
    input_path: str,
    case_id: str,
    evidence_id: str | None = None,
    profile: str = "standard",
) -> str:
    """Hunt for threats in Windows Event Logs using Hayabusa + Sigma rules.

    Runs Hayabusa threat detection against EVTX files, applying 4000+
    Sigma detection rules with MITRE ATT&CK mapping. Automatically
    creates findings from high/critical detections.

    Complementary to analyze_evtx: analyze_evtx *parses* events,
    hunt_evtx *detects* threats.

    Args:
        container: Container name.
        input_path: Path to EVTX directory inside the container (e.g. "/evidence").
        case_id: Case number (e.g. "CASE-2026-001").
        evidence_id: Optional evidence ID (EVD-NNN or UUID).
        profile: Hayabusa output profile — minimal, standard, verbose,
                 all-field-info, super-verbose (default: standard).

    Returns:
        Hunt results with detection count, severity breakdown, and auto-created findings.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="hunt_evtx", correlation_id=cid,
             container=container)

    cmd = ["hunt", input_path, "--case", case_id, "--profile", profile]
    if evidence_id:
        cmd.extend(["--evidence", evidence_id])
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def hunt_chainsaw(
    container: str,
    input_path: str,
    case_id: str,
    evidence_id: str | None = None,
    rule_profile: str = "precise",
    min_severity: str = "medium",
) -> str:
    """Hunt EVTX with Chainsaw and the pinned, verified DEFAIR Sigma rules.

    A second Sigma engine next to Raijin / Hayabusa, to cross-check
    detections. Rules come from the rule store (profile "precise" = SigmaHQ
    core + emerging threats, "broad" = every pinned Sigma source), re-verified
    before the hunt; each finding carries the rule file, SHA-256 and source.

    Args:
        container: Container name.
        input_path: EVTX file or directory inside the container.
        case_id: Case number, name or ID.
        evidence_id: Optional evidence ID.
        rule_profile: "precise" or "broad".
        min_severity: Lowest severity that becomes a finding.

    Returns:
        Hunt summary (run, detections, findings created).
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="hunt_chainsaw", correlation_id=cid, container=container)
    cmd = ["hunt", input_path, "--case", case_id, "--profile", "standard", "--engine", "chainsaw",
           "--rule-profile", rule_profile, "--min-severity", min_severity]
    if evidence_id:
        cmd.extend(["--evidence", evidence_id])
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def list_evtx_views() -> str:
    """List the typed EVTX views (logons, process_creation, services, rdp, …).

    Each view is a filtered, column-projected look at the EVTX artifacts of a
    case (whichever parser produced them) — use get_evtx_view to read one.

    Returns:
        JSON list of views: name, description, matched events, columns.
    """
    import json

    from defair.services.evtx_view_service import list_views

    return json.dumps(list_views(), indent=2)


@mcp.tool()
async def get_evtx_view(
    container: str,
    case_id: str,
    name: str,
    since: str | None = None,
    until: str | None = None,
    host: str | None = None,
    user: str | None = None,
    event_id: int | None = None,
    newest_first: bool = False,
    limit: int = 200,
    offset: int = 0,
) -> str:
    """Read one typed EVTX view for a case (e.g. "logons", "services").

    Args:
        container: Container name.
        case_id: Case number, name or ID.
        name: View name (see list_evtx_views).
        since / until: ISO 8601 bounds.
        host / user: Substring filters.
        event_id: Only this EventID of the view.
        newest_first: Reverse time order.
        limit / offset: Paging.

    Returns:
        JSON: total, columns and rows (timestamp, event_id, computer, view
        columns, artifact number).
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="get_evtx_view", correlation_id=cid, container=container)
    cmd = ["evtx", "view", name, "--case", case_id, "--limit", str(limit),
           "--offset", str(offset), "--json"]
    for flag, value in (("--since", since), ("--until", until), ("--host", host),
                        ("--user", user), ("--event-id", event_id)):
        if value is not None:
            cmd.extend([flag, str(value)])
    if newest_first:
        cmd.append("--desc")
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def build_timeline(container: str, case_id: str) -> str:
    """Build a timeline summary for a forensic case.

    Aggregates all artifacts with timestamps and shows:
    - Total event count
    - Time range (earliest → latest)
    - Breakdown by tool, category, and severity

    Args:
        container: Container name.
        case_id: Case number (e.g. "CASE-2026-001").

    Returns:
        Timeline summary with statistics.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="build_timeline", correlation_id=cid,
             container=container)

    return await _proxy_defair(container, ["timeline", "summary", "--case", case_id])


@mcp.tool()
async def search_timeline(
    container: str,
    case_id: str,
    query: str | None = None,
    from_time: str | None = None,
    to_time: str | None = None,
    hostname: str | None = None,
    username: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    source_tool: str | None = None,
    limit: int = 50,
) -> str:
    """Search the forensic timeline with filters.

    Query across all artifacts ordered by timestamp. Supports
    text search and filtering by time range, host, user, category,
    severity, and source tool.

    Args:
        container: Container name.
        case_id: Case number (e.g. "CASE-2026-001").
        query: Text to search in description/data (e.g. "powershell", "4624").
        from_time: Start time filter (ISO 8601, e.g. "2023-03-27").
        to_time: End time filter (ISO 8601).
        hostname: Filter by hostname.
        username: Filter by username.
        category: Filter by SANS category (e.g. "account_usage").
        severity: Filter by severity (critical, high, medium, low, informational).
        source_tool: Filter by tool (e.g. "hayabusa", "evtxecmd").
        limit: Max results (default 50).

    Returns:
        Timeline events matching the filters, ordered chronologically.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="search_timeline", correlation_id=cid,
             container=container)

    cmd = ["timeline", "search", "--case", case_id, "--limit", str(limit)]
    if query:
        cmd.extend(["--query", query])
    if from_time:
        cmd.extend(["--from", from_time])
    if to_time:
        cmd.extend(["--to", to_time])
    if hostname:
        cmd.extend(["--hostname", hostname])
    if username:
        cmd.extend(["--username", username])
    if category:
        cmd.extend(["--category", category])
    if severity:
        cmd.extend(["--severity", severity])
    if source_tool:
        cmd.extend(["--tool", source_tool])
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def list_findings(
    container: str,
    case_id: str,
    severity: str | None = None,
    status: str | None = None,
) -> str:
    """List investigation findings for a case.

    Findings are conclusions from threat hunting — they group
    related detections into actionable items with MITRE ATT&CK mapping.

    Args:
        container: Container name.
        case_id: Case number (e.g. "CASE-2026-001").
        severity: Filter by severity (critical, high, medium, low, informational).
        status: Filter by status (open, confirmed, false_positive, resolved).

    Returns:
        Table of findings with severity, title, and linked artifact count.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="list_findings", correlation_id=cid,
             container=container)

    cmd = ["findings", "list", "--case", case_id]
    if severity:
        cmd.extend(["--severity", severity])
    if status:
        cmd.extend(["--status", status])
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def search_ioc(container: str, case_id: str, value: str) -> str:
    """Search for an IOC (Indicator of Compromise) across all artifacts.

    Searches for a value (IP, hash, domain, filename, command, etc.)
    in artifact descriptions, data fields, hostnames, usernames,
    and source files.

    Args:
        container: Container name.
        case_id: Case number (e.g. "CASE-2026-001").
        value: IOC to search for (e.g. "192.168.1.100", "SharpHound",
               "Metasploit", "powershell.exe").

    Returns:
        Search results with matching artifacts and tools.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="search_ioc", correlation_id=cid,
             container=container)

    return await _proxy_defair(container, ["search", value, "--case", case_id])


# ── Mass scanning tools (Raijin, v0.3.7) ─────────────────────────────


def _scan_cmd(
    subcommand: str, input_path: str, case_id: str, evidence_id: str | None,
    profile: str, min_severity: str,
    yara_rules_dir: str | None = None, sigma_rules_dir: str | None = None,
) -> list[str]:
    cmd = ["scan", subcommand, input_path, "--case", case_id,
           "--profile", profile, "--min-severity", min_severity]
    if evidence_id:
        cmd.extend(["--evidence", evidence_id])
    if yara_rules_dir:
        cmd.extend(["--yara-rules-dir", yara_rules_dir])
    if sigma_rules_dir:
        cmd.extend(["--sigma-rules-dir", sigma_rules_dir])
    return cmd


@mcp.tool()
async def scan_yara(
    container: str, input_path: str, case_id: str,
    evidence_id: str | None = None,
    profile: str = "broad",
    min_severity: str = "medium",
    rules_dir: str | None = None,
) -> str:
    """Mass scan every file under a path with YARA rules (Raijin / YARA-X).

    Rules come from the pinned, hash-verified rule store; the scan is refused
    if any rule file differs from the lock. Creates one finding per matching
    rule, with the rule's provenance (source, pinned ref, file, SHA-256, license).

    Args:
        container: Container name.
        input_path: File or directory to scan (e.g. /evidence).
        case_id: Case number.
        evidence_id: Optional evidence ID.
        profile: "precise" (YARA Forge core) or "broad" (YARA Forge full,
                 Elastic, ESET, ReversingLabs, Malpedia, Neo23x0, ATR).
        min_severity: Lowest severity that becomes a finding.
        rules_dir: Custom YARA rules directory (default /rules/yara).

    Returns:
        Scan summary with match count and findings created.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="scan_yara", correlation_id=cid, container=container)
    return await _proxy_defair(container, _scan_cmd(
        "yara", input_path, case_id, evidence_id, profile, min_severity, yara_rules_dir=rules_dir,
    ))


@mcp.tool()
async def scan_sigma(
    container: str, input_path: str, case_id: str,
    evidence_id: str | None = None,
    profile: str = "broad",
    min_severity: str = "medium",
    rules_dir: str | None = None,
) -> str:
    """Mass scan EVTX / Linux logs with Sigma rules (Raijin).

    KAPE, Velociraptor and plain-mount layouts are detected automatically and
    each detection keeps the original host path and event time. Rules are the
    pinned, verified SigmaHQ / community sets.

    Args:
        container: Container name.
        input_path: Directory containing the logs / collection.
        case_id: Case number.
        evidence_id: Optional evidence ID.
        profile: "precise" (SigmaHQ core + emerging threats) or "broad"
                 (SigmaHQ all, mdecrevoisier, LOLRMM).
        min_severity: Lowest severity that becomes a finding.
        rules_dir: Custom Sigma rules directory (default /rules/sigma).

    Returns:
        Scan summary with detection count and findings created.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="scan_sigma", correlation_id=cid, container=container)
    return await _proxy_defair(container, _scan_cmd(
        "sigma", input_path, case_id, evidence_id, profile, min_severity, sigma_rules_dir=rules_dir,
    ))


@mcp.tool()
async def scan_evidence(
    container: str, input_path: str, case_id: str,
    evidence_id: str | None = None,
    profile: str = "broad",
    min_severity: str = "medium",
) -> str:
    """Scan a path with YARA and Sigma in a single Raijin pass.

    Args:
        container: Container name.
        input_path: Evidence directory (e.g. /evidence).
        case_id: Case number.
        evidence_id: Optional evidence ID.
        profile: "precise" or "broad" rule profile.
        min_severity: Lowest severity that becomes a finding.

    Returns:
        Scan summary with match count and findings created.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="scan_evidence", correlation_id=cid, container=container)
    return await _proxy_defair(container, _scan_cmd(
        "evidence", input_path, case_id, evidence_id, profile, min_severity,
    ))


@mcp.tool()
async def get_ruleset_info(container: str, verify: bool = False) -> str:
    """Describe the detection rule sets available in a container.

    Lists every pinned source (repo, release tag or commit, file count,
    license, profiles) and whether it is installed. With verify=True, every
    rule file is re-hashed against the lock.

    Args:
        container: Container name.
        verify: Re-hash every rule file (slower).

    Returns:
        JSON with sources, profiles and integrity status.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="get_ruleset_info", correlation_id=cid, container=container)
    return await _proxy_defair(container, ["rules", "status", "--json", *(["--verify"] if verify else [])])


@mcp.tool()
async def list_rule_conflicts(container: str, profile: str | None = None) -> str:
    """List overlapping rules across sources.

    Nothing is ever overwritten: this reports Sigma rules sharing an id
    (identical copies, or conflicting content where the first source wins)
    and YARA rule names shipped by several sources.

    Args:
        container: Container name.
        profile: "precise" or "broad" (default: both).

    Returns:
        JSON report per profile.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="list_rule_conflicts", correlation_id=cid, container=container)
    return await _proxy_defair(container, ["rules", "conflicts", *(["--profile", profile] if profile else [])])


# ── Evidence preparation (v0.4) ──────────────────────────────────────


@mcp.tool()
async def prepare_evidence(
    container: str,
    evidence_id: str,
    password: str | None = None,
    private_key: str | None = None,
    passphrase: str | None = None,
    force: bool = False,
) -> str:
    """Make a registered evidence usable by the forensic tools.

    - KAPE / Velociraptor / FastIR folders, mounts, log folders: used in place
    - ZIP (with or without password): extracted
    - Generaptor / DFIR-ORC collections: decrypted with the private key
    - Disk images (E01, VMDK, VHD/VHDX, QCOW2, raw): artifacts carved with
      Dissect (no mount), plus a host profile artifact

    Derived files go to /workspace/sources/EVD-NNN/ with a manifest (origin +
    SHA-256 of each file). Secrets are passed through the container
    environment — never on a command line, never stored or logged.

    Args:
        container: Container name.
        evidence_id: Evidence number (EVD-NNN).
        password: Archive password, if the evidence needs one.
        private_key: PEM private key path inside the container (under /keys).
        passphrase: Private key passphrase, if the key is encrypted.
        force: Prepare again even if already prepared.

    Returns:
        JSON: detected kind, platform, root, artifact selectors found, manifest.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="prepare_evidence", correlation_id=cid,
             container=container, evidence_id=evidence_id,
             secrets=[n for n, v in (("password", password), ("passphrase", passphrase)) if v])

    _check_key_path(private_key)
    cmd = ["evidence", "prepare", evidence_id, "--json"]
    if private_key:
        cmd.extend(["--private-key", private_key])
    if force:
        cmd.append("--force")
    return await _proxy_defair(container, cmd, env=_secret_env(password, passphrase))


# ── Profiles + profile runs (v0.4) ───────────────────────────────────

_SECRET_ENV = {"password": "DEFAIR_EVIDENCE_PASSWORD", "passphrase": "DEFAIR_KEY_PASSPHRASE"}


def _secret_env(password: str | None, passphrase: str | None) -> dict[str, str]:
    values = {"password": password, "passphrase": passphrase}
    return {_SECRET_ENV[k]: v for k, v in values.items() if v}


def _check_key_path(private_key: str | None) -> None:
    if private_key and (not private_key.startswith("/keys/") or ".." in private_key.split("/")):
        raise ValueError("private_key must be a path inside the container, under /keys/")


@mcp.tool()
async def list_profiles(container: str) -> str:
    """List the analysis profiles (windows-triage, windows-full, ransomware,
    persistence, registry-only, scan-only) with their steps.

    Args:
        container: Container name.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="list_profiles", correlation_id=cid, container=container)
    return await _proxy_defair(container, ["profile", "list", "--json"])


@mcp.tool()
async def get_profile(container: str, name: str) -> str:
    """Show a profile: each step's tool, input artifact, fallbacks and dependencies.

    Args:
        container: Container name.
        name: Profile name.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="get_profile", correlation_id=cid, container=container)
    return await _proxy_defair(container, ["profile", "show", name])


@mcp.tool()
async def run_profile(
    container: str,
    case_id: str,
    evidence_id: str,
    profile: str = "auto",
    engine: str = "auto",
    password: str | None = None,
    private_key: str | None = None,
    passphrase: str | None = None,
) -> str:
    """Run a complete analysis profile on an evidence — in the background.

    One call prepares the evidence (extraction / decryption / Dissect carving
    when needed) and runs every step of the profile as a DAG: EZ Tools first,
    then pure-Python and Dissect plugin fallbacks, Sigma hunting, YARA/Sigma
    scan, timeline. Returns immediately with a run number (PRUN-NNN): follow
    it with get_run_status, stop it with cancel_run.

    Args:
        container: Container name.
        case_id: Case number.
        evidence_id: Evidence number (EVD-NNN) — register it first.
        profile: Profile name, or "auto" (chosen from the detected platform).
        engine: "auto" (EZ Tools → fallbacks), "ez" (no Dissect) or
                "dissect" (Dissect plugins on the original image / collection).
        password: Archive password, if the evidence needs one.
        private_key: PEM key under /keys for DFIR-ORC / Generaptor.
        passphrase: Private key passphrase.

    Returns:
        JSON with the run number to follow.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="run_profile", correlation_id=cid, container=container,
             profile=profile, engine=engine, evidence_id=evidence_id)
    _check_key_path(private_key)
    cmd = ["run", "start", "--case", case_id, "--evidence", evidence_id,
           "--profile", profile, "--engine", engine, "--json"]
    if private_key:
        cmd.extend(["--private-key", private_key])
    return await _proxy_defair(container, cmd, env=_secret_env(password, passphrase))


@mcp.tool()
async def analyze_evidence(
    container: str,
    case_id: str,
    evidence_path: str,
    engine: str = "auto",
    password: str | None = None,
    private_key: str | None = None,
    passphrase: str | None = None,
) -> str:
    """One call from a path to a full investigation (background).

    Registers the evidence (file or collection folder under /evidence),
    detects its format and platform, prepares it, picks the profile
    (windows-triage for Windows, scan-only otherwise) and runs it.
    Follow with get_run_status.

    Args:
        container: Container name.
        case_id: Case number.
        evidence_path: Path inside the container (e.g. /evidence/host01.E01).
        engine: "auto", "ez" or "dissect".
        password: Archive password, if needed.
        private_key: PEM key under /keys for DFIR-ORC / Generaptor.
        passphrase: Private key passphrase.

    Returns:
        JSON with the run number to follow.
    """
    from defair.services.analysis_service import _is_under_allowed_root

    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="analyze_evidence", correlation_id=cid, container=container,
             evidence_path=evidence_path)
    if not _is_under_allowed_root(evidence_path):
        raise ValueError("evidence_path must be under /evidence, /workspace or /rules")
    _check_key_path(private_key)
    cmd = ["run", "start", "--case", case_id, "--evidence", evidence_path,
           "--profile", "auto", "--engine", engine, "--json"]
    if private_key:
        cmd.extend(["--private-key", private_key])
    return await _proxy_defair(container, cmd, env=_secret_env(password, passphrase))


@mcp.tool()
async def get_run_status(container: str, run: str) -> str:
    """Status of a profile run: overall state, each step (tools tried,
    fallback used, artifacts, errors), manifest path, worker log tail.

    Args:
        container: Container name.
        run: Run number (PRUN-NNN).
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="get_run_status", correlation_id=cid, container=container)
    return await _proxy_defair(container, ["run", "status", run, "--json"])


@mcp.tool()
async def list_runs(container: str, case_id: str | None = None) -> str:
    """List profile runs (PRUN-NNN) with their status.

    Args:
        container: Container name.
        case_id: Optional case filter.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="list_runs", correlation_id=cid, container=container)
    return await _proxy_defair(container, ["run", "list", "--json",
                                           *(["--case", case_id] if case_id else [])])


@mcp.tool()
async def cancel_run(container: str, run: str) -> str:
    """Cancel a running profile run; running tools are stopped.

    Args:
        container: Container name.
        run: Run number (PRUN-NNN).
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="cancel_run", correlation_id=cid, container=container)
    return await _proxy_defair(container, ["run", "cancel", run, "--json"])


@mcp.tool()
async def resume_run(container: str, run: str, password: str | None = None,
                     private_key: str | None = None, passphrase: str | None = None) -> str:
    """Resume a failed or cancelled profile run; completed steps are kept.

    Args:
        container: Container name.
        run: Run number (PRUN-NNN).
        password / private_key / passphrase: Secrets, if the evidence needs them.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="resume_run", correlation_id=cid, container=container)
    _check_key_path(private_key)
    cmd = ["run", "resume", run, "--json", *(["--private-key", private_key] if private_key else [])]
    return await _proxy_defair(container, cmd, env=_secret_env(password, passphrase))


# ── Normalization pipeline + timeline export (v0.3.8) ────────────────


@mcp.tool()
async def export_timeline(
    container: str, case_id: str, format: str = "timesketch",
    output_path: str | None = None,
) -> str:
    """Export a case timeline to a file inside the container workspace.

    Args:
        container: Container name.
        case_id: Case number.
        format: "timesketch" (JSONL with message / datetime / timestamp_desc,
                importable into Timesketch), "jsonl" or "csv".
        output_path: Destination (default /workspace/timeline/).

    Returns:
        Export result (path, event count).
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="export_timeline", correlation_id=cid, container=container)
    cmd = ["timeline", "export", "--case", case_id, "--format", format]
    if output_path:
        cmd.extend(["--output", output_path])
    return await _proxy_defair(container, cmd)


@mcp.tool()
async def normalize_replay(container: str, case_id: str) -> str:
    """Rebuild a case's artifacts from its normalized JSONL files.

    Each file is checked against the SHA-256 recorded when it was written;
    a modified or missing file is refused and reported. Artifact ids are
    deterministic, so findings keep pointing at the same artifacts.

    Args:
        container: Container name.
        case_id: Case number.

    Returns:
        Files loaded / refused and artifacts restored.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="normalize_replay", correlation_id=cid, container=container)
    return await _proxy_defair(container, ["normalize", "replay", "--case", case_id])


@mcp.tool()
async def normalize_rerun(container: str, run: str) -> str:
    """Re-normalize a tool run from its raw output (after a normalizer fix).

    Args:
        container: Container name.
        run: Run number (RUN-NNN) or run id.

    Returns:
        Artifact counts before / after and normalization counters.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="normalize_rerun", correlation_id=cid, container=container)
    return await _proxy_defair(container, ["normalize", "rerun", run])


@mcp.tool()
async def get_normalization_stats(container: str, run: str) -> str:
    """Normalization counters of a tool run.

    Rows read, artifacts normalized, rows skipped, errors, timestamps that
    could not be parsed (kept as null, never invented) with reasons, and the
    JSONL files produced with their SHA-256.

    Args:
        container: Container name.
        run: Run number (RUN-NNN) or run id.

    Returns:
        JSON statistics.
    """
    cid = new_correlation_id()
    log.info("mcp_tool_called", tool="get_normalization_stats", correlation_id=cid,
             container=container)
    return await _proxy_defair(container, ["normalize", "stats", run])


def main() -> None:
    """Entry point for the DEFAIR MCP server (stdio transport)."""
    log.info("mcp_server_starting", transport="stdio")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
