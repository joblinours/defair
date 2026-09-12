"""Discovery service — identify evidence type and available artifacts.

Uses Dissect (when available) or file-system heuristics to:
1. Identify what type of evidence was provided
2. Determine the OS/platform
3. List available forensic artifacts
4. Recommend which tools to run

Runs INSIDE the container.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import structlog

log = structlog.get_logger(component="discovery_service")

# Known Windows artifact paths and their types
WINDOWS_ARTIFACTS = {
    # NTFS
    "$MFT": {"type": "mft", "tool": "mftecmd", "description": "NTFS Master File Table"},
    "$J": {"type": "usn_journal", "tool": "mftecmd", "description": "NTFS USN Journal"},
    "$LogFile": {"type": "ntfs_logfile", "tool": None, "description": "NTFS Transaction Log"},

    # Event Logs
    "*.evtx": {"type": "evtx", "tool": "evtxecmd", "description": "Windows Event Logs"},
    "Security.evtx": {"type": "evtx", "tool": "evtxecmd", "description": "Security Event Log"},
    "System.evtx": {"type": "evtx", "tool": "evtxecmd", "description": "System Event Log"},
    "Application.evtx": {"type": "evtx", "tool": "evtxecmd", "description": "Application Event Log"},
    "Microsoft-Windows-Sysmon%4Operational.evtx": {"type": "evtx", "tool": "evtxecmd", "description": "Sysmon Log"},
    "Microsoft-Windows-PowerShell%4Operational.evtx": {"type": "evtx", "tool": "evtxecmd", "description": "PowerShell Log"},
    "Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx": {"type": "evtx", "tool": "evtxecmd", "description": "RDP Client Log"},
    "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx": {"type": "evtx", "tool": "evtxecmd", "description": "RDP Session Log"},

    # Registry Hives
    "SAM": {"type": "registry", "tool": "recmd", "description": "SAM Registry (users, accounts)"},
    "SYSTEM": {"type": "registry", "tool": "recmd", "description": "SYSTEM Registry (services, USB, Shimcache)"},
    "SOFTWARE": {"type": "registry", "tool": "recmd", "description": "SOFTWARE Registry (installs, network)"},
    "SECURITY": {"type": "registry", "tool": "recmd", "description": "SECURITY Registry (audit policies)"},
    "NTUSER.DAT": {"type": "registry", "tool": "recmd", "description": "NTUSER.DAT (user settings, MRU, UserAssist)"},
    "UsrClass.dat": {"type": "registry", "tool": "recmd", "description": "UsrClass.dat (ShellBags, file associations)"},

    # Prefetch
    "*.pf": {"type": "prefetch", "tool": "pecmd", "description": "Prefetch files (program execution)"},

    # Amcache
    "Amcache.hve": {"type": "amcache", "tool": "amcacheparser", "description": "Amcache (program execution, SHA-1)"},

    # LNK Shortcuts
    "*.lnk": {"type": "lnk", "tool": "lecmd", "description": "LNK shortcut files"},

    # Jump Lists
    "*.automaticDestinations-ms": {"type": "jumplist", "tool": "jlecmd", "description": "Jump Lists (recent files per app)"},
    "*.customDestinations-ms": {"type": "jumplist", "tool": "jlecmd", "description": "Custom Jump Lists (pinned items)"},

    # Recycle Bin
    "$I*": {"type": "recyclebin", "tool": "rbcmd", "description": "Recycle Bin metadata ($I files)"},
    "$R*": {"type": "recyclebin", "tool": "rbcmd", "description": "Recycle Bin data ($R files)"},

    # SRUM
    "SRUDB.dat": {"type": "srum", "tool": "srumecmd", "description": "SRUM (app network/resource usage)"},

    # Timeline
    "ActivitiesCache.db": {"type": "timeline", "tool": "wxtcmd", "description": "Windows 10/11 Timeline"},

    # Browser
    "History": {"type": "browser_sqlite", "tool": "sqlecmd", "description": "Browser History (Chrome/Edge)"},
    "Cookies": {"type": "browser_sqlite", "tool": "sqlecmd", "description": "Browser Cookies"},
    "Login Data": {"type": "browser_sqlite", "tool": "sqlecmd", "description": "Browser Saved Logins"},
    "places.sqlite": {"type": "browser_sqlite", "tool": "sqlecmd", "description": "Firefox History/Bookmarks"},
    "cookies.sqlite": {"type": "browser_sqlite", "tool": "sqlecmd", "description": "Firefox Cookies"},

    # Thumbcache
    "thumbcache_*.db": {"type": "thumbcache", "tool": None, "description": "Thumbcache database"},
}


async def discover_artifacts(
    evidence_path: str,
    recursive: bool = True,
) -> dict:
    """Scan an evidence path and identify forensic artifacts.

    Args:
        evidence_path: Path to scan (directory or mounted image).
        recursive: Whether to search recursively.

    Returns:
        Discovery result with platform, hostname, and artifact list.
    """
    path = Path(evidence_path)
    if not path.exists():
        raise FileNotFoundError(f"Evidence path not found: {evidence_path}")

    found_artifacts = []
    platform = "unknown"
    hostname = None

    if path.is_dir():
        found_artifacts = await _scan_directory(path, recursive)
    elif path.is_file():
        found_artifacts = _identify_file(path)

    # Determine platform from found artifacts
    if any(a["type"] in ("registry", "evtx", "prefetch", "amcache", "mft") for a in found_artifacts):
        platform = "windows"

    # Try to extract hostname from SYSTEM hive path
    for art in found_artifacts:
        if "SYSTEM" in art.get("path", ""):
            parts = Path(art["path"]).parts
            # Look for pattern like /Users/<hostname>/...
            for i, p in enumerate(parts):
                if p.lower() in ("windows", "system32", "config"):
                    break

    # Group by type
    artifact_types = {}
    for art in found_artifacts:
        art_type = art["type"]
        if art_type not in artifact_types:
            artifact_types[art_type] = {
                "count": 0,
                "recommended_tool": art.get("tool"),
                "description": art.get("description", ""),
                "files": [],
            }
        artifact_types[art_type]["count"] += 1
        artifact_types[art_type]["files"].append(art["path"])

    # Build recommendations
    recommended_tools = []
    for art_type, info in artifact_types.items():
        if info["recommended_tool"]:
            recommended_tools.append({
                "tool": info["recommended_tool"],
                "artifact_type": art_type,
                "file_count": info["count"],
                "description": info["description"],
            })

    result = {
        "platform": platform,
        "hostname": hostname,
        "evidence_path": evidence_path,
        "total_artifacts_found": len(found_artifacts),
        "artifact_types": artifact_types,
        "recommended_tools": recommended_tools,
        "artifacts": found_artifacts,
    }

    log.info(
        "discovery_completed",
        platform=platform,
        total=len(found_artifacts),
        types=len(artifact_types),
    )

    return result


async def _scan_directory(path: Path, recursive: bool) -> list[dict]:
    """Scan a directory for known Windows artifacts."""
    found = []

    def _scan():
        items = path.rglob("*") if recursive else path.iterdir()
        for item in items:
            if item.is_file():
                info = _identify_file(item)
                found.extend(info)

    await asyncio.to_thread(_scan)
    return found


def _identify_file(path: Path) -> list[dict]:
    """Identify a single file against known artifact patterns."""
    results = []
    name = path.name

    for pattern, info in WINDOWS_ARTIFACTS.items():
        if _matches_pattern(name, pattern):
            results.append({
                "path": str(path),
                "filename": name,
                "size": path.stat().st_size if path.exists() else 0,
                **info,
            })

    return results


def _matches_pattern(filename: str, pattern: str) -> bool:
    """Simple glob-like matching for artifact patterns."""
    if pattern.startswith("*"):
        return filename.lower().endswith(pattern[1:].lower())
    if pattern.endswith("*"):
        return filename.startswith(pattern[:-1])
    if "*" in pattern:
        prefix, suffix = pattern.split("*", 1)
        return filename.startswith(prefix) and filename.endswith(suffix)
    return filename == pattern
