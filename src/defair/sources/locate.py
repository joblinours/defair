"""Locate the artifacts each forensic tool needs in a prepared source.

Two strategies, combined:
1. known Windows paths under the filesystem root (case-insensitive);
2. content signatures (magic bytes) for everything else — loose logs next to
   a collection, flat folders, or files renamed by a collector (DFIR-ORC).

Selectors (the ``input`` of a profile step):

======================  =====================================================
``root``                Windows filesystem root (or the whole source)
``evtx_dir``            directories holding .evtx files
``hives_dir``           ``Windows/System32/config``
``system_hive``         SYSTEM hive                 (AppCompatCacheParser)
``software_hive``       SOFTWARE hive               (SrumECmd -r)
``registry_files``      every registry hive found by content
``users_dir``           ``Users`` (NTUSER / UsrClass / LNK / JumpLists / browsers)
``amcache``             Amcache.hve
``prefetch_dir``        directories holding .pf files
``mft`` / ``usnjrnl``   $MFT / $UsnJrnl:$J
``recyclebin``          ``$Recycle.Bin``
``srum``                SRUDB.dat
``activities``          ActivitiesCache.db files
``lnk_files``           loose .lnk files (outside Users)
======================  =====================================================
"""

from __future__ import annotations

from pathlib import Path

from defair.sources.magic import artifact_kind

MAX_SCAN_FILES = 50000

# selector → path under the Windows root (segments matched case-insensitively)
ROOT_PATHS: dict[str, list[tuple[str, ...]]] = {
    "evtx_dir": [("Windows", "System32", "winevt", "Logs")],
    "hives_dir": [("Windows", "System32", "config")],
    "system_hive": [("Windows", "System32", "config", "SYSTEM")],
    "software_hive": [("Windows", "System32", "config", "SOFTWARE")],
    "users_dir": [("Users",), ("Documents and Settings",)],
    "amcache": [("Windows", "AppCompat", "Programs", "Amcache.hve")],
    "prefetch_dir": [("Windows", "Prefetch")],
    "mft": [("$MFT",)],
    "usnjrnl": [("$Extend", "$J"), ("$Extend", "$UsnJrnl%3A$J"), ("$Extend", "$UsnJrnl:$J")],
    "recyclebin": [("$Recycle.Bin",)],
    "srum": [("Windows", "System32", "sru", "SRUDB.dat")],
}


def _resolve(root: Path, segments: tuple[str, ...]) -> Path | None:
    current = root
    for segment in segments:
        lower = segment.lower()
        try:
            match = next((c for c in current.iterdir() if c.name.lower() == lower), None)
        except OSError:
            return None
        if match is None:
            return None
        current = match
    return current


def _add(found: dict[str, list[str]], selector: str, path: Path) -> None:
    items = found.setdefault(selector, [])
    value = str(path)
    if value not in items:
        items.append(value)


def locate_artifacts(base: str | Path, root: str | Path | None = None) -> dict[str, list[str]]:
    """Map selectors to paths.

    Args:
        base: The whole prepared source (scanned by content).
        root: Windows filesystem root inside ``base``, if any.
    """
    base = Path(base)
    root_path = Path(root) if root else None
    found: dict[str, list[str]] = {}

    if base.is_file():
        kind = artifact_kind(base)
        _add(found, "root", base)
        if kind == "evtx":
            _add(found, "evtx_dir", base)
        elif kind == "registry":
            _add(found, "registry_files", base)
        elif kind == "prefetch":
            _add(found, "prefetch_dir", base)
        elif kind == "lnk":
            _add(found, "lnk_files", base)
        return found

    _add(found, "root", root_path or base)
    if root_path and root_path.is_dir():
        for selector, candidates in ROOT_PATHS.items():
            for segments in candidates:
                path = _resolve(root_path, segments)
                if path is not None and path.exists():
                    _add(found, selector, path)
                    break

    scanned = 0
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        scanned += 1
        if scanned > MAX_SCAN_FILES:
            break
        name = path.name.lower()
        kind = artifact_kind(path)
        if kind == "evtx":
            _add(found, "evtx_dir", path.parent)
        elif kind == "prefetch" or name.endswith(".pf"):
            _add(found, "prefetch_dir", path.parent)
        elif kind == "registry":
            _add(found, "registry_files", path)
            if name == "amcache.hve":
                _add(found, "amcache", path)
            elif name == "system":
                _add(found, "system_hive", path)
            elif name == "software":
                _add(found, "software_hive", path)
        elif kind == "ese" and name == "srudb.dat":
            _add(found, "srum", path)
        elif kind == "sqlite" and name == "activitiescache.db":
            _add(found, "activities", path)
        elif kind == "lnk" and not _under(path, found.get("users_dir", [])):
            _add(found, "lnk_files", path)
        elif kind == "mft" and name in ("$mft", "mft"):
            _add(found, "mft", path)

    # A directory already covered by a parent entry is redundant for -d tools
    for selector in ("evtx_dir", "prefetch_dir"):
        if selector in found:
            found[selector] = _collapse(found[selector])
    return found


def _under(path: Path, parents: list[str]) -> bool:
    return any(Path(p) in path.parents for p in parents)


def _collapse(paths: list[str]) -> list[str]:
    """Drop directories nested in another listed directory."""
    ordered = sorted(paths, key=len)
    kept: list[str] = []
    for p in ordered:
        if not any(Path(k) in Path(p).parents for k in kept):
            kept.append(p)
    return kept
