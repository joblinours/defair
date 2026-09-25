"""Targeted artifact extraction from disk images with Dissect (no mount).

Dissect opens E01 / Ex01 / VMDK / VHD(X) / QCOW2 / raw images, finds the
volumes and the Windows system volume by itself (so no partition offset to
compute), and reads NTFS directly — no FUSE, no SYS_ADMIN. Only the artifacts
the Windows profiles need are copied into ``<dest>/C/…`` (a KAPE-like tree),
each one recorded with its path in the image, size and SHA-256.
"""

from __future__ import annotations

import fnmatch
import hashlib
from pathlib import Path

import structlog

from defair.sources.archives import ExtractionError, ExtractionLimits, ExtractionLog

log = structlog.get_logger(component="sources.image")

# Globs relative to the Windows system volume. "**" = any depth.
# Registry transaction logs (.LOG1/.LOG2) come along so dirty hives can be replayed.
WINDOWS_TARGETS: tuple[str, ...] = (
    "$MFT",
    "$Extend/$UsnJrnl:$J",
    "Windows/System32/winevt/Logs/*.evtx",
    "Windows/System32/config/SYSTEM*",
    "Windows/System32/config/SOFTWARE*",
    "Windows/System32/config/SAM*",
    "Windows/System32/config/SECURITY*",
    "Windows/System32/config/DEFAULT*",
    "Windows/AppCompat/Programs/Amcache.hve*",
    "Windows/AppCompat/Programs/RecentFileCache.bcf",
    "Windows/System32/LogFiles/Sum/*",
    "Windows/Prefetch/*.pf",
    "Windows/System32/sru/SRUDB.dat",
    "Windows/System32/Tasks/**",
    "$Recycle.Bin/**/$I*",
    "Users/*/NTUSER.DAT*",
    "Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat*",
    "Users/*/AppData/Roaming/Microsoft/Windows/Recent/**",
    "Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
    "Users/*/AppData/Local/ConnectedDevicesPlatform/*/ActivitiesCache.db*",
    "Users/*/AppData/Local/Google/Chrome/User Data/*/History",
    "Users/*/AppData/Local/Microsoft/Edge/User Data/*/History",
    "Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite",
)


def _match(path, segments: list[str]):
    """Yield paths under ``path`` matching glob segments (case-insensitive)."""
    if not segments:
        yield path
        return
    head, rest = segments[0], segments[1:]
    if head == "**":
        yield from _match(path, rest)
        try:
            children = list(path.iterdir())
        except (OSError, NotADirectoryError, Exception):
            return
        for child in children:
            try:
                if child.is_dir():
                    yield from _match(child, segments)
            except Exception:
                continue
        return
    if not any(ch in head for ch in "*?["):
        candidate = path.joinpath(head)
        try:
            if candidate.exists():
                yield from _match(candidate, rest)
        except Exception:
            return
        return
    try:
        children = list(path.iterdir())
    except Exception:
        return
    for child in children:
        if fnmatch.fnmatch(child.name.lower(), head.lower()):
            yield from _match(child, rest)


def host_info(target) -> dict:
    """Best-effort host profile from Dissect (each field independently)."""
    info: dict = {}
    for name in ("hostname", "domain", "os", "version", "architecture", "timezone", "install_date"):
        try:
            value = getattr(target, name)
            info[name] = str(value) if value is not None else None
        except Exception:
            info[name] = None
    try:
        info["users"] = sorted({u.user.name for u in target.user_details.all_with_home() if u.user.name})
    except Exception:
        info["users"] = []
    try:
        info["ips"] = [str(ip) for ip in target.ips]
    except Exception:
        info["ips"] = []
    return info


def extract_image(
    image: Path,
    dest: Path,
    limits: ExtractionLimits | None = None,
    targets: tuple[str, ...] = WINDOWS_TARGETS,
) -> tuple[ExtractionLog, dict]:
    """Copy Windows artifacts out of a disk image into ``dest/C``.

    Returns:
        (extraction log, host info)
    """
    try:
        from dissect.target import Target
    except ImportError as e:
        raise ExtractionError("Dissect is not installed (pip install 'defair[forensic]')") from e

    limits = limits or ExtractionLimits()
    try:
        target = Target.open(str(image))
    except Exception as e:
        raise ExtractionError(f"Dissect cannot open {image.name}: {e}") from e

    os_name = None
    try:
        os_name = target.os
    except Exception:
        pass
    if os_name != "windows":
        raise ExtractionError(
            f"{image.name}: no Windows system volume found (os={os_name!r}); "
            "only Windows images are prepared in this version"
        )

    sysvol = target.fs.path("sysvol")
    drive_root = dest / "C"
    record = ExtractionLog()
    for pattern in targets:
        for src in _match(sysvol, pattern.split("/")):
            try:
                if not src.is_file():
                    continue
                rel = src.relative_to(sysvol).as_posix() if hasattr(src, "relative_to") else str(src)
            except Exception:
                continue
            out = drive_root / Path(*rel.replace(":", "%3A").split("/"))
            if out.exists():
                continue
            out.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            size = 0
            try:
                with src.open() as fh, out.open("wb") as fo:
                    for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                        fo.write(chunk)
                        digest.update(chunk)
                        size += len(chunk)
                        if record.total_bytes + size > limits.max_bytes:
                            raise ExtractionError("Extraction exceeds the configured size limit")
            except ExtractionError:
                raise
            except Exception as e:
                log.warning("image_extract_failed", path=rel, error=str(e))
                out.unlink(missing_ok=True)
                continue
            record.total_bytes += size
            record.files.append({
                "path": out.relative_to(dest).as_posix(),
                "origin": f"{image.name}:sysvol/{rel}",
                "size": size,
                "sha256": digest.hexdigest(),
            })
            if len(record.files) > limits.max_files:
                raise ExtractionError("Extraction exceeds the configured file-count limit")

    return record, host_info(target)
