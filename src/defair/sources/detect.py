"""Evidence source detection.

``detect_source(path)`` recognizes what an evidence path is — a triage
collection (KAPE, Velociraptor, FastIR, UAC, DFIR-ORC, Generaptor), a disk
image, an archive, a mounted filesystem or a plain folder of logs — and where
the Windows filesystem root is, when there is one.
"""

from __future__ import annotations

import json
import tarfile
import zipfile
from pathlib import Path
from urllib.parse import unquote

from pydantic import BaseModel, Field

from defair.sources.magic import archive_format, artifact_kind, image_format

MAX_DEPTH = 6
MAX_ENTRIES = 20000

SOURCE_KINDS = (
    "velociraptor", "kape", "kape_vhdx", "fastir", "mount", "logs", "disk_image",
    "zip", "zip_encrypted", "generaptor", "dfir_orc", "dfir_orc_encrypted", "uac", "unknown",
)


class SourceInfo(BaseModel):
    """What an evidence path is and how to reach its content."""

    kind: str = "unknown"
    platform: str = "unknown"  # windows, linux, unknown
    path: str
    root: str | None = None  # Windows filesystem root (dir containing Windows/)
    hostname: str | None = None
    image_format: str | None = None
    needs: list[str] = Field(default_factory=list)  # password, private_key
    details: dict = Field(default_factory=dict)

    @property
    def ready(self) -> bool:
        """Usable in place, without extraction or decryption."""
        return self.kind in ("velociraptor", "kape", "fastir", "mount", "logs")


def _children(path: Path) -> list[Path]:
    try:
        return sorted(path.iterdir())
    except OSError:
        return []


def _child(path: Path, name: str) -> Path | None:
    """Case-insensitive child lookup."""
    lower = name.lower()
    for child in _children(path):
        if child.name.lower() == lower:
            return child
    return None


# Subfolders that identify a Windows directory, even in partial triage
# collections (a KAPE target may only bring back Windows/Prefetch).
_WINDOWS_MARKERS = ("System32", "SysWOW64", "Prefetch", "AppCompat", "Tasks", "INF", "Logs")


def is_windows_root(path: Path) -> bool:
    windows = _child(path, "Windows")
    if windows and windows.is_dir() and any(_child(windows, m) for m in _WINDOWS_MARKERS):
        return True
    # Drive-letter folder of a collection (C/, D/…) with Users only
    drive = len(path.name) == 1 and path.name.isalpha()
    return drive and bool(_child(path, "Users") or windows)


def find_windows_root(base: Path, max_depth: int = MAX_DEPTH) -> Path | None:
    """Breadth-first search for a directory holding ``Windows/System32``."""
    queue = [(base, 0)]
    seen = 0
    while queue:
        path, depth = queue.pop(0)
        if is_windows_root(path):
            return path
        if depth >= max_depth:
            continue
        for child in _children(path):
            seen += 1
            if seen > MAX_ENTRIES:
                return None
            if child.is_dir() and not child.is_symlink():
                queue.append((child, depth + 1))
    return None


def _walk_files(base: Path, limit: int = MAX_ENTRIES):
    count = 0
    for path in base.rglob("*"):
        if path.is_file():
            yield path
            count += 1
            if count >= limit:
                return


def _decoded_parts(path: Path, base: Path) -> list[str]:
    return [unquote(p) for p in path.relative_to(base).parts]


def _detect_directory(path: Path) -> SourceInfo:
    info = SourceInfo(path=str(path))
    names = {c.name.lower() for c in _children(path)}

    # Velociraptor offline collection (extracted)
    uploads = _child(path, "uploads")
    if uploads and uploads.is_dir() and (
        {"results", "collection_context.json", "log.json", "requests.json"} & names
    ):
        info.kind = "velociraptor"
        root = find_windows_root(uploads)
        if root:
            info.root = str(root)
            info.platform = "windows"
            info.details["accessor_path"] = "/".join(_decoded_parts(root, uploads))
        context = _child(path, "collection_context.json")
        if context:
            try:
                data = json.loads(context.read_text(errors="replace"))
                info.hostname = (data.get("hostname") or data.get("Hostname")
                                 or (data.get("client_info") or {}).get("hostname"))
            except (ValueError, OSError, AttributeError):
                pass
        return info

    # UAC (Unix-like Artifacts Collector), extracted
    if "uac.log" in names or "[root]" in names:
        info.kind = "uac"
        info.platform = "linux"
        root = _child(path, "[root]")
        info.root = str(root) if root else str(path)
        return info

    # Mounted Windows filesystem
    if is_windows_root(path):
        info.kind = "mount"
        info.platform = "windows"
        info.root = str(path)
        return info

    root = find_windows_root(path)
    if root:
        info.platform = "windows"
        info.root = str(root)
        drive = root.name
        csvs = [c for c in _children(path) if c.suffix.lower() == ".csv"]
        if len(drive) == 1 and drive.isalpha():
            # A drive-letter folder: KAPE (optionally under <timestamp>_<host>/) or FastIR
            info.kind = "fastir" if csvs and root.parent == path else "kape"
        else:
            info.kind = "mount"
        info.details["relative_root"] = str(root.relative_to(path))
        return info

    # Nested containers / loose artifacts
    kinds: dict[str, int] = {}
    containers = []
    for file in _walk_files(path):
        if image_format(file):
            containers.append({"path": str(file), "type": "disk_image"})
            continue
        if file.name.lower().endswith(".7z.p7b"):
            containers.append({"path": str(file), "type": "dfir_orc_encrypted"})
            continue
        kind = artifact_kind(file)
        if kind:
            kinds[kind] = kinds.get(kind, 0) + 1
    if containers:
        info.details["containers"] = containers
    if kinds:
        info.kind = "logs"
        info.platform = "windows"
        info.root = str(path)
        info.details["artifact_counts"] = kinds
    return info


def _detect_zip(path: Path) -> SourceInfo:
    info = SourceInfo(path=str(path), kind="zip")
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            encrypted = any(i.flag_bits & 0x1 for i in zf.infolist())
            if "metadata.json" in names and "data.zip" in names:
                info.kind = "generaptor"
                info.needs = ["private_key"]
                try:
                    (meta,) = json.loads(zf.read("metadata.json").decode())
                    info.hostname = meta.get("device") or meta.get("hostname")
                    info.details["fingerprint_hex"] = meta.get("fingerprint_hex")
                except (ValueError, KeyError, TypeError):
                    pass
                return info
            if encrypted:
                info.kind = "zip_encrypted"
                info.needs = ["password"]
            info.details["entries"] = len(names)
            lowered = [n.lower() for n in names]
            if any(n.endswith(".vhdx") for n in lowered):
                info.details["contains"] = "kape_vhdx"
            elif any("/windows/system32/" in f"/{n}" for n in lowered):
                info.details["contains"] = "windows_tree"
    except zipfile.BadZipFile as e:
        info.kind = "unknown"
        info.details["error"] = str(e)
    return info


def _detect_tar(path: Path) -> SourceInfo:
    info = SourceInfo(path=str(path), kind="unknown")
    try:
        with tarfile.open(path) as tf:
            names = []
            for i, member in enumerate(tf):
                names.append(member.name)
                if i > 2000:
                    break
    except (tarfile.TarError, OSError) as e:
        info.details["error"] = str(e)
        return info
    if any(n.endswith("uac.log") or "/[root]/" in f"/{n}/" for n in names):
        info.kind = "uac"
        info.platform = "linux"
    return info


def detect_source(path: str | Path) -> SourceInfo:
    """Identify an evidence path (file or directory)."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Evidence path not found: {path}")
    if path.is_dir():
        return _detect_directory(path)

    fmt = image_format(path)
    if fmt:
        kind = "kape_vhdx" if fmt == "vhdx" else "disk_image"
        return SourceInfo(path=str(path), kind=kind, image_format=fmt, platform="unknown")

    archive = archive_format(path)
    if archive == "zip":
        return _detect_zip(path)
    if archive == "pkcs7" or path.name.lower().endswith(".7z.p7b"):
        return SourceInfo(path=str(path), kind="dfir_orc_encrypted", platform="windows",
                          needs=["private_key"])
    if archive == "7z":
        return SourceInfo(path=str(path), kind="dfir_orc", platform="windows")
    if archive in ("tar", "gzip"):
        return _detect_tar(path)

    kind = artifact_kind(path)
    if kind:
        return SourceInfo(path=str(path), kind="logs", platform="windows", root=str(path),
                          details={"artifact_counts": {kind: 1}, "single_file": True})
    return SourceInfo(path=str(path))
