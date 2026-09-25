"""Evidence preparation — turn any registered evidence into a usable root.

Collections already laid out on disk (KAPE, Velociraptor, FastIR, mounts,
log folders) are used in place, read-only. Everything else is derived into
``<workspace>/sources/EVD-NNN/``: archives extracted, Generaptor / DFIR-ORC
collections decrypted, disk images carved by Dissect — then detected again
(a ZIP may hold a KAPE VHDX, a Generaptor collection holds a Velociraptor one).

``manifest.json`` records every derived file (origin, size, SHA-256), the
host profile when Dissect provides one, and which kinds of secrets were used —
never their values.
"""

from __future__ import annotations

import json
import os
import shutil
import tarfile
from datetime import UTC, datetime
from pathlib import Path

import aiosqlite
import structlog

from defair.sources.archives import (
    ExtractionError,
    ExtractionLimits,
    ExtractionLog,
    decrypt_orc,
    extract_7z,
    extract_generaptor,
    extract_zip,
)
from defair.sources.detect import SourceInfo, detect_source
from defair.sources.locate import locate_artifacts

log = structlog.get_logger(component="sources.prepare")

WORKSPACE = Path(os.environ.get("DEFAIR_WORKSPACE", "/workspace"))
MAX_NESTING = 3


class PreparationError(RuntimeError):
    """The evidence cannot be prepared (missing secret, unsupported format…)."""


class Secrets:
    """Secrets for one preparation. Values never leave this object."""

    def __init__(
        self,
        password: str | None = None,
        private_key: str | None = None,
        passphrase: str | None = None,
    ) -> None:
        self.password = password
        self.private_key = Path(private_key) if private_key else None
        self.passphrase = passphrase

    def used(self) -> list[str]:
        return [name for name in ("password", "private_key", "passphrase") if getattr(self, name)]

    def require_key(self, what: str) -> Path:
        if not self.private_key:
            raise PreparationError(f"{what} is encrypted: a private key is required (--private-key)")
        if not self.private_key.is_file():
            raise PreparationError(f"Private key not found: {self.private_key}")
        return self.private_key


def _extract_tar(archive: Path, dest: Path, limits: ExtractionLimits) -> ExtractionLog:
    record = ExtractionLog()
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as tf:
        members = [m for m in tf.getmembers() if m.isfile()]
        if len(members) > limits.max_files or sum(m.size for m in members) > limits.max_bytes:
            raise ExtractionError(f"{archive.name} exceeds the extraction limits")
        tf.extractall(dest, members=members, filter="data")  # refuses traversal / links / devices
    for member in members:
        target = dest / member.name
        if target.is_file():
            record.add(target, f"{archive.name}:{member.name}", dest)
    return record


def _derive(info: SourceInfo, dest: Path, secrets: Secrets, limits: ExtractionLimits,
            host: dict) -> ExtractionLog:
    """Extract / decrypt / carve one container into ``dest``."""
    path = Path(info.path)
    if info.kind in ("zip", "zip_encrypted"):
        if info.kind == "zip_encrypted" and not secrets.password:
            raise PreparationError(f"{path.name} is password-protected: a password is required")
        return extract_zip(path, dest, password=secrets.password, limits=limits)
    if info.kind == "generaptor":
        key = secrets.require_key(f"Generaptor collection {path.name}")
        return extract_generaptor(path, dest, key, secrets.passphrase, limits)
    if info.kind == "dfir_orc_encrypted":
        key = secrets.require_key(f"DFIR-ORC archive {path.name}")
        decrypted = dest.parent / ".decrypted" / path.name.removesuffix(".p7b")
        decrypt_orc(path, decrypted, key, secrets.passphrase)
        try:
            return extract_7z(decrypted, dest / decrypted.stem, limits)
        finally:
            decrypted.unlink(missing_ok=True)
    if info.kind == "dfir_orc":
        return extract_7z(path, dest / path.stem, limits)
    if info.kind in ("disk_image", "kape_vhdx"):
        from defair.sources.image import extract_image

        record, host_info = extract_image(path, dest / path.stem, limits)
        host.update({k: v for k, v in host_info.items() if v})
        for f in record.files:  # paths relative to dest
            f["path"] = f"{path.stem}/{f['path']}"
        return record
    if info.kind == "uac":
        return _extract_tar(path, dest, limits)
    raise PreparationError(f"Unsupported evidence format: {info.kind} ({path.name})")


def _nested_containers(base: Path, info: SourceInfo) -> list[str]:
    """Containers left inside an extraction: images, encrypted ORC archives,
    and — when nothing usable was found yet — archives (ZIP in a ZIP…)."""
    found = [c["path"] for c in info.details.get("containers") or []]
    if not info.ready:
        from defair.sources.magic import archive_format

        for path in sorted(base.rglob("*")):
            if path.is_file() and not path.name.endswith(".extracted") and archive_format(path):
                found.append(str(path))
    return found


def prepare_path(
    evidence_path: str | Path,
    dest: Path,
    secrets: Secrets | None = None,
    limits: ExtractionLimits | None = None,
) -> dict:
    """Prepare an evidence path (no database). See :func:`prepare_evidence`."""
    secrets = secrets or Secrets()
    limits = limits or ExtractionLimits()
    info = detect_source(evidence_path)
    original = info
    files: list[dict] = []
    host: dict = {}
    base = Path(evidence_path)

    derived = not info.ready
    if derived:
        shutil.rmtree(dest, ignore_errors=True)
        base = dest / "content"
        files.extend(_derive(info, base, secrets, limits, host).files)
        done: set[str] = set()
        for _ in range(MAX_NESTING):
            info = detect_source(base)
            pending = [c for c in _nested_containers(base, info) if c not in done]
            if not pending:
                break
            for container in pending:
                done.add(container)
                sub_dest = Path(container + ".extracted")
                files.extend(_derive(detect_source(container), sub_dest, secrets, limits, host).files)
        info = detect_source(base)
    elif info.details.get("containers"):
        # A ready folder that also holds disk images / encrypted archives
        for container in info.details["containers"]:
            sub_dest = dest / "content" / (Path(container["path"]).name + ".extracted")
            files.extend(_derive(detect_source(container["path"]), sub_dest, secrets, limits,
                                 host).files)

    selectors = locate_artifacts(base, info.root)
    if (dest / "content").exists() and not derived:
        for key, values in locate_artifacts(dest / "content").items():
            if key != "root":
                for value in values:
                    selectors.setdefault(key, []).append(value)

    prepared = {
        "source": original.model_dump(),
        "kind": info.kind,
        "platform": info.platform if info.platform != "unknown" else original.platform,
        "base": str(base),
        "root": info.root,
        "target": str(Path(evidence_path)),  # original, for Dissect plugins
        "derived": derived or bool(files),
        "derived_files": len(files),
        "host": host,
        "selectors": selectors,
        "secrets_used": secrets.used(),
        "prepared_at": datetime.now(UTC).isoformat(),
    }
    if prepared["platform"] == "unknown" and host.get("os") == "windows":
        prepared["platform"] = "windows"
    if files or derived:
        dest.mkdir(parents=True, exist_ok=True)
        manifest = dest / "manifest.json"
        manifest.write_text(json.dumps({**prepared, "files": files}, indent=1))
        prepared["manifest"] = str(manifest)
    return prepared


async def prepare_evidence(
    conn: aiosqlite.Connection,
    evidence_id: str,
    secrets: Secrets | None = None,
    workspace: Path | None = None,
    limits: ExtractionLimits | None = None,
    force: bool = False,
) -> dict:
    """Prepare a registered evidence and store the result on it.

    Returns:
        The preparation record (kind, platform, root, selectors, manifest…).
    """
    import asyncio

    from defair.services.evidence_service import get_evidence

    evidence = await get_evidence(conn, evidence_id)
    if evidence is None:
        raise PreparationError(f"Evidence not found: {evidence_id}")
    if evidence.prepared and not force and Path(evidence.prepared.get("base", "")).exists():
        return evidence.prepared

    dest = (workspace or WORKSPACE) / "sources" / evidence.evidence_number
    try:
        prepared = await asyncio.to_thread(prepare_path, evidence.original_path, dest, secrets, limits)
    except ExtractionError as e:
        raise PreparationError(str(e)) from e
    prepared["evidence_id"] = evidence.id
    prepared["evidence_number"] = evidence.evidence_number

    await conn.execute("UPDATE evidence SET prepared = ? WHERE id = ?",
                       (json.dumps(prepared), evidence.id))
    await conn.commit()
    if prepared.get("host"):
        await _save_host_artifact(conn, evidence, prepared)
    log.info("evidence_prepared", evidence=evidence.evidence_number, kind=prepared["kind"],
             derived_files=prepared["derived_files"])
    return prepared


async def _save_host_artifact(conn: aiosqlite.Connection, evidence, prepared: dict) -> None:
    from defair.services.analysis_service import _save_artifact

    host = prepared["host"]
    await _save_artifact(conn, {
        "case_id": evidence.case_id,
        "evidence_id": evidence.id,
        "artifact_type": "windows.system.host_info",
        "category": "system_info",
        "source_tool": "dissect",
        "source_file": evidence.original_path,
        "hostname": host.get("hostname"),
        "description": f"Host profile: {host.get('hostname') or 'unknown host'} ({host.get('version') or host.get('os')})",
        "data": host,
        "provenance": {"tool": "dissect", "evidence_id": evidence.id, "stage": "prepare"},
        "record_key": f"host_info:{evidence.evidence_number}",
    })
