"""Install the pinned rule sets into a rule store.

Store layout (``/opt/defair/rules`` in the image)::

    <store>/<engine>/<source_id>/<upstream path>   rule files, tree preserved
    <store>/STORE.json                              what was installed (lock refs)
    <store>/INDEX.json                              rule → file lookup (provenance)
    <store>/CONFLICTS.json                          duplicates / conflicts per profile

Every file is checked against the per-file manifest of the lock; release
archives are also checked against their pinned archive SHA-256. Any mismatch
aborts the sync — nothing unverified is ever left in the store.
"""

from __future__ import annotations

import io
import json
import shutil
import zipfile
from pathlib import Path

import structlog

from defair.rules.conflicts import build_index, compute_conflicts
from defair.rules.lock import (
    LOCK_DIR,
    PROFILES,
    Fetcher,
    RuleIntegrityError,
    RuleLock,
    http_get,
    load_lock,
    load_manifest,
    select_members,
    sha256_bytes,
)

log = structlog.get_logger(component="rules.sync")

DEFAULT_STORE = Path("/opt/defair/rules")


def sync_rules(
    dest: Path = DEFAULT_STORE,
    lock: RuleLock | None = None,
    lock_dir: Path = LOCK_DIR,
    fetch: Fetcher = http_get,
    only: list[str] | None = None,
) -> dict:
    """Download every locked source and install it, verified, into ``dest``.

    Args:
        dest: Rule store directory.
        lock: Lock to follow (loaded from the package when omitted).
        lock_dir: Directory holding the lock and manifests.
        fetch: Downloader (injected by tests).
        only: Restrict to these source ids.

    Returns:
        Summary: files installed per source, conflict counts per profile.

    Raises:
        RuleIntegrityError: On any hash mismatch or missing/extra file.
    """
    lock = lock or load_lock(lock_dir)
    dest.mkdir(parents=True, exist_ok=True)
    installed: dict[str, dict] = {}

    for source in lock.sources:
        if only and source.id not in only:
            continue
        manifest = load_manifest(source.id, lock_dir)
        data = fetch(source.url)
        digest = sha256_bytes(data)

        if digest != source.archive_sha256:
            if source.kind == "release":
                raise RuleIntegrityError(
                    f"{source.id}: archive SHA-256 {digest} != pinned {source.archive_sha256}"
                )
            # GitHub may re-compress commit archives; the per-file manifest
            # below is the authoritative check for those.
            log.warning("rule_archive_digest_changed", source=source.id, digest=digest)

        target = dest / source.engine / source.id
        staging = dest / source.engine / f".{source.id}.staging"
        shutil.rmtree(staging, ignore_errors=True)
        try:
            _extract_verified(data, source, manifest, staging)
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        shutil.rmtree(target, ignore_errors=True)
        staging.rename(target)

        installed[source.id] = {
            "engine": source.engine,
            "ref": source.ref,
            "files": len(manifest),
            "license": source.license,
        }
        log.info("rule_source_installed", source=source.id, ref=source.ref, files=len(manifest))

    (dest / "STORE.json").write_text(json.dumps({
        "lock_generated_at": lock.generated_at,
        "sources": installed,
    }, indent=2, sort_keys=True))

    index = build_index(dest, lock)
    (dest / "INDEX.json").write_text(json.dumps(index, sort_keys=True))

    conflicts = {profile: compute_conflicts(dest, lock, profile, index) for profile in PROFILES}
    (dest / "CONFLICTS.json").write_text(json.dumps(conflicts, indent=1, sort_keys=True))

    return {
        "store": str(dest),
        "sources": installed,
        "conflicts": {p: {k: len(v) for k, v in c.items()} for p, c in conflicts.items()},
    }


def _extract_verified(data: bytes, source, manifest: dict[str, str], target: Path) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = select_members(archive, source)
        found = {rel for _, rel in members}
        missing = sorted(set(manifest) - found)
        extra = sorted(found - set(manifest))
        if missing or extra:
            raise RuleIntegrityError(
                f"{source.id}: archive content differs from the lock "
                f"(missing {len(missing)}: {missing[:3]}, extra {len(extra)}: {extra[:3]})"
            )
        for member, rel in members:
            content = archive.read(member)
            if sha256_bytes(content) != manifest[rel]:
                raise RuleIntegrityError(f"{source.id}: {rel} does not match its pinned SHA-256")
            out = target / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(content)
