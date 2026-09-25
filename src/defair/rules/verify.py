"""Scan-time integrity check of the installed rule store."""

from __future__ import annotations

import hashlib
from pathlib import Path

from defair.rules.lock import LOCK_DIR, RuleIntegrityError, RuleLock, load_lock, load_manifest


def verify_store(
    store: Path,
    sources: list[str] | None = None,
    lock: RuleLock | None = None,
    lock_dir: Path = LOCK_DIR,
) -> dict:
    """Compare the installed rules against the lock's per-file manifests.

    Args:
        store: Rule store directory.
        sources: Only check these source ids (default: all locked sources).

    Returns:
        ``{source_id: {"files": n, "missing": [...], "extra": [...], "modified": [...]}}``
    """
    lock = lock or load_lock(lock_dir)
    report: dict[str, dict] = {}
    for source in lock.sources:
        if sources is not None and source.id not in sources:
            continue
        manifest = load_manifest(source.id, lock_dir)
        root = store / source.engine / source.id
        present = {
            p.relative_to(root).as_posix(): p
            for p in root.rglob("*") if p.is_file()
        } if root.is_dir() else {}
        modified = sorted(
            rel for rel, path in present.items()
            if rel in manifest and hashlib.sha256(path.read_bytes()).hexdigest() != manifest[rel]
        )
        report[source.id] = {
            "files": len(present),
            "missing": sorted(set(manifest) - set(present)),
            "extra": sorted(set(present) - set(manifest)),
            "modified": modified,
        }
    return report


def is_clean(report: dict) -> bool:
    return all(not (r["missing"] or r["extra"] or r["modified"]) for r in report.values())


def assert_store_intact(
    store: Path,
    sources: list[str],
    lock: RuleLock | None = None,
    lock_dir: Path = LOCK_DIR,
) -> None:
    """Refuse to scan with rules that differ from the lock."""
    report = verify_store(store, sources, lock, lock_dir)
    problems = []
    for source_id, r in report.items():
        for kind in ("missing", "extra", "modified"):
            if r[kind]:
                problems.append(f"{source_id}: {len(r[kind])} {kind} (e.g. {r[kind][0]})")
    if problems:
        raise RuleIntegrityError(
            "Rule store does not match the pinned lock — scan refused. " + "; ".join(problems)
        )
