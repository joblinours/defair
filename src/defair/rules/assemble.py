"""Assemble the signature directory Raijin loads for one scan.

Each run gets ``<run_dir>/signatures/{yara,sigma}/NN_<source>`` symlinks into
the verified, read-only rule store, restricted to the chosen profile. The
``NN_`` prefix follows lock order: Raijin sorts paths, so the first source in
the lock is loaded first and wins on a duplicate Sigma ``id``. It is also the
YARA namespace name, which the normalizer maps back to the source.

Custom rules (``/rules/yara``, ``/rules/sigma``) are linked as ``99_custom``,
hashed, and recorded as ``provenance: custom``.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from defair.rules.lock import RuleLock

CUSTOM_ROOT = Path("/rules")
CUSTOM_SOURCE = "custom"
_PREFIX = re.compile(r"^\d{2}_")

RULE_EXTENSIONS = {"yara": (".yar", ".yara"), "sigma": (".yml", ".yaml")}


def namespace_to_source(namespace: str) -> str:
    """``03_elastic`` → ``elastic``; ``default`` stays as is."""
    return _PREFIX.sub("", namespace)


def hash_custom_rules(root: Path, engine: str) -> dict[str, str]:
    """SHA-256 of every custom rule file under ``root``."""
    if not root.is_dir():
        return {}
    return {
        p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*"))
        if p.is_file() and p.suffix.lower() in RULE_EXTENSIONS[engine]
    }


def assemble_signatures(
    store: Path,
    run_dir: Path,
    profile: str,
    lock: RuleLock,
    engines: tuple[str, ...] = ("yara", "sigma"),
    custom_dirs: dict[str, Path] | None = None,
) -> dict:
    """Build the per-run signature tree.

    Args:
        custom_dirs: Custom rule directory per engine; defaults to
            ``/rules/yara`` and ``/rules/sigma``.

    Returns:
        ``{"signatures": path, "profile": ..., "sources": {engine: [ids]},
        "custom": {engine: {rel: sha256}}}``
    """
    signatures = run_dir / "signatures"
    info: dict = {"signatures": str(signatures), "profile": profile, "sources": {}, "custom": {}}

    for engine in ("yara", "sigma"):
        engine_dir = signatures / engine
        engine_dir.mkdir(parents=True, exist_ok=True)
        if engine not in engines:
            continue  # empty dir: Raijin loads nothing for this engine

        linked = []
        for position, source in enumerate(lock.for_profile(profile, engine)):
            target = store / engine / source.id
            if not target.is_dir():
                continue
            (engine_dir / f"{position:02d}_{source.id}").symlink_to(target, target_is_directory=True)
            linked.append(source.id)
        info["sources"][engine] = linked

        custom = (custom_dirs or {}).get(engine, CUSTOM_ROOT / engine)
        custom_hashes = hash_custom_rules(custom, engine)
        if custom_hashes:
            (engine_dir / f"99_{CUSTOM_SOURCE}").symlink_to(custom, target_is_directory=True)
            info["custom"][engine] = custom_hashes

    return info
