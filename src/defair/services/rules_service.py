"""Rules service — status, verification and conflicts of the rule store.

Shared by the `defair rules` CLI and the MCP rule tools.
"""

from __future__ import annotations

import json
from pathlib import Path

from defair.rules.lock import PROFILES, load_lock
from defair.rules.verify import is_clean, verify_store


def _store(store: str | Path | None) -> Path:
    from defair.tools.raijin import RULES_STORE

    return Path(store) if store else RULES_STORE


def ruleset_info(store: str | Path | None = None, verify: bool = False) -> dict:
    """Pinned sources, installed store state and (optionally) integrity."""
    store_path = _store(store)
    lock = load_lock()
    installed = {}
    store_file = store_path / "STORE.json"
    if store_file.exists():
        installed = json.loads(store_file.read_text()).get("sources", {})

    sources = []
    for s in lock.sources:
        sources.append({
            "id": s.id,
            "engine": s.engine,
            "repo": s.repo,
            "ref": s.ref,
            "license": s.license,
            "files": s.files,
            "profiles": s.profiles,
            "installed": s.id in installed and installed[s.id].get("ref") == s.ref,
        })

    info: dict = {
        "store": str(store_path),
        "lock_generated_at": lock.generated_at,
        "profiles": {
            p: [s.id for s in lock.for_profile(p)] for p in PROFILES
        },
        "sources": sources,
    }
    validation = store_path / "VALIDATION.txt"
    if validation.exists():
        info["validation"] = validation.read_text()[-4000:]
    if verify:
        report = verify_store(store_path, [s["id"] for s in sources if s["installed"]], lock)
        info["integrity"] = "ok" if is_clean(report) else "FAILED"
        info["integrity_report"] = {
            k: {kind: len(v[kind]) for kind in ("missing", "extra", "modified")}
            for k, v in report.items()
        }
    return info


def verify_rules(store: str | Path | None = None) -> dict:
    """Full per-file verification of the store against the lock."""
    report = verify_store(_store(store))
    return {"ok": is_clean(report), "sources": report}


def rule_conflicts(store: str | Path | None = None, profile: str | None = None) -> dict:
    """Duplicates / conflicts computed at sync time (CONFLICTS.json)."""
    path = _store(store) / "CONFLICTS.json"
    if not path.exists():
        return {}
    data = json.loads(path.read_text())
    return {profile: data.get(profile, {})} if profile else data


def show_rule(source: str, path: str, store: str | Path | None = None) -> dict:
    """Content of one rule file of the store (``source`` + path inside it)."""
    from defair.rules.lock import load_lock

    lock = load_lock()
    try:
        engine = lock.get(source).engine
    except KeyError as e:
        raise ValueError(f"Unknown rule source '{source}'") from e
    base = (_store(store) / engine / source).resolve()
    target = (base / path).resolve()
    if base not in target.parents:
        raise ValueError("Rule path must stay inside the rule source")
    if not target.is_file():
        raise ValueError(f"Rule file not found: {target}")
    return {"source": source, "engine": engine, "path": str(target), "content": target.read_text(errors="replace")}
