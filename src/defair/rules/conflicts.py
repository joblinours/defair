"""Rule index and duplicate / conflict detection across sources.

Nothing is overwritten: each source keeps its own tree, YARA sources each get
their own namespace, and Raijin loads sources in lock order (first wins on a
duplicate Sigma ``id``). This module *reports* what overlaps:

- ``sigma_duplicates``: same ``id``, identical file content in a later source
- ``sigma_conflicts``: same ``id``, different content — the first source wins
- ``yara_name_collisions``: same rule name in several sources (both load, in
  separate namespaces; results are merged at normalization)
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from defair.rules.lock import RuleLock

# Rule declarations start a line. Comments are deliberately not stripped:
# "//" and "/*" also occur inside strings (URLs in meta, regexes), and a naive
# stripper then swallows real rules. A commented-out declaration starts with
# "//" or "/*" and therefore does not match.
_YARA_RULE = re.compile(
    r"^[ \t]*(?:(?:private|global)[ \t]+)*rule[ \t]+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE
)
_SIGMA_ID = re.compile(r"^id:\s*['\"]?([0-9A-Za-z-]+)['\"]?\s*$", re.MULTILINE)


def yara_rule_names(text: str) -> list[str]:
    """Rule identifiers declared in a YARA source file."""
    return _YARA_RULE.findall(text)


def sigma_rule_ids(text: str) -> list[str]:
    """Top-level ``id`` values of a Sigma file (one per YAML document)."""
    return _SIGMA_ID.findall(text)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def build_index(store: Path, lock: RuleLock) -> dict:
    """Map rules to the files that define them.

    Returns ``{"yara": {source: {rule_name: rel_path}},
    "sigma": {source: {rel_path: [ids]}}}``.
    """
    index: dict = {"yara": {}, "sigma": {}}
    for source in lock.sources:
        root = store / source.engine / source.id
        if not root.is_dir():
            continue
        entries: dict = {}
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            rel = path.relative_to(root).as_posix()
            text = _read(path)
            if source.engine == "yara":
                for name in yara_rule_names(text):
                    entries.setdefault(name, rel)
            else:
                ids = sigma_rule_ids(text)
                if ids:
                    entries[rel] = ids
        index[source.engine][source.id] = entries
    return index


def compute_conflicts(store: Path, lock: RuleLock, profile: str, index: dict) -> dict:
    """Overlaps between the sources of one profile, in precedence order."""
    report: dict[str, list] = {
        "sigma_duplicates": [],
        "sigma_conflicts": [],
        "yara_name_collisions": [],
    }

    first_sigma: dict[str, tuple[str, str, str]] = {}
    for source in lock.for_profile(profile, "sigma"):
        root = store / "sigma" / source.id
        for rel, ids in index["sigma"].get(source.id, {}).items():
            content_sha = hashlib.sha256((root / rel).read_bytes()).hexdigest()
            for rule_id in ids:
                if rule_id not in first_sigma:
                    first_sigma[rule_id] = (source.id, rel, content_sha)
                    continue
                kept_source, kept_rel, kept_sha = first_sigma[rule_id]
                if kept_source == source.id and kept_rel == rel:
                    continue
                kind = "sigma_duplicates" if kept_sha == content_sha else "sigma_conflicts"
                report[kind].append({
                    "id": rule_id,
                    "kept": {"source": kept_source, "path": kept_rel, "sha256": kept_sha},
                    "skipped": {"source": source.id, "path": rel, "sha256": content_sha},
                })

    first_yara: dict[str, tuple[str, str]] = {}
    for source in lock.for_profile(profile, "yara"):
        for name, rel in index["yara"].get(source.id, {}).items():
            if name not in first_yara:
                first_yara[name] = (source.id, rel)
                continue
            kept_source, kept_rel = first_yara[name]
            if kept_source != source.id:
                report["yara_name_collisions"].append({
                    "rule": name,
                    "first": {"source": kept_source, "path": kept_rel},
                    "also": {"source": source.id, "path": rel},
                })
    return report
