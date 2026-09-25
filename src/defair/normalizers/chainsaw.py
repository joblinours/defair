"""Normalizer for Chainsaw hunt output (``--json``).

Chainsaw reports a Sigma hit with the rule's id, name, level and tags, and
the whole matched event — not the rule file. The file (and its SHA-256,
source, pinned ref, license) is resolved from the rule store index by Sigma
id, following the load order recorded by the wrapper, so Chainsaw findings
carry the same provenance as Raijin ones.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import structlog

from defair.models.artifact import ArtifactCategory
from defair.normalizers.base import BaseNormalizer
from defair.normalizers.evtx_flatten import flatten_event
from defair.normalizers.raijin import _MITRE_TECHNIQUE, SIGMA_LEVELS, TACTIC_CATEGORY
from defair.rules.assemble import CUSTOM_SOURCE, RULE_EXTENSIONS

log = structlog.get_logger(component="normalizer.chainsaw")


class ChainsawNormalizer(BaseNormalizer):
    """Chainsaw Sigma hits → detection.sigma.match artifacts."""

    @property
    def tool_name(self) -> str:
        return "chainsaw"

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        return self._artifact(row, {}, **ctx)

    def normalize_directory(self, output_dir, **context) -> list[dict[str, Any]]:
        out = Path(output_dir)
        meta = {}
        try:
            meta = json.loads((out / "rules.meta").read_text())
        except (OSError, ValueError):
            pass
        rules = RuleResolver(meta)
        path = out / "chainsaw.json"
        if not path.exists():
            return []
        try:
            hits = json.loads(path.read_text(encoding="utf-8", errors="replace") or "[]")
        except ValueError as e:
            log.error("chainsaw_output_unreadable", error=str(e))
            self.stats["errors"] += 1
            return []
        artifacts = []
        for index, hit in enumerate(hits):
            self.stats["rows_read"] += 1
            try:
                art = self._artifact(hit, rules.resolve(hit), **context)
            except Exception as e:
                self.stats["errors"] += 1
                log.warning("chainsaw_hit_error", error=str(e))
                continue
            if art is None:
                self.stats["skipped"] += 1
                continue
            event = art["data"]["event"]
            art["record_key"] = (f"{art['source_file']}#{event.get('EventRecordID', index)}/"
                                 f"{art['data']['rule'].get('id') or art['data']['rule_name']}")
            artifacts.append(art)
        return artifacts

    def _artifact(self, hit: dict, provenance: dict, **ctx) -> dict[str, Any] | None:
        if hit.get("group") != "Sigma" and hit.get("source") != "sigma":
            return None
        document = hit.get("document") or {}
        event = flatten_event(document.get("data") or {})
        tags = hit.get("tags") or []
        rule = {"engine": "sigma", "name": hit.get("name"), "id": hit.get("id"),
                "level": hit.get("level"), "tags": tags, "status": hit.get("status"),
                **provenance}
        mitre = sorted({m.group(1).upper() for t in tags if (m := _MITRE_TECHNIQUE.match(t))})
        category = next((TACTIC_CATEGORY[t] for t in tags if t in TACTIC_CATEGORY),
                        ArtifactCategory.OTHER)
        host_path = document.get("path", "")
        return {
            "artifact_type": "detection.sigma.match",
            "category": category,
            "source_tool": "chainsaw",
            "source_file": host_path,
            "timestamp": hit.get("timestamp"),
            "hostname": event.get("Computer"),
            "description": f"Sigma (Chainsaw): {hit.get('name')}",
            "severity": SIGMA_LEVELS.get((hit.get("level") or "").lower(), "medium"),
            "tags": tags,
            "data": {
                "rule": rule,
                "engine": "sigma",
                "rule_name": hit.get("name"),
                "rule_id": hit.get("id"),
                "authors": hit.get("authors"),
                "references": hit.get("references"),
                "falsepositives": hit.get("falsepositives"),
                "mitre_techniques": mitre,
                "host_path": host_path,
                "file_name": Path(host_path).name,
                "event_id": event.get("EventID"),
                "channel": event.get("Channel"),
                "record_number": event.get("EventRecordID"),
                "event": event,
            },
            **ctx,
        }


class RuleResolver:
    """Sigma id → the rule file that defines it, in the run's load order."""

    def __init__(self, meta: dict) -> None:
        self.store = Path(meta.get("store") or "/opt/defair/rules")
        self.sources: list[str] = meta.get("sources") or []
        self.custom_dir = Path(meta["custom_dir"]) if meta.get("custom_dir") else Path("/rules/sigma")
        self._ids: dict[str, tuple[str, str]] | None = None
        self._custom: dict[str, tuple[str, str]] | None = None

    def _index(self) -> dict[str, tuple[str, str]]:
        if self._ids is None:
            self._ids = {}
            try:
                index = json.loads((self.store / "INDEX.json").read_text()).get("sigma", {})
            except (OSError, ValueError):
                index = {}
            for source in self.sources:  # first source wins, as for Raijin
                for rel, ids in (index.get(source) or {}).items():
                    for rule_id in ids:
                        self._ids.setdefault(rule_id, (source, rel))
        return self._ids

    def _custom_index(self) -> dict[str, tuple[str, str]]:
        if self._custom is None:
            from defair.rules.conflicts import sigma_rule_ids

            self._custom = {}
            if self.custom_dir.is_dir():
                for path in sorted(self.custom_dir.rglob("*")):
                    if path.is_file() and path.suffix.lower() in RULE_EXTENSIONS["sigma"]:
                        text = path.read_text(encoding="utf-8", errors="replace")
                        for rule_id in sigma_rule_ids(text):
                            self._custom.setdefault(rule_id, (str(path), hashlib.sha256(
                                path.read_bytes()).hexdigest()))
        return self._custom

    def resolve(self, hit: dict) -> dict:
        rule_id = hit.get("id")
        if not rule_id:
            return {}
        found = self._index().get(rule_id)
        if found:
            source, rel = found
            info = {"source": source, "file": rel}
            info.update(_source_info(source))
            sha = _manifest(source).get(rel)
            if sha:
                info["file_sha256"] = sha
            return info
        custom = self._custom_index().get(rule_id)
        if custom:
            return {"source": CUSTOM_SOURCE, "provenance": "custom", "file": custom[0],
                    "file_sha256": custom[1]}
        return {}


def _source_info(source_id: str) -> dict:
    from defair.rules.lock import load_lock

    try:
        locked = load_lock().get(source_id)
    except Exception:
        return {}
    return {"repo": locked.repo, "ref": locked.ref, "license": locked.license}


def _manifest(source_id: str) -> dict[str, str]:
    from defair.rules.lock import load_manifest

    try:
        return load_manifest(source_id)
    except Exception:
        return {}
