"""Normalizer for Raijin JSONL output (YARA + Sigma matches).

One artifact per (matched event, rule). Each artifact carries the rule's full
provenance — source, pinned ref, rule file path + SHA-256, license — resolved
from the rule store index and the lock, so a finding can always be traced back
to the exact rule bytes that produced it.

The same YARA rule shipped by two sources loads twice (one namespace per
source) and may fire twice on one file: those hits are merged into a single
artifact listing every source in ``data.rule.also_in``.
"""

from __future__ import annotations

import hashlib
import json
import re
from functools import cached_property
from pathlib import Path
from typing import Any

import structlog

from defair.models.artifact import ArtifactCategory
from defair.normalizers.base import BaseNormalizer
from defair.rules.assemble import CUSTOM_SOURCE, namespace_to_source

log = structlog.get_logger(component="normalizer.raijin")

_SIGNATURE_PATH = re.compile(r"/signatures/(?:yara|sigma)/(\d{2}_[^/]+)/(.+)$")
_MITRE_TECHNIQUE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)

SIGMA_LEVELS = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
}

# Sigma ATT&CK tactic tags → artifact category
TACTIC_CATEGORY = {
    "attack.persistence": ArtifactCategory.PERSISTENCE,
    "attack.privilege_escalation": ArtifactCategory.PERSISTENCE,
    "attack.execution": ArtifactCategory.PROGRAM_EXECUTION,
    "attack.credential_access": ArtifactCategory.ACCOUNT_USAGE,
    "attack.lateral_movement": ArtifactCategory.NETWORK_ACTIVITY,
    "attack.command_and_control": ArtifactCategory.NETWORK_ACTIVITY,
    "attack.exfiltration": ArtifactCategory.NETWORK_ACTIVITY,
}


def score_to_severity(score: float | None) -> str:
    """Raijin/YARA score (0-100) → DEFAIR severity."""
    score = float(score or 0)
    if score >= 90:
        return "critical"
    if score >= 75:
        return "high"
    if score >= 60:
        return "medium"
    if score >= 40:
        return "low"
    return "informational"


class RaijinNormalizer(BaseNormalizer):
    """Normalize Raijin ``file_match`` events into detection artifacts."""

    def __init__(self, rules_store: str | Path | None = None) -> None:
        from defair.tools.raijin import RULES_STORE

        self.rules_store = Path(rules_store) if rules_store else RULES_STORE

    @property
    def tool_name(self) -> str:
        return "raijin"

    # -- provenance lookups (lazy, cached per normalizer) -------------------

    @cached_property
    def _index(self) -> dict:
        try:
            return json.loads((self.rules_store / "INDEX.json").read_text())
        except (OSError, ValueError):
            return {"yara": {}, "sigma": {}}

    @cached_property
    def _lock(self):
        from defair.rules.lock import load_lock

        try:
            return load_lock()
        except Exception:
            return None

    def _manifest(self, source_id: str) -> dict[str, str]:
        from defair.rules.lock import load_manifest

        cache = self.__dict__.setdefault("_manifests", {})
        if source_id not in cache:
            try:
                cache[source_id] = load_manifest(source_id)
            except Exception:
                cache[source_id] = {}
        return cache[source_id]

    def _source_info(self, source_id: str) -> dict:
        if source_id == CUSTOM_SOURCE:
            return {"provenance": "custom"}
        if self._lock is None:
            return {}
        try:
            locked = self._lock.get(source_id)
        except KeyError:
            return {}
        return {"repo": locked.repo, "ref": locked.ref, "license": locked.license}

    def resolve_rule(self, rule: dict) -> dict:
        """Complete a Raijin ``rule`` reference with source, file and hash."""
        resolved = dict(rule)
        engine = rule.get("engine")
        source_id = None
        rel = None

        if engine == "yara":
            source_id = namespace_to_source(rule.get("namespace") or "")
            rel = self._index.get("yara", {}).get(source_id, {}).get(rule.get("name", ""))
        elif engine == "sigma" and rule.get("file"):
            match = _SIGNATURE_PATH.search(rule["file"])
            if match:
                source_id = namespace_to_source(match.group(1))
                rel = match.group(2)

        if source_id:
            resolved["source"] = source_id
            resolved.update(self._source_info(source_id))
        if rel:
            resolved["file"] = rel
            if source_id == CUSTOM_SOURCE:
                custom = Path(rule.get("file") or "")
                if custom.is_file():
                    resolved["file_sha256"] = hashlib.sha256(custom.read_bytes()).hexdigest()
            elif source_id:
                sha = self._manifest(source_id).get(rel)
                if sha:
                    resolved["file_sha256"] = sha
        return resolved

    # -- normalization ------------------------------------------------------

    def normalize_row(self, row: dict[str, Any], **ctx) -> dict[str, Any] | None:
        artifacts = self.normalize_event(row, **ctx)
        return artifacts[0] if artifacts else None

    def normalize_event(self, event: dict[str, Any], **ctx) -> list[dict[str, Any]]:
        """All artifacts of one Raijin JSONL event (one per rule)."""
        if event.get("event_type") != "file_match":
            return []

        merged: dict[tuple, dict] = {}
        for reason in event.get("reasons") or []:
            rule = reason.get("rule")
            if not rule:
                continue  # IOC match without a rule — not produced with DEFAIR's config
            resolved = self.resolve_rule(rule)
            key = (resolved.get("engine"), resolved.get("name"), resolved.get("id"))
            if key in merged:
                also = merged[key]["data"]["rule"].setdefault("also_in", [])
                also.append({k: resolved.get(k) for k in ("source", "ref", "file", "file_sha256")})
                continue
            merged[key] = self._artifact(event, reason, resolved, **ctx)
        return list(merged.values())

    def normalize_file(self, file_path: str | Path, **context) -> list[dict[str, Any]]:
        path = Path(file_path)
        if not path.exists():
            return []
        artifacts: list[dict[str, Any]] = []
        for index, event in enumerate(self._read_jsonl(path)):
            self.stats["rows_read"] += 1
            try:
                produced = self.normalize_event(event, **context)
            except Exception as e:
                self.stats["errors"] += 1
                log.warning("raijin_event_error", error=str(e), event=str(event)[:200])
                continue
            if not produced:
                self.stats["skipped"] += 1
            for art in produced:
                rule = art["data"]["rule"]
                art["record_key"] = (
                    f"{path.name}#{index}/{rule.get('engine')}:{rule.get('source')}:"
                    f"{rule.get('id') or rule.get('name')}"
                )
            artifacts.extend(produced)
        log.info("normalizer_completed", tool=self.tool_name, file=path.name,
                 artifacts_produced=len(artifacts))
        return artifacts

    def _artifact(self, event: dict, reason: dict, rule: dict, **ctx) -> dict[str, Any]:
        engine = rule.get("engine")
        tags = rule.get("tags") or []
        host_path = event.get("file_path", "")

        if engine == "sigma":
            artifact_type = "detection.sigma.match"
            severity = SIGMA_LEVELS.get((rule.get("level") or "").lower()) or score_to_severity(
                reason.get("score")
            )
            category = next(
                (TACTIC_CATEGORY[t] for t in tags if t in TACTIC_CATEGORY),
                ArtifactCategory.OTHER,
            )
            timestamp = event.get("event_timestamp")
            description = f"Sigma: {rule.get('name')}"
        else:
            artifact_type = "detection.yara.match"
            severity = score_to_severity(reason.get("score"))
            category = ArtifactCategory.MALWARE
            timestamp = None  # a YARA hit has no event time; file times are in data
            description = f"YARA: {rule.get('name')} on {Path(host_path).name}"

        mitre = sorted({
            m.group(1).upper() for t in tags if (m := _MITRE_TECHNIQUE.match(t))
        })

        from defair.services.artifact_service import explain_match

        # Where the match is, in a form an analyst can open right away
        located = explain_match({"source_tool": "raijin", "data": {
            "engine": engine, "rule": rule, "host_path": host_path,
            "matched_strings": reason.get("matched_strings") or []}}, self.input_path)

        return {
            "artifact_type": artifact_type,
            "category": category,
            "source_tool": "raijin",
            "source_file": host_path,
            "timestamp": timestamp,
            "hostname": event.get("source_host"),
            "description": description,
            "severity": severity,
            "tags": tags,
            "data": {
                "rule": rule,
                "engine": engine,
                "rule_name": rule.get("name"),
                "rule_id": rule.get("id"),
                "score": reason.get("score"),
                "event_score": event.get("score"),
                "rule_description": reason.get("description"),
                "author": reason.get("author"),
                "reference": reason.get("reference"),
                "matched_strings": reason.get("matched_strings") or [],
                "mitre_techniques": mitre,
                "host_path": host_path,
                "scan_root": self.input_path,
                "evidence_path": located.get("evidence_path"),
                "event": located.get("event") or {},
                "matched_fields": located.get("matched_fields") or [],
                "matched_patterns": located.get("matched_patterns") or [],
                "file_name": Path(host_path).name,
                "md5": event.get("md5"),
                "sha1": event.get("sha1"),
                "sha256": event.get("sha256"),
                "file_size": event.get("file_size"),
                "file_created": event.get("file_created"),
                "file_modified": event.get("file_modified"),
                "file_accessed": event.get("file_accessed"),
            },
            **ctx,
        }
