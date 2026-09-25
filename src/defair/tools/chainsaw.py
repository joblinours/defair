"""Chainsaw wrapper — Sigma hunting on EVTX with the pinned rule store.

Chainsaw (WithSecure, GPL-3.0, run as a separate pinned binary) is a second
Sigma engine next to Raijin and Hayabusa, useful to cross-check detections.
It never uses its own rule bundle: like Raijin, the rules are the verified
DEFAIR store (``precise`` or ``broad`` profile + custom rules), re-verified
against the lock before every hunt, assembled as ``NN_<source>`` symlinks.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.models.tool_run import ToolRun
from defair.tools.base import BaseTool

CHAINSAW_BIN = "chainsaw"
MAPPING = Path("/opt/chainsaw/mappings/sigma-event-logs-all.yml")
OUTPUT_FILE = "chainsaw.json"
RULES_META = "rules.meta"  # sources in load order (read by the normalizer)


class ChainsawTool(BaseTool):
    """Wrapper for WithSecure's Chainsaw (Sigma mode)."""

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="chainsaw",
            display_name="Chainsaw",
            allowed_options=["profile", "sigma_rules_dir", "level", "from_time", "to_time"],
            vendor="WithSecure",
            description="Sigma hunting on EVTX (second engine), with the pinned and verified DEFAIR rule store.",
            category=ToolCategory.DETECTION,
            command=CHAINSAW_BIN,
            runtime="native",
            timeout=7200,
            capabilities=["sigma_detection", "evtx", "threat_hunting", "mitre_attack"],
            input_types=["evtx directory", "evtx file"],
            output_formats=["json"],
            artifact_types=["detection.sigma.match"],
            sans_categories=["program_execution", "persistence", "account_usage"],
        )

    def build_command(self, input_path: str, output_dir: str, **kwargs) -> list[str]:
        cmd = [
            CHAINSAW_BIN, "hunt", input_path,
            "-s", kwargs.get("signatures", "/opt/defair/rules/sigma"),
            "--mapping", str(kwargs.get("mapping", MAPPING)),
            "--json", "-o", str(Path(output_dir) / OUTPUT_FILE),
            "-q", "--skip-errors",
        ]
        if kwargs.get("level"):
            cmd.extend(["--level", str(kwargs["level"])])
        if kwargs.get("from_time"):
            cmd.extend(["--from", str(kwargs["from_time"])])
        if kwargs.get("to_time"):
            cmd.extend(["--to", str(kwargs["to_time"])])
        return cmd

    async def run(
        self,
        input_path: str,
        output_dir: str,
        case_id: str,
        evidence_id: str | None = None,
        run_number: str = "RUN-000",
        timeout: int | None = None,
        **kwargs,
    ) -> ToolRun:
        """Verify the rule store, assemble the profile's Sigma rules, then hunt."""
        from defair.rules.assemble import assemble_signatures
        from defair.rules.lock import load_lock
        from defair.rules.verify import assert_store_intact
        from defair.tools.raijin import RULES_STORE

        profile = kwargs.pop("profile", "precise")
        store = Path(kwargs.pop("rules_store", RULES_STORE))
        custom = kwargs.pop("sigma_rules_dir", None)
        custom_dirs = {"sigma": Path(custom)} if custom else None

        lock = load_lock()
        used = [s.id for s in lock.sources if profile in s.profiles and s.engine == "sigma"]
        assert_store_intact(store, used, lock)

        run_dir = Path(output_dir).parent / f".signatures-{run_number}"
        shutil.rmtree(run_dir, ignore_errors=True)
        assembled = assemble_signatures(store, run_dir, profile, lock, ("sigma",), custom_dirs)
        kwargs["signatures"] = str(Path(assembled["signatures"]) / "sigma")
        kwargs["rules"] = {
            "profile": profile,
            "lock_generated_at": lock.generated_at,
            "sources": {s.id: {"ref": s.ref, "license": s.license}
                        for s in lock.sources if s.id in used},
            "custom": assembled["custom"],
        }
        tool_run = await super().run(
            input_path, output_dir, case_id,
            evidence_id=evidence_id, run_number=run_number, timeout=timeout,
            **kwargs,
        )
        out = Path(output_dir)
        if out.is_dir():
            (out / RULES_META).write_text(json.dumps({
                "store": str(store),
                "sources": assembled["sources"].get("sigma", []),
                "custom_dir": custom,
            }))
        return tool_run
