"""Raijin wrapper — YARA-X + Sigma cold scanner (vendored in engines/raijin).

One engine for both mass-scanning modes:
- YARA over every file under the input (``mode="yara"``)
- Sigma over EVTX / Linux logs, with KAPE / Velociraptor layout detection
  (``mode="sigma"``)
- both in a single pass (``mode="all"``)

Before each run the rule store is checked against the pinned lock and a
per-run signature tree is assembled for the chosen profile (see
``defair.rules``). The lock refs, the profile and the hashes of any custom
rules are recorded in the ToolRun parameters.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.models.tool_run import ToolRun
from defair.tools.base import BaseTool

RULES_STORE = Path(os.environ.get("DEFAIR_RULES_STORE", "/opt/defair/rules"))
RAIJIN_BIN = os.environ.get("DEFAIR_RAIJIN_BIN", "raijin")
SCAN_MODES = ("all", "yara", "sigma")
JSONL_NAME = "raijin.jsonl"


class RaijinTool(BaseTool):
    """Wrapper for the Raijin scanner."""

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="raijin",
            display_name="Raijin",
            allowed_options=[
                "profile", "mode", "all_files", "max_file_size", "threads",
                "yara_rules_dir", "sigma_rules_dir",
            ],
            vendor="TCS-CERT (vendored in DEFAIR)",
            version="1.1.1",
            description=(
                "YARA-X and Sigma cold scanner. Scans every file with YARA and every "
                "EVTX / Linux log with Sigma, using pinned and verified rule sets "
                "(YARA Forge, SigmaHQ and community sources)."
            ),
            category=ToolCategory.DETECTION,
            command=RAIJIN_BIN,
            runtime="native",
            timeout=7200,
            success_exit_codes=[0, 2],  # 2 = matches found
            capabilities=[
                "yara", "sigma_detection", "malware_detection", "ioc_scanning",
                "evtx", "linux_logs", "kape", "velociraptor", "mitre_attack",
            ],
            input_types=["*"],
            output_formats=["jsonl"],
            artifact_types=["detection.yara.match", "detection.sigma.match"],
            sans_categories=["program_execution", "persistence", "malware"],
        )

    def build_command(self, input_path: str, output_dir: str, **kwargs) -> list[str]:
        mode = kwargs.get("mode", "all")
        if mode not in SCAN_MODES:
            raise ValueError(f"Unknown scan mode '{mode}'. Use one of: {', '.join(SCAN_MODES)}")

        cmd = [
            RAIJIN_BIN,
            # Cold scan of --folder only, never this machine's processes. Do NOT
            # add --scan-all-drives / --scan-hard-drives: they make Raijin scan
            # every drive of the host and ignore --folder.
            "--lab", "--no-procs",
            "--no-tui", "--no-html", "--no-log",
            "--folder", input_path,
            "--signatures", kwargs.get("signatures", str(RULES_STORE)),
            "--jsonl", str(Path(output_dir) / JSONL_NAME),
            f"--threads={kwargs.get('threads', -2)}",
        ]
        if kwargs.get("all_files", True):
            cmd.append("--scan-all-files")  # forensic: every file, not only executables
        if kwargs.get("max_file_size"):
            cmd.extend(["--max-file-size", str(kwargs["max_file_size"])])
        if mode == "yara":
            cmd.append("--no-sigma")
        elif mode == "sigma":
            cmd.append("--no-fs")
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
        """Verify the rule store, assemble the profile's signatures, then scan."""
        from defair.rules.assemble import assemble_signatures
        from defair.rules.lock import load_lock
        from defair.rules.verify import assert_store_intact

        profile = kwargs.pop("profile", "broad")
        mode = kwargs.get("mode", "all")
        store = Path(kwargs.pop("rules_store", RULES_STORE))
        custom_dirs = {
            engine: Path(kwargs.pop(f"{engine}_rules_dir"))
            for engine in ("yara", "sigma") if kwargs.get(f"{engine}_rules_dir")
        }
        engines = ("yara", "sigma") if mode == "all" else (mode,)

        lock = load_lock()
        used = [
            s.id for s in lock.sources
            if profile in s.profiles and s.engine in engines
        ]
        assert_store_intact(store, used, lock)

        run_dir = Path(output_dir).parent / f".signatures-{run_number}"
        shutil.rmtree(run_dir, ignore_errors=True)
        assembled = assemble_signatures(store, run_dir, profile, lock, engines, custom_dirs)

        kwargs["signatures"] = assembled["signatures"]
        kwargs["rules"] = {
            "profile": profile,
            "lock_generated_at": lock.generated_at,
            "sources": {
                s.id: {"ref": s.ref, "license": s.license}
                for s in lock.sources if s.id in used
            },
            "custom": assembled["custom"],
        }
        return await super().run(
            input_path, output_dir, case_id,
            evidence_id=evidence_id, run_number=run_number, timeout=timeout,
            **kwargs,
        )
