"""Hayabusa wrapper — Sigma-based threat hunting on Windows Event Logs.

Hayabusa is a Rust-based tool that applies 4000+ Sigma rules against
EVTX files to detect suspicious activity, producing a timeline of
detections with severity levels and MITRE ATT&CK mappings.

Complementary to EvtxECmd: EvtxECmd *parses* events, Hayabusa *detects* threats.
"""

from __future__ import annotations

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.base import BaseTool

HAYABUSA_PROFILES = ("minimal", "standard", "verbose", "all-field-info", "super-verbose")


class HayabusaTool(BaseTool):
    """Wrapper for Hayabusa EVTX threat hunting tool."""

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="hayabusa",
            display_name="Hayabusa",
            vendor="Yamato Security",
            version="2.18.0",
            description=(
                "Sigma-based threat hunting and detection for Windows Event Logs. "
                "Applies 4000+ detection rules with MITRE ATT&CK mapping."
            ),
            category=ToolCategory.DETECTION,
            command="hayabusa",
            runtime="native",
            timeout=3600,
            capabilities=[
                "sigma_detection", "threat_hunting", "evtx",
                "mitre_attack", "timeline", "alerting",
            ],
            input_types=["evtx"],
            output_formats=["csv", "jsonl"],
            artifact_types=[
                "windows.hayabusa.alert",
                "windows.hayabusa.detection",
            ],
            sans_categories=[
                "program_execution",
                "account_usage",
                "network_activity",
                "persistence",
            ],
        )

    def build_command(self, input_path: str, output_dir: str, **kwargs) -> list[str]:
        profile = kwargs.get("profile", "standard")
        if profile not in HAYABUSA_PROFILES:
            profile = "standard"

        output_file = f"{output_dir}/hayabusa_results.csv"

        cmd = [
            "hayabusa", "csv-timeline",
            "-d", input_path,
            "-o", output_file,
            "-w",          # overwrite output
            "-C",          # no color in output
            "-p", profile,
            "-q",          # quiet mode (no banner)
        ]

        # Custom rules directory
        rules_dir = kwargs.get("rules_dir")
        if rules_dir:
            cmd.extend(["-r", rules_dir])

        # Minimum severity level filter
        min_level = kwargs.get("min_level")
        if min_level:
            cmd.extend(["-l", min_level])

        return cmd
