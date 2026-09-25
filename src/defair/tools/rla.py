"""rla wrapper — Registry Log Applier (replay dirty hives).

Hives copied from a live or crashed system are often "dirty": recent changes
still sit in the ``.LOG1`` / ``.LOG2`` transaction logs. rla applies those
logs and writes clean copies to the workspace — the evidence is never
modified — so RECmd, AmcacheParser and AppCompatCacheParser see every key.

Produces hives, not artifacts: a profile step uses its output directory as
the input of the registry steps (``input: step:hives_replay``).
"""

from __future__ import annotations

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.base import BaseTool


class RlaTool(BaseTool):
    """Wrapper for Eric Zimmerman's rla."""

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="rla",
            display_name="rla (Registry Log Applier)",
            allowed_options=["directory"],
            vendor="Eric Zimmerman",
            description="Apply registry transaction logs to dirty hives; clean copies are written to the workspace.",
            category=ToolCategory.REGISTRY,
            command="rla",
            runtime="dotnet",
            timeout=1800,
            capabilities=["registry", "transaction_logs", "dirty_hive_replay", "preprocessing"],
            input_types=["registry hive", "directory of hives"],
            output_formats=["hive"],
            artifact_types=[],
            sans_categories=[],
        )

    def build_command(self, input_path: str, output_dir: str, **kwargs) -> list[str]:
        flag = "-d" if kwargs.get("directory", True) else "-f"
        # --ca: clean hives are copied too, so the output holds a complete set
        return ["rla", flag, input_path, "--out", output_dir, "--ca"]
