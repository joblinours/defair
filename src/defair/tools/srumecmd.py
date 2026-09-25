"""SrumECmd wrapper — System Resource Usage Monitor (SRUM) parser.

Covers SANS FOR500 categories:
- Program Execution (app execution with resource usage)
- Network Activity (network bytes sent/received per app)
- Account Usage (SID-to-username mapping)

SRUM (SRUDB.dat) tracks per-application:
- Network usage (bytes sent/received, interface)
- App timeline (foreground/background time)
- Energy usage
- Push notifications
- Windows notifications

Located at: C:\\Windows\\System32\\sru\\SRUDB.dat
Requires SOFTWARE hive for SID resolution.
"""

from __future__ import annotations

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.base import BaseTool


class SrumECmdTool(BaseTool):
    """Wrapper for Eric Zimmerman's SrumECmd."""

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="srumecmd",
            display_name="SrumECmd",
            allowed_options=["registry_hive"],
            vendor="Eric Zimmerman",
            description="SRUM parser. Extracts network usage, app timelines, energy usage, and push notification data per application with SID resolution.",
            category=ToolCategory.NETWORK,
            command="SrumECmd",
            runtime="dotnet",
            timeout=1800,
            capabilities=[
                "srum", "network_usage", "app_timeline", "energy_usage",
                "push_notifications", "bytes_sent", "bytes_received",
            ],
            input_types=["SRUDB.dat"],
            output_formats=["csv"],
            artifact_types=[
                "windows.srum.network_usage",
                "windows.srum.app_timeline",
                "windows.srum.energy_usage",
                "windows.srum.push_notification",
            ],
            sans_categories=[
                "program_execution",
                "network_activity",
                "account_usage",
            ],
        )

    def build_command(self, input_path: str, output_dir: str, **kwargs) -> list[str]:
        cmd = ["SrumECmd", "-f", input_path, "--csv", output_dir]
        if kwargs.get("registry_hive"):
            cmd.extend(["-r", kwargs["registry_hive"]])
        return cmd
