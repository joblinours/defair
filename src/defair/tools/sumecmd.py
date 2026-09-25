"""SumECmd wrapper — User Access Logging (UAL) databases (Windows Server).

Covers SANS FOR500 categories:
- Account Usage (authenticated users per server role)
- Network Activity (client IP addresses and host names)

UAL (``Current.mdb``, ``{GUID}.mdb``, ``SystemIdentity.mdb``) records, for
up to three years, which client (IP + user) reached which server role (SMB,
RDP gateway, IIS, DHCP, …), first / last seen and daily access counts —
lateral movement evidence on Windows Server 2012+.

Located at: C:\\Windows\\System32\\LogFiles\\Sum\\
"""

from __future__ import annotations

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.base import BaseTool


class SumECmdTool(BaseTool):
    """Wrapper for Eric Zimmerman's SumECmd."""

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="sumecmd",
            display_name="SumECmd",
            allowed_options=[],
            vendor="Eric Zimmerman",
            description="User Access Logging (UAL) parser: clients, users and server roles accessed (Windows Server).",
            category=ToolCategory.NETWORK,
            command="SumECmd",
            runtime="dotnet",
            timeout=1800,
            capabilities=["ual", "sum", "lateral_movement", "client_access"],
            input_types=["Sum directory (Current.mdb, SystemIdentity.mdb)"],
            output_formats=["csv"],
            artifact_types=[
                "windows.ual.client_access",
                "windows.ual.role_access",
                "windows.ual.dns",
                "windows.ual.virtual_machine",
            ],
            sans_categories=["account_usage", "network_activity"],
        )

    def build_command(self, input_path: str, output_dir: str, **kwargs) -> list[str]:
        # --wd adds one row per client and day: the summary file is enough
        return ["SumECmd", "-d", input_path, "--csv", output_dir, "--dt", "yyyy-MM-dd HH:mm:ss.fffffff"]
