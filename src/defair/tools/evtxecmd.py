"""EvtxECmd wrapper — Windows Event Log (.evtx) parser.

Covers SANS FOR500 categories:
- Program Execution (process creation events 4688, Sysmon 1)
- Account Usage (logon 4624/4625, RDP, service events)
- Network Activity (WLAN, firewall events)
- External Device (PnP events 20001, 10000)
- Persistence (service install, scheduled tasks)

Produces: CSV/JSON with parsed event records.
"""

from __future__ import annotations

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.base import BaseTool


class EvtxECmdTool(BaseTool):
    """Wrapper for Eric Zimmerman's EvtxECmd."""

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="evtxecmd",
            display_name="EvtxECmd",
            vendor="Eric Zimmerman",
            description="Windows Event Log parser. Parses .evtx files with event maps for structured output.",
            category=ToolCategory.EVENTLOG,
            command="EvtxECmd",
            runtime="dotnet",
            timeout=3600,
            capabilities=[
                "evtx", "event_logs", "security_log", "system_log",
                "application_log", "sysmon", "powershell_log",
            ],
            input_types=["evtx"],
            output_formats=["csv", "json", "jsonl", "xml"],
            artifact_types=[
                "windows.evtx.logon",
                "windows.evtx.logoff",
                "windows.evtx.process_creation",
                "windows.evtx.service_install",
                "windows.evtx.scheduled_task",
                "windows.evtx.rdp_connection",
                "windows.evtx.account_management",
                "windows.evtx.firewall",
                "windows.evtx.powershell",
                "windows.evtx.sysmon",
                "windows.evtx.pnp_device",
                "windows.evtx.wlan",
                "windows.evtx.generic",
            ],
            sans_categories=[
                "program_execution",
                "account_usage",
                "network_activity",
                "external_device",
            ],
        )

    def build_command(self, input_path: str, output_dir: str, **kwargs) -> list[str]:
        cmd = ["EvtxECmd"]

        # Single file or directory
        if kwargs.get("directory"):
            cmd.extend(["-d", input_path])
        else:
            cmd.extend(["-f", input_path])

        cmd.extend(["--csv", output_dir])

        if kwargs.get("json_output"):
            cmd.extend(["--json", output_dir])
        if kwargs.get("maps_dir"):
            cmd.extend(["--maps", kwargs["maps_dir"]])

        return cmd
