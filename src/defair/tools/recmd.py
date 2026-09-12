"""RECmd wrapper — Windows Registry hive parser.

Covers SANS FOR500 categories:
- Program Execution (UserAssist, BAM/DAM, RecentApps)
- File Download (Open/Save MRU)
- File/Folder Opening (Recent Files, Open/Save MRU, Last-Visited MRU)
- Deleted File Knowledge (WordWheelQuery)
- Network Activity (Network History, interfaces)
- External Device (USB, MountedDevices, MountPoints2)
- Account Usage (Last Login, ProfileList, SAM)
- Browser Usage (TypedURLs)
- Persistence (Run keys, Services)

The most versatile EZ Tool — covers nearly every SANS category through
different registry hives (SAM, SYSTEM, SOFTWARE, NTUSER.DAT, UsrClass.dat).
"""

from __future__ import annotations

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.base import BaseTool


class RECmdTool(BaseTool):
    """Wrapper for Eric Zimmerman's RECmd."""

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="recmd",
            display_name="RECmd",
            vendor="Eric Zimmerman",
            description=(
                "Windows Registry parser with batch processing. "
                "Uses RECmd batch files to extract UserAssist, MRU, ShellBags, "
                "USB devices, network info, persistence keys, and more."
            ),
            category=ToolCategory.REGISTRY,
            command="RECmd",
            runtime="dotnet",
            timeout=3600,
            capabilities=[
                "registry", "sam", "system", "software", "ntuser", "usrclass",
                "userassist", "mru", "shellbags", "usb_devices", "network_history",
                "persistence", "services", "run_keys", "bam_dam", "recent_apps",
                "typed_urls", "wordwheelquery", "mountpoints", "last_login",
            ],
            input_types=["SAM", "SYSTEM", "SOFTWARE", "NTUSER.DAT", "UsrClass.dat", "Amcache.hve"],
            output_formats=["csv", "json"],
            artifact_types=[
                "windows.registry.userassist",
                "windows.registry.mru_opensave",
                "windows.registry.mru_lastvisited",
                "windows.registry.recent_docs",
                "windows.registry.run_key",
                "windows.registry.service",
                "windows.registry.bam_dam",
                "windows.registry.recent_apps",
                "windows.registry.typed_urls",
                "windows.registry.wordwheelquery",
                "windows.registry.usb_device",
                "windows.registry.mountpoint",
                "windows.registry.network_profile",
                "windows.registry.timezone",
                "windows.registry.last_login",
                "windows.registry.profile_list",
                "windows.registry.generic",
            ],
            sans_categories=[
                "program_execution",
                "file_download",
                "file_folder_opening",
                "deleted_file",
                "network_activity",
                "external_device",
                "account_usage",
                "browser_usage",
            ],
        )

    def build_command(self, input_path: str, output_dir: str, **kwargs) -> list[str]:
        cmd = ["RECmd"]

        if kwargs.get("directory"):
            cmd.extend(["-d", input_path])
        else:
            cmd.extend(["-f", input_path])

        cmd.extend(["--csv", output_dir])

        # Batch file for structured extraction
        if kwargs.get("batch_file"):
            cmd.extend(["--bn", kwargs["batch_file"]])
        elif kwargs.get("use_default_batch", True):
            cmd.extend(["--bn", "/opt/eztools/BatchExamples/RECmd_Batch_MC.reb"])

        if kwargs.get("json_output"):
            cmd.extend(["--json", output_dir])

        return cmd
