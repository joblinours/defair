"""Tool Registry — manages all available forensic tools.

The registry knows about every integrated tool, can check their health,
and provides lookup by name or capability.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from defair.models.tool_manifest import ToolManifest
    from defair.tools.base import BaseTool

log = structlog.get_logger(component="tool_registry")


class ToolRegistry:
    """Central registry of all forensic tools.

    Usage:
        registry = ToolRegistry()
        registry.register(MFTECmdTool())
        tool = registry.get("mftecmd")
        available = registry.list_available()
    """

    def __init__(self) -> None:
        self._tools: dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> None:
        """Register a tool in the registry."""
        m = tool.manifest()
        self._tools[m.name] = tool
        log.debug("tool_registered", tool=m.name, category=m.category)

    def get(self, name: str) -> BaseTool | None:
        """Get a tool by name."""
        return self._tools.get(name)

    def list_all(self) -> list[ToolManifest]:
        """List all registered tool manifests."""
        return [t.manifest() for t in self._tools.values()]

    def list_available(self) -> list[ToolManifest]:
        """List manifests of tools whose binary is available."""
        return [
            t.manifest()
            for t in self._tools.values()
            if t.is_available()
        ]

    def list_unavailable(self) -> list[ToolManifest]:
        """List manifests of tools whose binary is NOT available."""
        return [
            t.manifest()
            for t in self._tools.values()
            if not t.is_available()
        ]

    def list_by_category(self, category: str) -> list[ToolManifest]:
        """List tools matching a category."""
        return [
            t.manifest()
            for t in self._tools.values()
            if t.manifest().category == category
        ]

    def list_by_capability(self, capability: str) -> list[ToolManifest]:
        """List tools that have a specific capability."""
        return [
            t.manifest()
            for t in self._tools.values()
            if capability in t.manifest().capabilities
        ]

    def list_by_sans_category(self, sans_category: str) -> list[ToolManifest]:
        """List tools covering a SANS FOR500 artifact category."""
        return [
            t.manifest()
            for t in self._tools.values()
            if sans_category in t.manifest().sans_categories
        ]

    def health_check(self) -> dict[str, bool]:
        """Check availability of all registered tools."""
        return {
            name: tool.is_available()
            for name, tool in self._tools.items()
        }


def get_default_registry() -> ToolRegistry:
    """Create and populate the default registry with all known tools."""
    from defair.tools.amcache_parser import AmcacheParserTool
    from defair.tools.appcompat_parser import AppCompatCacheParserTool
    from defair.tools.bstrings import BstringsTool
    from defair.tools.chainsaw import ChainsawTool
    from defair.tools.dissect_plugin import DissectPluginTool
    from defair.tools.dissect_tool import DissectTool
    from defair.tools.evtx_native import EvtxNativeTool
    from defair.tools.evtxecmd import EvtxECmdTool
    from defair.tools.hayabusa import HayabusaTool
    from defair.tools.iis_native import IisNativeTool
    from defair.tools.indx_native import IndxNativeTool
    from defair.tools.jlecmd import JLECmdTool
    from defair.tools.lecmd import LECmdTool
    from defair.tools.lnk_native import LnkNativeTool
    from defair.tools.logfile_native import LogFileNativeTool
    from defair.tools.mftecmd import MFTECmdTool
    from defair.tools.mplog_native import MplogNativeTool
    from defair.tools.prefetch import PrefetchTool
    from defair.tools.psreadline_native import PsReadLineNativeTool
    from defair.tools.raijin import RaijinTool
    from defair.tools.rbcmd import RBCmdTool
    from defair.tools.rdpcache_native import RdpCacheNativeTool
    from defair.tools.recentfilecache import RecentFileCacheParserTool
    from defair.tools.recmd import RECmdTool
    from defair.tools.rla import RlaTool
    from defair.tools.sbecmd import SBECmdTool
    from defair.tools.sqlecmd import SQLECmdTool
    from defair.tools.srumecmd import SrumECmdTool
    from defair.tools.sumecmd import SumECmdTool
    from defair.tools.tasks_native import TasksNativeTool
    from defair.tools.webcache_native import WebCacheNativeTool
    from defair.tools.wxtcmd import WxTCmdTool

    registry = ToolRegistry()
    for tool_cls in [
        DissectTool,
        MFTECmdTool,
        EvtxECmdTool,
        HayabusaTool,
        RECmdTool,
        PrefetchTool,
        AmcacheParserTool,
        AppCompatCacheParserTool,
        LECmdTool,
        JLECmdTool,
        RBCmdTool,
        SBECmdTool,
        WxTCmdTool,
        SQLECmdTool,
        SrumECmdTool,
        RaijinTool,
        EvtxNativeTool,
        LnkNativeTool,
        DissectPluginTool,
        RecentFileCacheParserTool,
        SumECmdTool,
        BstringsTool,
        RlaTool,
        IndxNativeTool,
        LogFileNativeTool,
        MplogNativeTool,
        PsReadLineNativeTool,
        TasksNativeTool,
        WebCacheNativeTool,
        RdpCacheNativeTool,
        IisNativeTool,
        ChainsawTool,
    ]:
        registry.register(tool_cls())

    return registry
