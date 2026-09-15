"""Tests for the tool framework — registry, manifests, and wrappers."""

from __future__ import annotations

from defair.tools.registry import ToolRegistry, get_default_registry


class TestToolRegistry:
    def test_default_registry_has_15_tools(self):
        registry = get_default_registry()
        manifests = registry.list_all()
        assert len(manifests) == 15

    def test_all_tools_have_names(self):
        registry = get_default_registry()
        for m in registry.list_all():
            assert m.name
            assert m.display_name
            assert m.category

    def test_get_tool_by_name(self):
        registry = get_default_registry()
        tool = registry.get("mftecmd")
        assert tool is not None
        assert tool.manifest().name == "mftecmd"

    def test_get_unknown_tool(self):
        registry = get_default_registry()
        assert registry.get("nonexistent") is None

    def test_list_by_category(self):
        registry = get_default_registry()
        fs_tools = registry.list_by_category("filesystem")
        assert len(fs_tools) >= 1
        assert all(m.category == "filesystem" for m in fs_tools)

    def test_list_by_capability(self):
        registry = get_default_registry()
        evtx_tools = registry.list_by_capability("evtx")
        assert len(evtx_tools) >= 1

    def test_list_by_sans_category(self):
        registry = get_default_registry()
        exec_tools = registry.list_by_sans_category("program_execution")
        assert len(exec_tools) >= 4  # Prefetch, AmcacheParser, AppCompat, RECmd, etc.

    def test_health_check(self):
        registry = get_default_registry()
        health = registry.health_check()
        assert isinstance(health, dict)
        assert len(health) == 15
        # On dev machines without EZ Tools, all should be False
        assert all(isinstance(v, bool) for v in health.values())

    def test_empty_registry(self):
        registry = ToolRegistry()
        assert registry.list_all() == []
        assert registry.health_check() == {}


class TestToolManifests:
    """Verify each tool's manifest has correct SANS mappings."""

    def test_mftecmd_covers_filesystem(self):
        registry = get_default_registry()
        m = registry.get("mftecmd").manifest()
        assert "mft" in m.capabilities
        assert "filesystem" == m.category

    def test_evtxecmd_covers_eventlog(self):
        registry = get_default_registry()
        m = registry.get("evtxecmd").manifest()
        assert "evtx" in m.capabilities
        assert "program_execution" in m.sans_categories
        assert "account_usage" in m.sans_categories

    def test_recmd_covers_most_categories(self):
        registry = get_default_registry()
        m = registry.get("recmd").manifest()
        # RECmd is the most versatile — covers 8 SANS categories
        assert len(m.sans_categories) >= 6
        assert "registry" == m.category

    def test_prefetch_covers_execution(self):
        registry = get_default_registry()
        m = registry.get("prefetch").manifest()
        assert "prefetch" in m.capabilities
        assert "program_execution" in m.sans_categories
        assert m.runtime == "python"

    def test_rbcmd_covers_deleted_files(self):
        registry = get_default_registry()
        m = registry.get("rbcmd").manifest()
        assert "deleted_file" in m.sans_categories

    def test_sbecmd_covers_folder_opening(self):
        registry = get_default_registry()
        m = registry.get("sbecmd").manifest()
        assert "file_folder_opening" in m.sans_categories

    def test_lecmd_covers_external_device(self):
        registry = get_default_registry()
        m = registry.get("lecmd").manifest()
        assert "external_device" in m.sans_categories

    def test_srumecmd_covers_network(self):
        registry = get_default_registry()
        m = registry.get("srumecmd").manifest()
        assert "network_activity" in m.sans_categories

    def test_sqlecmd_covers_browser(self):
        registry = get_default_registry()
        m = registry.get("sqlecmd").manifest()
        assert "browser_usage" in m.sans_categories

    def test_all_tools_have_build_command(self):
        """Every tool can produce a command line."""
        registry = get_default_registry()
        for m in registry.list_all():
            tool = registry.get(m.name)
            cmd = tool.build_command("/input/file", "/output/dir")
            assert isinstance(cmd, list)
            assert len(cmd) >= 2


class TestToolBuildCommand:
    def test_mftecmd_command(self):
        registry = get_default_registry()
        tool = registry.get("mftecmd")
        cmd = tool.build_command("/evidence/$MFT", "/output")
        assert cmd == ["MFTECmd", "-f", "/evidence/$MFT", "--csv", "/output"]

    def test_evtxecmd_directory(self):
        registry = get_default_registry()
        tool = registry.get("evtxecmd")
        cmd = tool.build_command("/evidence/logs", "/output", directory=True)
        assert "-d" in cmd
        assert "/evidence/logs" in cmd

    def test_prefetch_is_available(self):
        registry = get_default_registry()
        tool = registry.get("prefetch")
        # PrefetchTool is always available (pure Python)
        assert tool.is_available() is True
