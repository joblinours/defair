"""Tests for the DEFAIR MCP server.

Case/evidence MCP tools proxy into containers via container_service.exec_in_container.
Container management tools call container_service directly.
All Docker interactions are mocked.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from defair.services.container_service import ContainerInfo


def _get_text(result) -> str | None:
    """Extract text from a FastMCP ToolResult."""
    if not result.content:
        return None
    return result.content[0].text


@pytest.fixture
def mcp_server():
    """Return the MCP server instance."""
    from defair.mcp_server.server import mcp
    return mcp


# ---------------------------------------------------------------------------
# Container management tools (run on host, mock container_service)
# ---------------------------------------------------------------------------


class TestMCPContainerTools:
    @pytest.mark.asyncio
    @patch("defair.mcp_server.server.container_service")
    async def test_create_container(self, mock_cs, mcp_server):
        mock_info = ContainerInfo(
            name="defair-case-2026-001",
            container_id="abc123",
            status="created",
            image="ghcr.io/joblinours/defair:latest",
            workspace="/home/user/.defair/workspaces/defair-case-2026-001",
        )
        mock_cs.create_container = AsyncMock(return_value=mock_info)
        # After create, start is called (start=True by default)
        started_info = ContainerInfo(
            name="defair-case-2026-001",
            container_id="abc123",
            status="running",
            image="ghcr.io/joblinours/defair:latest",
            workspace="/home/user/.defair/workspaces/defair-case-2026-001",
        )
        mock_cs.start_container = AsyncMock(return_value=started_info)
        mock_cs.DEFAULT_IMAGE = "ghcr.io/joblinours/defair:latest"

        result = await mcp_server.call_tool(
            "create_container", {"case_id": "CASE-2026-001"}
        )
        text = _get_text(result)
        data = json.loads(text)
        assert data["name"] == "defair-case-2026-001"
        assert data["status"] == "running"

    @pytest.mark.asyncio
    @patch("defair.mcp_server.server.container_service")
    async def test_list_containers(self, mock_cs, mcp_server):
        mock_cs.list_containers = AsyncMock(return_value=[
            ContainerInfo(
                name="defair-case-2026-001",
                container_id="abc",
                status="running",
                image="ghcr.io/joblinours/defair:latest",
                workspace="/ws/1",
            ),
        ])

        result = await mcp_server.call_tool("list_containers", {})
        text = _get_text(result)
        data = json.loads(text)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["name"] == "defair-case-2026-001"

    @pytest.mark.asyncio
    async def test_exec_in_container_disabled_by_default(self, mcp_server):
        names = {t.name for t in await mcp_server.list_tools()}
        assert "exec_in_container" not in names
        assert "run_tool" in names

    @pytest.mark.asyncio
    async def test_exec_in_container_enabled_by_flag(self):
        import importlib

        import defair.mcp_server.server as server_module
        from defair.config import DefairConfig

        enabled = DefairConfig(mcp={"allow_exec": True})
        try:
            with patch("defair.config.load_config", return_value=enabled):
                reloaded = importlib.reload(server_module)
            names = {t.name for t in await reloaded.mcp.list_tools()}
            assert "exec_in_container" in names
        finally:
            importlib.reload(server_module)

    @pytest.mark.asyncio
    @patch("defair.mcp_server.server.container_service")
    async def test_create_container_enforces_policy(self, mock_cs, mcp_server):
        mock_cs.create_container = AsyncMock(return_value=ContainerInfo(
            name="defair-x", container_id="a", status="created", image="img",
        ))
        mock_cs.DEFAULT_IMAGE = "ghcr.io/joblinours/defair:latest"

        await mcp_server.call_tool(
            "create_container", {"case_id": "CASE-2026-001", "start": False},
        )
        kwargs = mock_cs.create_container.call_args.kwargs
        assert kwargs["strict_evidence_roots"] is True
        assert kwargs["policy"] is not None

    @pytest.mark.asyncio
    @patch("defair.mcp_server.server.container_service")
    async def test_stop_container(self, mock_cs, mcp_server):
        mock_cs.stop_container = AsyncMock(return_value=ContainerInfo(
            name="defair-case-2026-001",
            container_id="abc",
            status="exited",
            image="ghcr.io/joblinours/defair:latest",
            workspace="/ws/1",
        ))

        result = await mcp_server.call_tool(
            "stop_container", {"name_or_id": "defair-case-2026-001"}
        )
        text = _get_text(result)
        data = json.loads(text)
        assert data["status"] == "exited"

    @pytest.mark.asyncio
    @patch("defair.mcp_server.server.container_service")
    async def test_remove_container(self, mock_cs, mcp_server):
        mock_cs.remove_container = AsyncMock(return_value={
            "removed": "defair-case-2026-001",
        })

        result = await mcp_server.call_tool(
            "remove_container", {"name_or_id": "defair-case-2026-001"}
        )
        text = _get_text(result)
        data = json.loads(text)
        assert data["removed"] == "defair-case-2026-001"


# ---------------------------------------------------------------------------
# Case tools (proxied into container via exec_in_container)
# ---------------------------------------------------------------------------


class TestMCPCaseTools:
    @pytest.mark.asyncio
    @patch("defair.mcp_server.server.container_service")
    async def test_create_case(self, mock_cs, mcp_server):
        mock_cs.exec_in_container = AsyncMock(return_value={
            "exit_code": 0,
            "stdout": "✓ Case created: CASE-2026-001\n  Name: Test Incident\n",
            "stderr": "",
        })

        result = await mcp_server.call_tool(
            "create_case",
            {"container": "defair-test", "name": "Test Incident", "description": "A test"},
        )
        text = _get_text(result)
        assert "CASE-2026-001" in text
        assert "Test Incident" in text

        # Verify the exec call
        mock_cs.exec_in_container.assert_called_once()
        call_args = mock_cs.exec_in_container.call_args
        assert call_args[0][0] == "defair-test"
        cmd = call_args[0][1]
        assert cmd == ["defair", "case", "create", "Test Incident", "--description", "A test"]

    @pytest.mark.asyncio
    @patch("defair.mcp_server.server.container_service")
    async def test_list_cases(self, mock_cs, mcp_server):
        mock_cs.exec_in_container = AsyncMock(return_value={
            "exit_code": 0,
            "stdout": "CASE-2026-001  Test Case  active  2026-09-12\n",
            "stderr": "",
        })

        result = await mcp_server.call_tool(
            "list_cases", {"container": "defair-test"}
        )
        text = _get_text(result)
        assert "CASE-2026-001" in text

    @pytest.mark.asyncio
    @patch("defair.mcp_server.server.container_service")
    async def test_get_case(self, mock_cs, mcp_server):
        mock_cs.exec_in_container = AsyncMock(return_value={
            "exit_code": 0,
            "stdout": "CASE-2026-001 — Test Case\n  Status: active\n",
            "stderr": "",
        })

        result = await mcp_server.call_tool(
            "get_case", {"container": "defair-test", "case_id": "CASE-2026-001"}
        )
        text = _get_text(result)
        assert "CASE-2026-001" in text

    @pytest.mark.asyncio
    @patch("defair.mcp_server.server.container_service")
    async def test_create_case_failure(self, mock_cs, mcp_server):
        from fastmcp.exceptions import ToolError

        mock_cs.exec_in_container = AsyncMock(return_value={
            "exit_code": 1,
            "stdout": "",
            "stderr": "Error: database locked\n",
        })

        with pytest.raises(ToolError, match="Command failed"):
            await mcp_server.call_tool(
                "create_case", {"container": "defair-test", "name": "Fail"}
            )


# ---------------------------------------------------------------------------
# Evidence tools (proxied into container via exec_in_container)
# ---------------------------------------------------------------------------


class TestMCPEvidenceTools:
    @pytest.mark.asyncio
    @patch("defair.mcp_server.server.container_service")
    async def test_register_evidence(self, mock_cs, mcp_server):
        mock_cs.exec_in_container = AsyncMock(return_value={
            "exit_code": 0,
            "stdout": "✓ Evidence registered: EVD-001\n  SHA-256: abc123\n",
            "stderr": "",
        })

        result = await mcp_server.call_tool(
            "register_evidence",
            {
                "container": "defair-test",
                "case_id": "CASE-2026-001",
                "path": "/evidence/disk.E01",
                "evidence_type": "disk_image",
            },
        )
        text = _get_text(result)
        assert "EVD-001" in text

        cmd = mock_cs.exec_in_container.call_args[0][1]
        assert cmd == [
            "defair", "evidence", "add", "CASE-2026-001",
            "/evidence/disk.E01", "--type", "disk_image",
        ]

    @pytest.mark.asyncio
    @patch("defair.mcp_server.server.container_service")
    async def test_list_evidence(self, mock_cs, mcp_server):
        mock_cs.exec_in_container = AsyncMock(return_value={
            "exit_code": 0,
            "stdout": "EVD-001  disk.E01  disk_image\n",
            "stderr": "",
        })

        result = await mcp_server.call_tool(
            "list_evidence", {"container": "defair-test"}
        )
        text = _get_text(result)
        assert "EVD-001" in text

    @pytest.mark.asyncio
    @patch("defair.mcp_server.server.container_service")
    async def test_list_evidence_with_case_filter(self, mock_cs, mcp_server):
        mock_cs.exec_in_container = AsyncMock(return_value={
            "exit_code": 0,
            "stdout": "EVD-001  disk.E01  disk_image\n",
            "stderr": "",
        })

        await mcp_server.call_tool(
            "list_evidence", {"container": "defair-test", "case_id": "CASE-2026-001"}
        )

        cmd = mock_cs.exec_in_container.call_args[0][1]
        assert "--case" in cmd
        assert "CASE-2026-001" in cmd

    @pytest.mark.asyncio
    @patch("defair.mcp_server.server.container_service")
    async def test_get_evidence(self, mock_cs, mcp_server):
        mock_cs.exec_in_container = AsyncMock(return_value={
            "exit_code": 0,
            "stdout": "EVD-001\n  File: disk.E01\n  SHA-256: abc\n",
            "stderr": "",
        })

        result = await mcp_server.call_tool(
            "get_evidence", {"container": "defair-test", "evidence_id": "EVD-001"}
        )
        text = _get_text(result)
        assert "EVD-001" in text

    @pytest.mark.asyncio
    @patch("defair.mcp_server.server.container_service")
    async def test_verify_evidence(self, mock_cs, mcp_server):
        mock_cs.exec_in_container = AsyncMock(return_value={
            "exit_code": 0,
            "stdout": "✓ VERIFIED — EVD-001 (disk.E01)\n  SHA-256: abc\n",
            "stderr": "",
        })

        result = await mcp_server.call_tool(
            "verify_evidence", {"container": "defair-test", "evidence_id": "EVD-001"}
        )
        text = _get_text(result)
        assert "VERIFIED" in text

    @pytest.mark.asyncio
    @patch("defair.mcp_server.server.container_service")
    async def test_verify_evidence_mismatch(self, mock_cs, mcp_server):
        mock_cs.exec_in_container = AsyncMock(return_value={
            "exit_code": 0,
            "stdout": "✗ INTEGRITY FAILURE — EVD-001\n  ⚠ Evidence has been modified!\n",
            "stderr": "",
        })

        result = await mcp_server.call_tool(
            "verify_evidence", {"container": "defair-test", "evidence_id": "EVD-001"}
        )
        text = _get_text(result)
        assert "INTEGRITY FAILURE" in text or "modified" in text


# ---------------------------------------------------------------------------
# run_tool (v0.3.6) — the safe replacement for arbitrary exec
# ---------------------------------------------------------------------------


class TestMCPRunTool:
    @pytest.mark.asyncio
    @patch("defair.mcp_server.server.container_service")
    async def test_run_tool_proxies_analyze(self, mock_cs, mcp_server):
        mock_cs.exec_in_container = AsyncMock(return_value={
            "exit_code": 0, "stdout": "ok", "stderr": "",
        })
        await mcp_server.call_tool("run_tool", {
            "container": "defair-case-2026-001",
            "tool": "hayabusa",
            "input_path": "/evidence/logs",
            "case_id": "CASE-2026-001",
            "options": {"min_level": "high"},
            "directory": True,
        })
        cmd = mock_cs.exec_in_container.call_args.args[1]
        assert cmd[:4] == ["defair", "analyze", "hayabusa", "/evidence/logs"]
        assert "--directory" in cmd
        assert cmd[cmd.index("--option") + 1] == "min_level=high"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("payload, message", [
        ({"tool": "rm", "input_path": "/evidence/x"}, "Unknown tool"),
        ({"tool": "mftecmd", "input_path": "/etc/shadow"}, "must be under"),
        ({"tool": "mftecmd", "input_path": "/evidence/../etc"}, "must be under"),
        ({"tool": "mftecmd", "input_path": "/evidence/$MFT",
          "options": {"shell": "id"}}, "not allowed"),
        ({"tool": "evtxecmd", "input_path": "/evidence/logs",
          "options": {"maps_dir": "/etc"}}, "must be under"),
    ])
    @patch("defair.mcp_server.server.container_service")
    async def test_run_tool_rejects(self, mock_cs, mcp_server, payload, message):
        mock_cs.exec_in_container = AsyncMock()
        args = {"container": "c", "case_id": "CASE-2026-001", **payload}
        with pytest.raises(Exception, match=message):
            await mcp_server.call_tool("run_tool", args)
        mock_cs.exec_in_container.assert_not_called()
