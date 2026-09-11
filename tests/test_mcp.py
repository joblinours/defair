"""Tests for the DEFAIR MCP server.

These tests instantiate the FastMCP server directly and call tools
via call_tool() — no subprocess or network needed.
"""

from __future__ import annotations

import json

import pytest

from defair.database import get_initialized_connection


@pytest.fixture
async def mcp_server(tmp_path):
    """Create a fresh MCP server instance with a temp database.

    Patches the module-level config and connection so each test
    gets its own isolated database.
    """
    from unittest.mock import patch

    from defair.config import DefairConfig, StorageConfig

    db_path = tmp_path / "mcp_test.db"
    test_config = DefairConfig(
        storage=StorageConfig(database=db_path),
    )

    # Pre-create the connection so the server uses our temp DB
    conn = await get_initialized_connection(db_path)

    with patch("defair.mcp_server.server._config", test_config), \
         patch("defair.mcp_server.server._db_conn", conn):
        import importlib

        import defair.mcp_server.server as server_module
        importlib.reload(server_module)

        # Re-patch after reload (reload resets module-level vars)
        server_module._config = test_config
        server_module._db_conn = conn

        yield server_module.mcp

    await conn.close()


def _get_text(result) -> str | None:
    """Extract text from a FastMCP ToolResult."""
    if not result.content:
        return None
    return result.content[0].text


class TestMCPTools:
    @pytest.mark.asyncio
    async def test_create_case(self, mcp_server):
        result = await mcp_server.call_tool(
            "create_case", {"name": "MCP Test Case", "description": "Created via MCP"}
        )
        text = _get_text(result)
        data = json.loads(text)
        assert data["name"] == "MCP Test Case"
        assert data["case_number"].startswith("CASE-")
        assert data["status"] == "active"

    @pytest.mark.asyncio
    async def test_list_cases(self, mcp_server):
        await mcp_server.call_tool("create_case", {"name": "Listed Case"})
        result = await mcp_server.call_tool("list_cases", {})
        text = _get_text(result)
        data = json.loads(text)
        assert isinstance(data, list)
        assert len(data) >= 1
        assert any(c["name"] == "Listed Case" for c in data)

    @pytest.mark.asyncio
    async def test_get_case(self, mcp_server):
        create_result = await mcp_server.call_tool(
            "create_case", {"name": "Get Me"}
        )
        created = json.loads(_get_text(create_result))
        case_number = created["case_number"]

        get_result = await mcp_server.call_tool("get_case", {"case_id": case_number})
        found = json.loads(_get_text(get_result))
        assert found["name"] == "Get Me"
        assert found["case_number"] == case_number

    @pytest.mark.asyncio
    async def test_get_case_not_found(self, mcp_server):
        result = await mcp_server.call_tool("get_case", {"case_id": "CASE-9999-999"})
        text = _get_text(result)
        # When tool returns None, FastMCP may return empty content or "null"
        assert text is None or text == "null" or text == "None"


class TestMCPEvidenceTools:
    @pytest.mark.asyncio
    async def test_register_evidence(self, mcp_server, sample_file):
        # Create a case first
        await mcp_server.call_tool("create_case", {"name": "MCP Evidence Case"})

        result = await mcp_server.call_tool(
            "register_evidence",
            {"case_id": "CASE-2026-001", "path": str(sample_file)},
        )
        text = _get_text(result)
        data = json.loads(text)
        assert data["evidence_number"] == "EVD-001"
        assert data["filename"] == "sample.txt"
        assert len(data["sha256"]) == 64

    @pytest.mark.asyncio
    async def test_list_evidence(self, mcp_server, sample_file):
        await mcp_server.call_tool("create_case", {"name": "MCP List Evd"})
        await mcp_server.call_tool(
            "register_evidence",
            {"case_id": "CASE-2026-001", "path": str(sample_file)},
        )

        result = await mcp_server.call_tool("list_evidence", {})
        text = _get_text(result)
        data = json.loads(text)
        assert isinstance(data, list)
        assert len(data) >= 1
        assert data[0]["filename"] == "sample.txt"

    @pytest.mark.asyncio
    async def test_list_evidence_filter_by_case(self, mcp_server, sample_file):
        await mcp_server.call_tool("create_case", {"name": "Filtered Case"})
        await mcp_server.call_tool(
            "register_evidence",
            {"case_id": "CASE-2026-001", "path": str(sample_file)},
        )

        result = await mcp_server.call_tool(
            "list_evidence", {"case_id": "CASE-2026-001"}
        )
        text = _get_text(result)
        data = json.loads(text)
        assert len(data) == 1

    @pytest.mark.asyncio
    async def test_get_evidence(self, mcp_server, sample_file):
        await mcp_server.call_tool("create_case", {"name": "MCP Get Evd"})
        await mcp_server.call_tool(
            "register_evidence",
            {"case_id": "CASE-2026-001", "path": str(sample_file)},
        )

        result = await mcp_server.call_tool(
            "get_evidence", {"evidence_id": "EVD-001"}
        )
        text = _get_text(result)
        data = json.loads(text)
        assert data["evidence_number"] == "EVD-001"
        assert data["filename"] == "sample.txt"

    @pytest.mark.asyncio
    async def test_get_evidence_not_found(self, mcp_server):
        result = await mcp_server.call_tool(
            "get_evidence", {"evidence_id": "EVD-999"}
        )
        text = _get_text(result)
        assert text is None or text == "null" or text == "None"

    @pytest.mark.asyncio
    async def test_verify_evidence(self, mcp_server, sample_file):
        await mcp_server.call_tool("create_case", {"name": "MCP Verify"})
        await mcp_server.call_tool(
            "register_evidence",
            {"case_id": "CASE-2026-001", "path": str(sample_file)},
        )

        result = await mcp_server.call_tool(
            "verify_evidence", {"evidence_id": "EVD-001"}
        )
        text = _get_text(result)
        data = json.loads(text)
        assert data["status"] == "ok"
        assert data["verified"] is True
