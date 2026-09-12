"""Tests for the discovery service."""

from __future__ import annotations

from pathlib import Path

import pytest

from defair.services.discovery_service import discover_artifacts, _identify_file, _matches_pattern


class TestPatternMatching:
    def test_exact_match(self):
        assert _matches_pattern("SAM", "SAM")
        assert not _matches_pattern("SAM", "SYSTEM")

    def test_suffix_wildcard(self):
        assert _matches_pattern("Security.evtx", "*.evtx")
        assert not _matches_pattern("Security.log", "*.evtx")

    def test_prefix_wildcard(self):
        assert _matches_pattern("$I12345", "$I*")
        assert not _matches_pattern("INFO2", "$I*")

    def test_middle_wildcard(self):
        assert _matches_pattern("thumbcache_256.db", "thumbcache_*.db")
        assert not _matches_pattern("thumbcache.db", "thumbcache_*.db")


class TestFileIdentification:
    def test_identify_evtx(self, tmp_path):
        evtx = tmp_path / "Security.evtx"
        evtx.write_bytes(b"dummy")
        results = _identify_file(evtx)
        assert len(results) >= 1
        assert any(r["type"] == "evtx" for r in results)

    def test_identify_registry_sam(self, tmp_path):
        sam = tmp_path / "SAM"
        sam.write_bytes(b"dummy")
        results = _identify_file(sam)
        assert len(results) == 1
        assert results[0]["type"] == "registry"
        assert results[0]["tool"] == "recmd"

    def test_identify_prefetch(self, tmp_path):
        pf = tmp_path / "CALC.EXE-12345678.pf"
        pf.write_bytes(b"dummy")
        results = _identify_file(pf)
        assert any(r["type"] == "prefetch" for r in results)

    def test_identify_lnk(self, tmp_path):
        lnk = tmp_path / "recent.lnk"
        lnk.write_bytes(b"dummy")
        results = _identify_file(lnk)
        assert any(r["type"] == "lnk" for r in results)

    def test_identify_amcache(self, tmp_path):
        amcache = tmp_path / "Amcache.hve"
        amcache.write_bytes(b"dummy")
        results = _identify_file(amcache)
        assert any(r["type"] == "amcache" for r in results)

    def test_identify_recyclebin(self, tmp_path):
        ifile = tmp_path / "$IABC123"
        ifile.write_bytes(b"dummy")
        results = _identify_file(ifile)
        assert any(r["type"] == "recyclebin" for r in results)

    def test_identify_unknown_file(self, tmp_path):
        unknown = tmp_path / "random.txt"
        unknown.write_bytes(b"dummy")
        results = _identify_file(unknown)
        assert len(results) == 0


class TestDiscoverArtifacts:
    @pytest.mark.asyncio
    async def test_discover_empty_dir(self, tmp_path):
        result = await discover_artifacts(str(tmp_path))
        assert result["total_artifacts_found"] == 0
        assert result["platform"] == "unknown"

    @pytest.mark.asyncio
    async def test_discover_windows_artifacts(self, tmp_path):
        # Create fake Windows artifacts
        (tmp_path / "Security.evtx").write_bytes(b"evtx")
        (tmp_path / "System.evtx").write_bytes(b"evtx")
        (tmp_path / "SAM").write_bytes(b"registry")
        (tmp_path / "SYSTEM").write_bytes(b"registry")
        (tmp_path / "NTUSER.DAT").write_bytes(b"registry")

        result = await discover_artifacts(str(tmp_path))
        assert result["platform"] == "windows"
        assert result["total_artifacts_found"] >= 5
        assert "evtx" in result["artifact_types"]
        assert "registry" in result["artifact_types"]

    @pytest.mark.asyncio
    async def test_discover_recommends_tools(self, tmp_path):
        (tmp_path / "Security.evtx").write_bytes(b"evtx")
        (tmp_path / "CALC.EXE-1234.pf").write_bytes(b"pf")

        result = await discover_artifacts(str(tmp_path))
        tools = [r["tool"] for r in result["recommended_tools"]]
        assert "evtxecmd" in tools
        assert "pecmd" in tools

    @pytest.mark.asyncio
    async def test_discover_nonexistent_path(self):
        with pytest.raises(FileNotFoundError):
            await discover_artifacts("/nonexistent/path")
