"""Tests for the cross-platform Prefetch parser (PrefetchTool).

Tests the Python-native prefetch parser that replaces PECmd.
"""

from __future__ import annotations

import csv
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from defair.normalizers.eztools import PrefetchNormalizer, get_normalizer
from defair.tools.prefetch import PrefetchTool
from defair.tools.registry import get_default_registry


class TestPrefetchToolManifest:
    def test_manifest_basics(self):
        m = PrefetchTool.manifest()
        assert m.name == "prefetch"
        assert m.runtime == "python"
        assert m.category == "execution"
        assert "prefetch" in m.capabilities
        assert "program_execution" in m.sans_categories
        assert "pf" in m.input_types

    def test_manifest_artifact_types(self):
        m = PrefetchTool.manifest()
        assert "windows.prefetch.execution" in m.artifact_types

    def test_registered_in_registry(self):
        registry = get_default_registry()
        tool = registry.get("prefetch")
        assert tool is not None
        assert isinstance(tool, PrefetchTool)

    def test_is_available(self):
        tool = PrefetchTool()
        assert tool.is_available() is True

    def test_is_available_without_lib(self):
        tool = PrefetchTool()
        with (
            patch.dict("sys.modules", {"windowsprefetch": None}),
            patch("builtins.__import__", side_effect=ImportError),
        ):
            assert tool.is_available() is False


class TestPrefetchToolParsing:
    def test_extract_row(self):
        """Test _extract_row with a mock Prefetch object."""
        mock_pf = MagicMock()
        mock_pf.executableName = "POWERSHELL.EXE"
        mock_pf.hash = "ABCD1234"
        mock_pf.runCount = 5
        mock_pf.timestamps = [
            "2026-01-15 14:30:00",
            "2026-01-14 10:00:00",
            "2026-01-13 09:00:00",
        ]
        mock_pf.resources = [
            "\\VOLUME{01}\\WINDOWS\\SYSTEM32\\POWERSHELL.EXE",
            "\\VOLUME{01}\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
        ]
        mock_pf.directoryStringsArray = [
            ["\\VOLUME{01}\\WINDOWS\\SYSTEM32", "\\VOLUME{01}\\WINDOWS"],
        ]
        mock_pf.volumesInformationArray = [
            {
                "Volume Name": "\\DEVICE\\HARDDISKVOLUME2".encode("UTF-16"),
                "Serial Number": "A1B2C3D4",
                "Creation Date": "2025-06-01 00:00:00",
            }
        ]

        tool = PrefetchTool()
        row = tool._extract_row(mock_pf, Path("/evidence/POWERSHELL.EXE-1234.pf"))

        assert row["ExecutableName"] == "POWERSHELL.EXE"
        assert row["Hash"] == "ABCD1234"
        assert row["RunCount"] == "5"
        assert row["LastRun"] == "2026-01-15 14:30:00"
        assert row["PreviousRun0"] == "2026-01-14 10:00:00"
        assert row["PreviousRun1"] == "2026-01-13 09:00:00"
        assert row["PreviousRun2"] == ""
        assert "POWERSHELL.EXE" in row["FilesLoaded"]
        assert "NTDLL.DLL" in row["FilesLoaded"]
        assert "SYSTEM32" in row["Directories"]
        assert row["Volume0Serial"] == "A1B2C3D4"

    def test_write_csv(self, tmp_path):
        """Test CSV output writing."""
        rows = [
            {
                "SourceFilename": "/evidence/CALC.EXE-1234.pf",
                "ExecutableName": "CALC.EXE",
                "Hash": "AAAA",
                "RunCount": "3",
                "LastRun": "2026-01-15 14:00:00",
                "PreviousRun0": "",
                "PreviousRun1": "",
                "PreviousRun2": "",
                "PreviousRun3": "",
                "PreviousRun4": "",
                "PreviousRun5": "",
                "PreviousRun6": "",
                "Volume0Name": "C:",
                "Volume0Serial": "1234",
                "Volume0Created": "",
                "Directories": "",
                "FilesLoaded": "",
            },
        ]

        csv_path = tmp_path / "prefetch_results.csv"
        PrefetchTool._write_csv(rows, csv_path)

        assert csv_path.exists()
        content = csv_path.read_text()
        reader = csv.DictReader(content.splitlines())
        parsed = list(reader)
        assert len(parsed) == 1
        assert parsed[0]["ExecutableName"] == "CALC.EXE"
        assert parsed[0]["RunCount"] == "3"

    def test_parse_empty_directory(self, tmp_path):
        """An empty directory returns no rows."""
        tool = PrefetchTool()
        rows = tool._parse_prefetch_files(str(tmp_path))
        assert rows == []


class TestPrefetchToolRun:
    @pytest.mark.asyncio
    async def test_run_empty_dir(self, tmp_path):
        """Running on a directory with no .pf files succeeds with 0 results."""
        tool = PrefetchTool()
        output_dir = str(tmp_path / "output")

        run = await tool.run(
            input_path=str(tmp_path),
            output_dir=output_dir,
            case_id="test-case",
            run_number="RUN-001",
        )

        assert run.status.value == "completed"
        assert run.tool_name == "prefetch"
        assert run.exit_code == 0

    @pytest.mark.asyncio
    async def test_run_invalid_path(self, tmp_path):
        """Running on a non-.pf file should fail."""
        bad_file = tmp_path / "notaprefetch.txt"
        bad_file.write_text("not a pf file")
        output_dir = str(tmp_path / "output")

        tool = PrefetchTool()
        run = await tool.run(
            input_path=str(bad_file),
            output_dir=output_dir,
            case_id="test-case",
            run_number="RUN-002",
        )

        assert run.status.value == "failed"


class TestPrefetchNormalizerCompat:
    def test_normalizer_registered(self):
        n = get_normalizer("prefetch")
        assert n is not None
        assert n.tool_name == "prefetch"

    def test_normalize_row(self):
        n = PrefetchNormalizer()
        row = {
            "ExecutableName": "CMD.EXE",
            "RunCount": "12",
            "Hash": "BEEF1234",
            "LastRun": "2026-01-15 14:30:00",
            "SourceFilename": "/evidence/CMD.EXE-5678.pf",
            "PreviousRun0": "2026-01-14 10:00:00",
            "PreviousRun1": "",
            "PreviousRun2": "",
            "PreviousRun3": "",
            "PreviousRun4": "",
            "PreviousRun5": "",
            "PreviousRun6": "",
            "Volume0Name": "C:",
            "Volume0Serial": "1234",
            "Directories": "\\WINDOWS\\SYSTEM32",
            "FilesLoaded": "\\WINDOWS\\SYSTEM32\\CMD.EXE",
        }
        result = n.normalize_row(row)

        assert result["artifact_type"] == "windows.prefetch.execution"
        assert result["category"] == "program_execution"
        assert result["source_tool"] == "prefetch"
        assert "CMD.EXE" in result["description"]
        assert result["data"]["executable_name"] == "CMD.EXE"
        assert result["data"]["run_count"] == "12"
