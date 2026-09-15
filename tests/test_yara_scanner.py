"""Tests for the YARA scanner tool and normalizer."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from defair.normalizers.eztools import get_normalizer
from defair.normalizers.yara import YaraNormalizer
from defair.tools.registry import get_default_registry
from defair.tools.yara_scanner import YaraTool


class TestYaraToolManifest:
    def test_manifest_basics(self):
        m = YaraTool.manifest()
        assert m.name == "yara"
        assert m.runtime == "python"
        assert m.category == "detection"
        assert "yara" in m.capabilities
        assert "malware_detection" in m.capabilities

    def test_registered_in_registry(self):
        registry = get_default_registry()
        tool = registry.get("yara")
        assert tool is not None
        assert isinstance(tool, YaraTool)

    def test_is_available(self):
        tool = YaraTool()
        assert tool.is_available() is True

    def test_is_available_without_lib(self):
        tool = YaraTool()
        with (
            patch.dict("sys.modules", {"yara": None}),
            patch("builtins.__import__", side_effect=ImportError),
        ):
            assert tool.is_available() is False


class TestYaraToolScanning:
    def test_collect_rule_files(self, tmp_path):
        """Should find .yar and .yara files recursively."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "test1.yar").write_text("rule test1 { condition: true }")
        (rules_dir / "test2.yara").write_text("rule test2 { condition: true }")
        (rules_dir / "subdir").mkdir()
        (rules_dir / "subdir" / "test3.yar").write_text("rule test3 { condition: true }")
        (rules_dir / "readme.txt").write_text("not a rule")

        files = YaraTool._collect_rule_files([str(rules_dir)])
        assert len(files) == 3
        extensions = {f.suffix for f in files}
        assert extensions == {".yar", ".yara"}

    def test_collect_rule_files_nonexistent(self):
        """Non-existent directories should be silently skipped."""
        files = YaraTool._collect_rule_files(["/nonexistent/path"])
        assert files == []

    def test_scan_files_no_rules(self, tmp_path):
        """Should return empty list when no rules are available."""
        target = tmp_path / "target"
        target.mkdir()
        (target / "file.txt").write_text("test content")

        tool = YaraTool()
        matches = tool._scan_files(str(target), [str(tmp_path / "no_rules")])
        assert matches == []

    def test_scan_files_with_match(self, tmp_path):
        """Should detect matches with a simple YARA rule."""
        import yara  # noqa: F401

        # Create a rule
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "test.yar").write_text(
            'rule detect_test_string {\n'
            '  meta:\n'
            '    severity = "high"\n'
            '    description = "Detects test marker"\n'
            '    author = "DEFAIR Test"\n'
            '  strings:\n'
            '    $marker = "MALWARE_MARKER_12345"\n'
            '  condition:\n'
            '    $marker\n'
            '}'
        )

        # Create target files
        target = tmp_path / "evidence"
        target.mkdir()
        (target / "clean.txt").write_text("nothing here")
        (target / "suspicious.bin").write_bytes(b"header MALWARE_MARKER_12345 footer")

        tool = YaraTool()
        matches = tool._scan_files(str(target), [str(rules_dir)])

        assert len(matches) == 1
        assert matches[0]["RuleName"] == "detect_test_string"
        assert matches[0]["FileName"] == "suspicious.bin"
        assert matches[0]["Severity"] == "high"
        assert matches[0]["Author"] == "DEFAIR Test"

    def test_scan_single_file(self, tmp_path):
        """Should work on a single file, not just directories."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "test.yar").write_text(
            'rule detect_abc {\n'
            '  strings:\n'
            '    $abc = "ABC"\n'
            '  condition:\n'
            '    $abc\n'
            '}'
        )

        target_file = tmp_path / "target.bin"
        target_file.write_bytes(b"ABC123")

        tool = YaraTool()
        matches = tool._scan_files(str(target_file), [str(rules_dir)])
        assert len(matches) == 1

    def test_scan_skips_large_files(self, tmp_path):
        """Should skip files exceeding max_file_size."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "test.yar").write_text(
            'rule always { condition: true }'
        )

        target = tmp_path / "evidence"
        target.mkdir()
        (target / "large.bin").write_bytes(b"x" * 1000)

        tool = YaraTool()
        # Set max size to 500 bytes
        matches = tool._scan_files(str(target), [str(rules_dir)], max_file_size=500)
        assert len(matches) == 0

    def test_match_to_dict(self):
        """Test conversion of YARA match to dict."""
        mock_match = MagicMock()
        mock_match.rule = "TestRule"
        mock_match.namespace = "test_ns"
        mock_match.tags = ["malware", "ransomware"]
        mock_match.meta = {
            "severity": "critical",
            "description": "Test rule",
            "author": "Tester",
            "reference": "https://example.com",
        }

        mock_string = MagicMock()
        mock_string.identifier = "$test"
        mock_instance = MagicMock()
        mock_instance.offset = 0x100
        mock_string.instances = [mock_instance]
        mock_match.strings = [mock_string]

        result = YaraTool._match_to_dict(mock_match, Path("/evidence/file.exe"))

        assert result["RuleName"] == "TestRule"
        assert result["Namespace"] == "test_ns"
        assert "malware" in result["Tags"]
        assert result["Severity"] == "critical"
        assert result["Author"] == "Tester"
        assert "$test@0x100" in result["MatchedStrings"]


class TestYaraToolRun:
    @pytest.mark.asyncio
    async def test_run_with_rules(self, tmp_path):
        """Full run with a rule file and a target directory."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "test.yar").write_text(
            'rule find_marker {\n'
            '  strings:\n'
            '    $m = "FIND_ME"\n'
            '  condition:\n'
            '    $m\n'
            '}'
        )

        evidence = tmp_path / "evidence"
        evidence.mkdir()
        (evidence / "clean.txt").write_text("nothing")
        (evidence / "marked.bin").write_bytes(b"data FIND_ME data")

        output = str(tmp_path / "output")

        tool = YaraTool()
        run = await tool.run(
            input_path=str(evidence),
            output_dir=output,
            case_id="test-case",
            run_number="RUN-001",
            rules_dir=str(rules_dir),
        )

        assert run.status.value == "completed"
        assert run.exit_code == 0
        assert "1 YARA match" in run.stdout

        # Verify CSV was written
        csv_path = Path(output) / "yara_results.csv"
        assert csv_path.exists()

    @pytest.mark.asyncio
    async def test_run_no_rules(self, tmp_path):
        """Run completes successfully with 0 matches when no rules exist."""
        evidence = tmp_path / "evidence"
        evidence.mkdir()
        (evidence / "file.txt").write_text("test")

        output = str(tmp_path / "output")

        tool = YaraTool()
        run = await tool.run(
            input_path=str(evidence),
            output_dir=output,
            case_id="test-case",
            run_number="RUN-002",
        )

        assert run.status.value == "completed"
        assert "0 YARA match" in run.stdout


class TestYaraNormalizer:
    def test_normalizer_registered(self):
        n = get_normalizer("yara")
        assert n is not None
        assert n.tool_name == "yara"

    def test_normalize_row(self):
        n = YaraNormalizer()
        row = {
            "Timestamp": "2026-01-15T14:30:00Z",
            "FilePath": "/evidence/malware.exe",
            "FileName": "malware.exe",
            "RuleName": "RANSOM_WannaCry",
            "Namespace": "ransomware",
            "Tags": "malware, ransomware",
            "Severity": "critical",
            "Description": "Detects WannaCry ransomware",
            "Author": "Florian Roth",
            "Reference": "https://example.com",
            "MatchedStrings": "$s1@0x100; $s2@0x200",
            "MatchCount": "2",
        }
        result = n.normalize_row(row)

        assert result["artifact_type"] == "detection.yara.match"
        assert result["category"] == "malware"
        assert result["source_tool"] == "yara"
        assert result["severity"] == "critical"
        assert result["data"]["rule_name"] == "RANSOM_WannaCry"
        assert "WannaCry" in result["description"]

    def test_severity_mapping(self):
        assert YaraNormalizer._map_severity("critical") == "critical"
        assert YaraNormalizer._map_severity("HIGH") == "high"
        assert YaraNormalizer._map_severity("info") == "informational"
        assert YaraNormalizer._map_severity("unknown") == "medium"
