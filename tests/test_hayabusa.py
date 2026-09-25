"""Tests for Hayabusa tool wrapper and normalizer."""

from __future__ import annotations

import csv
from pathlib import Path

from defair.normalizers.hayabusa import HayabusaNormalizer
from defair.tools.hayabusa import HayabusaTool


class TestHayabusaTool:
    def test_manifest(self):
        m = HayabusaTool.manifest()
        assert m.name == "hayabusa"
        assert m.category == "detection"
        assert m.runtime == "native"
        assert "sigma_detection" in m.capabilities
        assert "evtx" in m.input_types

    def test_build_command_defaults(self):
        tool = HayabusaTool()
        cmd = tool.build_command("/evidence/logs", "/output")
        assert cmd[0] == "hayabusa"
        assert "dfir-timeline" in cmd  # Hayabusa 4.x
        assert "-d" in cmd
        assert cmd[cmd.index("-d") + 1] == "/evidence/logs"
        assert "-p" in cmd
        assert cmd[cmd.index("-p") + 1] == "standard"
        assert "-q" in cmd

    def test_build_command_verbose_profile(self):
        tool = HayabusaTool()
        cmd = tool.build_command("/evidence", "/output", profile="verbose")
        assert cmd[cmd.index("-p") + 1] == "verbose"

    def test_build_command_invalid_profile_defaults(self):
        tool = HayabusaTool()
        cmd = tool.build_command("/evidence", "/output", profile="invalid")
        assert cmd[cmd.index("-p") + 1] == "standard"

    def test_build_command_custom_rules(self):
        tool = HayabusaTool()
        cmd = tool.build_command("/evidence", "/output", rules_dir="/custom/rules")
        assert "-r" in cmd
        assert cmd[cmd.index("-r") + 1] == "/custom/rules"

    def test_build_command_min_level(self):
        tool = HayabusaTool()
        cmd = tool.build_command("/evidence", "/output", min_level="high")
        assert "-m" in cmd
        assert cmd[cmd.index("-m") + 1] == "high"


class TestHayabusaNormalizer:
    def test_tool_name(self):
        n = HayabusaNormalizer()
        assert n.tool_name == "hayabusa"

    def test_normalize_critical_alert(self):
        row = {
            "Timestamp": "2023-03-27T14:37:09.000Z",
            "RuleTitle": "Suspicious PowerShell Execution",
            "Level": "critical",
            "Computer": "DESKTOP-01",
            "Channel": "Microsoft-Windows-PowerShell/Operational",
            "EventID": "4104",
            "RecordID": "12345",
            "Details": "Invoke-Mimikatz",
            "MitreTactics": "Execution",
            "MitreTags": "T1059.001",
            "RuleFile": "sigma/proc_creation/mimikatz.yml",
            "EvtxFile": "PowerShell.evtx",
        }
        n = HayabusaNormalizer()
        result = n.normalize_row(row)

        assert result is not None
        assert result["artifact_type"] == "windows.hayabusa.alert"
        assert result["severity"] == "critical"
        assert result["hostname"] == "DESKTOP-01"
        assert result["description"] == "Suspicious PowerShell Execution"
        assert result["data"]["mitre_tactics"] == "Execution"
        assert result["data"]["mitre_tags"] == "T1059.001"

    def test_normalize_low_detection(self):
        row = {
            "Timestamp": "2023-03-27T14:00:00.000Z",
            "RuleTitle": "User Logon",
            "Level": "low",
            "Computer": "DESKTOP-01",
            "Channel": "Security",
            "EventID": "4624",
        }
        n = HayabusaNormalizer()
        result = n.normalize_row(row)

        assert result is not None
        assert result["artifact_type"] == "windows.hayabusa.detection"
        assert result["severity"] == "low"

    def test_normalize_empty_level_skipped(self):
        row = {"Timestamp": "2023-01-01", "Level": "", "RuleTitle": "test"}
        n = HayabusaNormalizer()
        result = n.normalize_row(row)
        assert result is None

    def test_normalize_file(self, tmp_path: Path):
        """Test normalizing a CSV file."""
        csv_file = tmp_path / "hayabusa_results.csv"
        with csv_file.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "Timestamp", "RuleTitle", "Level", "Computer",
                "Channel", "EventID", "MitreTactics", "MitreTags",
                "RuleFile", "EvtxFile",
            ])
            writer.writeheader()
            writer.writerow({
                "Timestamp": "2023-03-27T14:37:09.000Z",
                "RuleTitle": "Alert 1",
                "Level": "high",
                "Computer": "SRV01",
                "Channel": "Security",
                "EventID": "4688",
                "MitreTactics": "Execution",
                "MitreTags": "T1059",
                "RuleFile": "rule1.yml",
                "EvtxFile": "Security.evtx",
            })
            writer.writerow({
                "Timestamp": "2023-03-27T15:00:00.000Z",
                "RuleTitle": "Detection 1",
                "Level": "informational",
                "Computer": "SRV01",
                "Channel": "System",
                "EventID": "7045",
                "MitreTactics": "",
                "MitreTags": "",
                "RuleFile": "rule2.yml",
                "EvtxFile": "System.evtx",
            })

        n = HayabusaNormalizer()
        artifacts = n.normalize_file(str(csv_file))

        assert len(artifacts) == 2
        assert artifacts[0]["artifact_type"] == "windows.hayabusa.alert"
        assert artifacts[0]["severity"] == "high"
        assert artifacts[1]["artifact_type"] == "windows.hayabusa.detection"
        assert artifacts[1]["severity"] == "informational"


class TestHayabusa4:
    def test_runs_from_its_directory(self):
        from defair.tools.hayabusa import HayabusaTool

        assert HayabusaTool.manifest().cwd == "/opt/hayabusa"

    def test_command_flags(self):
        from defair.tools.hayabusa import HayabusaTool

        cmd = HayabusaTool().build_command("/evidence/logs", "/out")
        for flag in ("-w", "-C", "-K", "-q", "-Q"):
            assert flag in cmd

    def test_abbreviated_levels(self):
        from defair.normalizers.hayabusa import HayabusaNormalizer

        n = HayabusaNormalizer()
        crit = n.normalize_row({"Level": "crit", "RuleTitle": "x", "Timestamp": "2023-03-24 22:02:43.512 +01:00"})
        med = n.normalize_row({"Level": "med", "RuleTitle": "y"})
        assert crit["severity"] == "critical" and crit["artifact_type"] == "windows.hayabusa.alert"
        assert med["severity"] == "medium"
