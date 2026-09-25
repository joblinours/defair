"""Tests for the Dissect plugin tool and its normalizer (v0.4)."""

from __future__ import annotations

from pathlib import Path

from defair.models.tool_run import ToolRun, ToolRunStatus
from defair.normalizers.dissect import DissectNormalizer
from defair.normalizers.eztools import get_normalizer
from defair.tools.dissect_plugin import RECORDS_FILE, DissectPluginTool
from defair.tools.registry import get_default_registry

FIXTURE = Path(__file__).parent / "fixtures" / "dissect_mft_sample.jsonl"


class TestTool:
    def test_registered(self):
        assert isinstance(get_default_registry().get("dissect_plugin"), DissectPluginTool)
        assert DissectPluginTool.manifest().stdout_file == RECORDS_FILE

    def test_build_command(self):
        cmd = DissectPluginTool().build_command("/evidence/d.E01", "/o", plugin="evtx")
        assert cmd == ["target-query", "-f", "evtx", "-j", "/evidence/d.E01"]

    def test_unsupported_plugin_is_a_failure(self, tmp_path):
        run = ToolRun(run_number="RUN-1", case_id="c", tool_name="dissect_plugin",
                      status=ToolRunStatus.COMPLETED,
                      stderr="error: Unsupported plugin for evtx: Unsupported function `registry`")
        (tmp_path / RECORDS_FILE).write_text("")
        DissectPluginTool().check_result(run, tmp_path)
        assert run.status == ToolRunStatus.FAILED and "Unsupported plugin" in run.stderr

    def test_records_with_warnings_stay_completed(self, tmp_path):
        run = ToolRun(run_number="RUN-1", case_id="c", tool_name="dissect_plugin",
                      status=ToolRunStatus.COMPLETED, stderr="warning: Failed to map drive letters")
        (tmp_path / RECORDS_FILE).write_text('{"a": 1}\n')
        DissectPluginTool().check_result(run, tmp_path)
        assert run.status == ToolRunStatus.COMPLETED


class TestNormalizer:
    def test_registered(self):
        assert isinstance(get_normalizer("dissect_plugin"), DissectNormalizer)

    def test_mft_records(self):
        n = DissectNormalizer()
        artifacts = n.normalize_file(FIXTURE, case_id="c", run_id="r")
        mft = [a for a in artifacts if a["artifact_type"] == "windows.mft.file_entry"]
        assert len(mft) == 3
        assert mft[0]["timestamp_desc"].endswith("(MFT)")
        assert mft[0]["description"] == "c:\\$MFT"
        assert mft[0]["data"]["record_type"] == "filesystem/ntfs/mft/std"
        assert n.stats["rows_read"] == 4  # descriptor lines are not records

    def test_evtx_record_uses_catalog(self):
        artifacts = DissectNormalizer().normalize_file(FIXTURE)
        logon = next(a for a in artifacts if a["data"]["record_type"] == "filesystem/windows/evtx")
        assert logon["artifact_type"] == "windows.evtx.logon"
        assert logon["category"] == "account_usage"
        assert logon["hostname"] == "DC01"
        assert "mitre:T1078" in logon["tags"]
        assert logon["timestamp"] == "2024-05-21T03:30:12.123456+00:00"

    def test_record_keys_unique(self):
        artifacts = DissectNormalizer().normalize_file(FIXTURE)
        keys = [a["record_key"] for a in artifacts]
        assert len(keys) == len(set(keys))

    def test_unknown_record_type(self):
        art = DissectNormalizer().normalize_row({"_recorddescriptor": ["windows/something/new", 1],
                                                "ts": "2024-01-01T00:00:00Z", "path": "x"})
        assert art["artifact_type"] == "windows.dissect.windows.something.new"
        assert art["timestamp"] == "2024-01-01T00:00:00Z"
