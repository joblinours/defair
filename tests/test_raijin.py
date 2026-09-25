"""Tests for the Raijin tool wrapper and its normalizer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from defair.normalizers.eztools import get_normalizer
from defair.normalizers.raijin import RaijinNormalizer, score_to_severity
from defair.tools.raijin import RaijinTool
from defair.tools.registry import get_default_registry

FIXTURE = Path(__file__).parent / "fixtures" / "raijin_sample.jsonl"


@pytest.fixture
def store(tmp_path):
    """A minimal rule store index matching the fixture's rules."""
    store = tmp_path / "store"
    store.mkdir()
    (store / "INDEX.json").write_text(json.dumps({
        "yara": {"yaraforge_full": {"BINARYALERT_Eicar_Av_Test": "yara-rules-full.yar"}},
        "sigma": {},
    }))
    return store


class TestRaijinTool:
    def test_registered(self):
        assert isinstance(get_default_registry().get("raijin"), RaijinTool)
        assert get_default_registry().get("yara") is None

    def test_manifest(self):
        m = RaijinTool.manifest()
        assert 2 in m.success_exit_codes
        assert "profile" in m.allowed_options

    @pytest.mark.parametrize("mode, flag, absent", [
        ("yara", "--no-sigma", "--no-fs"),
        ("sigma", "--no-fs", "--no-sigma"),
        ("all", None, "--no-sigma"),
    ])
    def test_build_command(self, mode, flag, absent):
        cmd = RaijinTool().build_command(
            "/evidence", "/workspace/analysis/raijin/RUN-001",
            signatures="/sig", mode=mode,
        )
        assert cmd[0] == "raijin"
        for required in ("--lab", "--no-procs", "--no-tui", "--scan-all-files"):
            assert required in cmd
        # These make Raijin scan every host drive and ignore --folder
        assert "--scan-all-drives" not in cmd and "--scan-hard-drives" not in cmd
        assert cmd[cmd.index("--signatures") + 1] == "/sig"
        assert cmd[cmd.index("--jsonl") + 1].endswith("RUN-001/raijin.jsonl")
        if flag:
            assert flag in cmd
        assert absent not in cmd

    def test_build_command_executables_only(self):
        cmd = RaijinTool().build_command("/e", "/o", signatures="/s", all_files=False)
        assert "--scan-all-files" not in cmd

    def test_build_command_bad_mode(self):
        with pytest.raises(ValueError):
            RaijinTool().build_command("/e", "/o", signatures="/s", mode="rm")

    @pytest.mark.asyncio
    async def test_run_refuses_tampered_store(self, tmp_path):
        from defair.rules.lock import RuleIntegrityError

        empty_store = tmp_path / "store"
        empty_store.mkdir()
        with pytest.raises(RuleIntegrityError, match="scan refused"):
            await RaijinTool().run(
                "/evidence", str(tmp_path / "out" / "RUN-001"), "case",
                profile="precise", rules_store=str(empty_store),
            )


class TestRaijinNormalizer:
    def test_registered(self):
        assert isinstance(get_normalizer("raijin"), RaijinNormalizer)

    def test_normalize_fixture(self, store):
        artifacts = RaijinNormalizer(store).normalize_file(FIXTURE, case_id="c", run_id="r")
        types = {a["artifact_type"] for a in artifacts}
        assert types == {"detection.sigma.match", "detection.yara.match"}
        assert all(a["case_id"] == "c" and a["source_tool"] == "raijin" for a in artifacts)

    def test_sigma_provenance(self, store):
        artifacts = RaijinNormalizer(store).normalize_file(FIXTURE)
        lsass = next(a for a in artifacts if a["data"]["rule_name"] == "LSASS dump via process access")
        rule = lsass["data"]["rule"]
        assert rule["source"] == "mdecrevoisier"
        assert rule["file"] == "windows-lsass/win-os-LSASS credential dump via process access.yaml"
        assert rule["ref"] and rule["license"] == "CC0-1.0"
        assert len(rule["file_sha256"]) == 64  # resolved from the packaged manifest
        assert lsass["hostname"] == "PC04.example.corp"
        assert lsass["timestamp"].startswith("2019-03-17T19:37:16")
        assert lsass["severity"] == "high"
        assert "T1003.001" in lsass["data"]["mitre_techniques"]

    def test_yara_provenance(self, store):
        artifacts = RaijinNormalizer(store).normalize_file(FIXTURE)
        eicar = next(a for a in artifacts if a["data"]["rule_name"] == "BINARYALERT_Eicar_Av_Test")
        assert eicar["category"] == "malware"
        assert eicar["timestamp"] is None
        assert eicar["data"]["rule"]["source"] == "yaraforge_full"
        assert eicar["data"]["rule"]["file"] == "yara-rules-full.yar"
        assert eicar["data"]["sha256"].startswith("275a021bbfb6")

    def test_cross_namespace_duplicates_merged(self, store):
        event = {
            "event_type": "file_match", "file_path": "/evidence/x.exe", "score": 90,
            "reasons": [
                {"message": "m", "score": 80, "rule": {"engine": "yara", "name": "Dup",
                                                       "namespace": "00_yaraforge_full"}},
                {"message": "m", "score": 80, "rule": {"engine": "yara", "name": "Dup",
                                                       "namespace": "05_neo23x0"}},
            ],
        }
        artifacts = RaijinNormalizer(store).normalize_event(event)
        assert len(artifacts) == 1
        assert artifacts[0]["data"]["rule"]["also_in"][0]["source"] == "neo23x0"

    def test_non_match_events_ignored(self, store):
        assert RaijinNormalizer(store).normalize_event({"event_type": "info", "message": "x"}) == []

    @pytest.mark.parametrize("score, severity", [
        (95, "critical"), (80, "high"), (65, "medium"), (45, "low"), (10, "informational"),
    ])
    def test_score_to_severity(self, score, severity):
        assert score_to_severity(score) == severity
