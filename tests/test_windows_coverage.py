"""v0.4.5 — Windows coverage: new EZ Tools, USN, SRUM, UAL, rla chaining."""

from __future__ import annotations

import shutil
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from defair.normalizers.eztools import get_normalizer
from defair.orchestrator.profile import Profile, Step
from defair.orchestrator.steps import StepContext, run_step
from defair.tools.registry import get_default_registry

FIXTURES = Path(__file__).parent / "fixtures"


def _write_csv(path: Path, header: list[str], rows: list[list[str]]) -> Path:
    import csv

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        writer.writerows(rows)
    return path


class TestUsn:
    def test_mftecmd_j_output_is_usn(self, tmp_path):
        shutil.copy(FIXTURES / "mftecmd_$J_Output.csv", tmp_path)
        arts = get_normalizer("mftecmd").normalize_directory(tmp_path)
        assert [a["artifact_type"] for a in arts] == ["windows.usn.journal_entry"] * 2
        assert arts[0]["timestamp"] == "2019-04-17 18:40:00.0000000" or arts[0]["timestamp"]
        assert arts[1]["category"] == "deleted_file"
        assert arts[1]["data"]["update_reasons"] == "FileDelete|Close"
        assert arts[0]["record_key"] == "usn#4096"
        assert arts[0]["timestamp_desc"] == "USN Record Updated"

    def test_mftecmd_mft_rows_unchanged(self):
        art = get_normalizer("mftecmd").normalize_row({"FileName": "a.txt", "Created0x10": ""})
        assert art["artifact_type"] == "windows.mft.file_entry"

    def test_mft_path_only_for_j(self):
        tool = get_default_registry().get("mftecmd")
        j = tool.build_command("/evidence/C/$Extend/$J", "/out", mft_path="/evidence/C/$MFT")
        assert j[-2:] == ["-m", "/evidence/C/$MFT"]
        mft = tool.build_command("/evidence/C/$MFT", "/out", mft_path="/evidence/C/$MFT")
        assert "-m" not in mft

    def test_bodyfile_drive_letter(self):
        cmd = get_default_registry().get("mftecmd").build_command("/e/$MFT", "/o", body_file=True)
        assert cmd[cmd.index("--bdl") + 1] == "C"

    def test_dissect_usn_same_type(self):
        from defair.normalizers.dissect import DissectNormalizer

        art = DissectNormalizer().normalize_row(
            {"_recorddescriptor": ["filesystem/ntfs/usnjrnl"], "path": "x", "ts": "2020-01-01"})
        assert art["artifact_type"] == "windows.usn.journal_entry"


class TestSrum:
    @pytest.mark.parametrize("name, expected", [
        ("20260101_SrumECmd_NetworkUsages_Output.csv", "windows.srum.network_usage"),
        ("20260101_SrumECmd_AppResourceUseInfo_Output.csv", "windows.srum.app_resource_usage"),
        ("20260101_SrumECmd_NetworkConnections_Output.csv", "windows.srum.network_connectivity"),
        ("20260101_SrumECmd_EnergyUsage_Output.csv", "windows.srum.energy_usage"),
        ("20260101_SrumECmd_PushNotifications_Output.csv", "windows.srum.push_notification"),
        ("20260101_SrumECmd_Unknown_Output.csv", "windows.srum.generic"),
    ])
    def test_type_by_table(self, tmp_path, name, expected):
        _write_csv(tmp_path / name, ["Timestamp", "ExeInfo", "BytesSent"],
                   [["2024-01-02 03:04:05", "\\device\\evil.exe", "12"]])
        arts = get_normalizer("srumecmd").normalize_directory(tmp_path)
        assert arts[0]["artifact_type"] == expected
        assert arts[0]["data"]["table"] == name


class TestNewEzTools:
    def test_registered_with_commands(self):
        registry = get_default_registry()
        assert registry.get("recentfilecacheparser").build_command("/e/RecentFileCache.bcf", "/o") == [
            "RecentFileCacheParser", "-f", "/e/RecentFileCache.bcf", "--csv", "/o", "-q"]
        assert registry.get("sumecmd").build_command("/e/Sum", "/o")[:5] == [
            "SumECmd", "-d", "/e/Sum", "--csv", "/o"]
        assert registry.get("rla").build_command("/e/config", "/o") == [
            "rla", "-d", "/e/config", "--out", "/o", "--ca"]
        cmd = registry.get("bstrings").build_command("/e/pagefile.sys", "/o", regex="ipv4", min_length=6)
        assert cmd[:3] == ["bstrings", "-f", "/e/pagefile.sys"]
        assert ["--lr", "ipv4"] == cmd[cmd.index("--lr"):cmd.index("--lr") + 2]
        assert "-m" in cmd and "--off" in cmd

    def test_bstrings_runs_with_tty_stdin(self):
        assert get_default_registry().get("bstrings").manifest().stdin_tty is True

    def test_pinned_names_match_archives(self):
        checksums = Path(__file__).parent.parent / "docker" / "checksums.sha256"
        archives = {line.split()[1].removesuffix(".zip").lower() for line in checksums.read_text().splitlines()}
        for name in ("recentfilecacheparser", "sumecmd", "bstrings", "rla"):
            assert name in archives

    def test_recentfilecache_normalizer(self, tmp_path):
        _write_csv(tmp_path / "x_RecentFileCacheParser_Output.csv",
                   ["SourceFile", "SourceCreated", "SourceModified", "SourceAccessed", "Filename"],
                   [["/e/RecentFileCache.bcf", "2012-01-01 00:00:00", "2012-02-01 00:00:00",
                     "2012-02-01 00:00:00", "c:\\users\\bob\\downloads\\evil.exe"]])
        art = get_normalizer("recentfilecacheparser").normalize_directory(tmp_path)[0]
        assert art["artifact_type"] == "windows.recentfilecache.entry"
        assert art["timestamp"] is None  # entries carry no time of their own
        assert art["data"]["cache_modified"]

    def test_sumecmd_normalizer(self, tmp_path):
        _write_csv(tmp_path / "x_SumECmd_DETAIL_Clients_Output.csv",
                   ["RoleGuid", "RoleDescription", "AuthenticatedUserName", "TotalAccesses",
                    "InsertDate", "LastAccess", "IpAddress", "ClientName", "TenantId", "SourceFile"],
                   [["10a9226f", "File Server", "corp\\admin", "42", "2024-01-01 10:00:00",
                     "2024-03-01 11:00:00", "10.0.0.5", "", "", "Current.mdb"]])
        _write_csv(tmp_path / "x_SumECmd_DETAIL_ClientsDetailed_Output.csv", ["RoleGuid"], [["a"]])
        _write_csv(tmp_path / "x_SumECmd_SUMMARY_RoleInfos_Output.csv", ["RoleGuid"], [["a"]])
        arts = get_normalizer("sumecmd").normalize_directory(tmp_path)
        assert len(arts) == 1
        art = arts[0]
        assert art["artifact_type"] == "windows.ual.client_access"
        assert art["username"] == "corp\\admin" and art["data"]["ip_address"] == "10.0.0.5"
        assert art["timestamp_desc"] == "Last Access"

    def test_bstrings_normalizer(self, tmp_path):
        (tmp_path / "bstrings.txt").write_text(
            "hello http://evil.example/x.exe\t0x2 (A)\n10.1.2.3\t0x5E (U)\n\nnooffset\n")
        n = get_normalizer("bstrings")
        n.input_path = "/e/pagefile.sys"
        arts = n.normalize_directory(tmp_path)
        assert [a["data"]["string"] for a in arts] == [
            "hello http://evil.example/x.exe", "10.1.2.3", "nooffset"]
        assert arts[0]["data"]["offset"] == 2 and arts[1]["data"]["encoding"] == "utf-16le"
        assert arts[0]["source_file"] == "/e/pagefile.sys"


class TestLocate:
    def test_new_selectors(self, tmp_path):
        from defair.sources.locate import locate_artifacts

        root = tmp_path / "C"
        (root / "Windows/AppCompat/Programs").mkdir(parents=True)
        (root / "Windows/AppCompat/Programs/RecentFileCache.bcf").write_bytes(b"\xfe\xff")
        (root / "Windows/System32/LogFiles/Sum").mkdir(parents=True)
        (root / "Windows/System32/LogFiles/Sum/Current.mdb").write_bytes(b"x")
        found = locate_artifacts(tmp_path, root)
        assert found["recentfilecache"][0].endswith("RecentFileCache.bcf")
        assert found["sum_dir"][0].endswith("Sum")


def _ctx(tmp_path, selectors):
    from unittest.mock import MagicMock

    registry = MagicMock()

    def get(name):
        tool = MagicMock()
        tool.is_available.return_value = True
        tool.manifest.return_value.allowed_options = ["directory"]
        return tool

    registry.get.side_effect = get
    prepared = {"kind": "kape", "base": str(tmp_path), "root": str(tmp_path / "C"),
                "target": str(tmp_path), "source": {"kind": "kape"}, "selectors": selectors}
    return StepContext(conn=None, case_id="case", evidence_id="ev", prepared=prepared,
                       output_base=str(tmp_path / "analysis"), registry=registry)


class TestStepInput:
    def test_profile_requires_need(self):
        with pytest.raises(ValueError, match="needs"):
            Profile(name="p", steps=[Step(id="a", tool="rla"),
                                     Step(id="b", tool="recmd", input="step:a")])

    @pytest.mark.asyncio
    async def test_reads_previous_step_output(self, tmp_path):
        replayed = tmp_path / "analysis" / "rla" / "RUN-001"
        replayed.mkdir(parents=True)
        (replayed / "SYSTEM").write_bytes(b"regf")
        ctx = _ctx(tmp_path, {"hives_dir": [str(tmp_path / "config")]})

        calls = []

        async def fake(conn, tool, target, case_id, **kwargs):
            calls.append((tool, target))
            out = str(replayed) if tool == "rla" else str(tmp_path / "analysis" / tool)
            return {"status": "completed", "run_number": "RUN-001", "output_path": out,
                    "artifacts_produced": 0}

        with patch("defair.services.analysis_service.run_tool_and_normalize", side_effect=fake):
            await run_step(ctx, Step(id="hives_replay", tool="rla", input="hives_dir"))
            detail = await run_step(ctx, Step(id="registry", tool="recmd", input="step:hives_replay",
                                              input_fallback="hives_dir", needs=["hives_replay"]))
        assert calls[-1] == ("recmd", str(replayed))
        assert "warning" not in detail

    @pytest.mark.asyncio
    async def test_falls_back_when_step_produced_nothing(self, tmp_path):
        ctx = _ctx(tmp_path, {"hives_dir": [str(tmp_path / "config")]})
        run = AsyncMock(return_value={"status": "completed", "run_number": "RUN-002",
                                      "output_path": str(tmp_path / "x"), "artifacts_produced": 1})
        with patch("defair.services.analysis_service.run_tool_and_normalize", run):
            detail = await run_step(ctx, Step(id="registry", tool="recmd", input="step:hives_replay",
                                              input_fallback="hives_dir", needs=["hives_replay"]))
        assert run.call_args.args[2] == str(tmp_path / "config")
        assert "hives_dir" in detail["warning"]


class TestMcp:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool, args, expected", [
        ("analyze_srum", {"input_path": "/e/SRUDB.dat", "case_id": "C", "registry_hive": "/e/SOFTWARE"},
         ["analyze", "srumecmd", "/e/SRUDB.dat", "--case", "C", "--option", "registry_hive=/e/SOFTWARE"]),
        ("analyze_usn", {"input_path": "/e/$J", "case_id": "C", "mft_path": "/e/$MFT"},
         ["analyze", "mftecmd", "/e/$J", "--case", "C", "--option", "mft_path=/e/$MFT"]),
        ("analyze_ual", {"input_path": "/e/Sum", "case_id": "C"},
         ["analyze", "sumecmd", "/e/Sum", "--case", "C"]),
    ])
    @patch("defair.mcp_server.server.container_service")
    async def test_proxies(self, mock_cs, tool, args, expected):
        from defair.mcp_server.server import mcp

        mock_cs.exec_in_container = AsyncMock(return_value={"exit_code": 0, "stdout": "{}", "stderr": ""})
        await mcp.call_tool(tool, {"container": "defair-case", **args})
        assert mock_cs.exec_in_container.call_args.args[1] == ["defair", *expected]
