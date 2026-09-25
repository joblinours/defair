"""v0.4.5 part 4 — host profile, strings extraction, watchlists."""

from __future__ import annotations

import io
import json
import shutil
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from defair.normalizers.eztools import get_normalizer
from defair.tools import strings_native


async def _case_with_run(conn, tmp_path, artifacts: list[dict]):
    """A case, an evidence folder and one tool run normalized through the pipeline."""
    from defair.normalizers.pipeline import normalize_run
    from defair.services import case_service, evidence_service

    case = await case_service.create_case(conn, "hostcase")
    collection = tmp_path / "collection"
    collection.mkdir(exist_ok=True)
    (collection / "notes.txt").write_text("user ran AnyDesk.exe from downloads\n")
    (collection / "blob.bin").write_bytes(b"\x00\x01" + "rclone copy".encode("utf-16-le") + b"\x00")
    evidence = await evidence_service.add_evidence(conn, case.id, collection)
    run_dir = tmp_path / "ws" / "analysis" / "fake" / "RUN-001"
    run_dir.mkdir(parents=True)
    (run_dir / "rows.jsonl").write_text("\n".join(json.dumps(a) for a in artifacts) + "\n")
    await conn.execute(
        "INSERT INTO tool_runs (id, run_number, case_id, tool_name, status, created_at) "
        "VALUES ('run1', 'RUN-001', ?, 'fake', 'completed', '2024-01-01')", (case.id,))

    class Passthrough(get_normalizer("psreadline_native").__class__):
        @property
        def tool_name(self):
            return "fake"

        def normalize_row(self, row, **ctx):
            return {**row, **ctx}

    await normalize_run(conn, {"id": "run1", "run_number": "RUN-001", "case_id": case.id,
                               "evidence_id": evidence.id, "tool_name": "fake",
                               "output_path": str(run_dir)}, Passthrough())
    return case, evidence


ARTIFACTS = [
    {"artifact_type": "windows.registry.timezone", "category": "system_info", "source_tool": "recmd",
     "description": "TimeZoneKeyName", "data": {"value_data": "Central Standard Time"}},
    {"artifact_type": "windows.registry.usb_device", "category": "external_device", "source_tool": "recmd",
     "timestamp": "2024-05-01T10:00:00Z", "description": "SanDisk Cruzer"},
    {"artifact_type": "windows.evtx.logon", "category": "account_usage", "source_tool": "evtxecmd",
     "timestamp": "2024-05-01T10:00:00Z", "hostname": "WS01.corp.local", "description": "logon"},
    {"artifact_type": "windows.powershell.history", "category": "program_execution",
     "source_tool": "psreadline_native", "description": "PS> .\\mimikatz.exe sekurlsa::logonpasswords"},
]


class TestHostProfile:
    @pytest.mark.asyncio
    async def test_sources_and_conflicts(self, db_conn, tmp_path):
        from defair.services import host_profile_service

        case, evidence = await _case_with_run(db_conn, tmp_path, ARTIFACTS)
        prepared = {"kind": "kape", "base": str(tmp_path), "root": str(tmp_path / "C"),
                    "host": {"hostname": "WS01", "os": "windows", "version": "Windows 10 Pro"}}
        await db_conn.execute("UPDATE evidence SET prepared = ? WHERE id = ?",
                              (json.dumps(prepared), evidence.id))
        await db_conn.commit()
        live = {"hostname": "OTHER-NAME", "timezone": "America/Chicago", "users": ["bob"],
                "applications": [{"name": "7-Zip"}]}
        with patch.object(host_profile_service, "dissect_host", return_value=live):
            profile = await host_profile_service.build_host_profile(db_conn, case.id)
        fields = profile["fields"]
        assert fields["hostname"]["value"] == "WS01"
        assert fields["hostname"]["source"] == "dissect:hostname (prepare)"
        assert "evtx" in fields["hostname"]["also"]  # WS01.corp.local → WS01
        assert profile["conflicts"][0]["value"] == "OTHER-NAME"  # listed, not overwritten
        assert fields["timezone"]["value"] == "America/Chicago"
        assert fields["timezone_registry"]["value"] == "Central Standard Time"
        assert fields["timezone_registry"]["source"].startswith("ART-")
        assert fields["usb_devices"]["value"][0]["device"] == "SanDisk Cruzer"
        assert fields["applications"]["value"] == [{"name": "7-Zip"}]
        assert profile["evtx_computers"][0]["computer"] == "WS01.corp.local"
        first = profile["artifact"]

        # stored once per evidence; rebuilding keeps the number
        with patch.object(host_profile_service, "dissect_host", return_value={}):
            again = await host_profile_service.build_host_profile(db_conn, case.id, evidence.evidence_number)
        assert again["artifact"] == first
        stored = await host_profile_service.get_host_profile(db_conn, case.id)
        assert stored["artifact"] == first and stored["fields"]["hostname"]["value"] == "WS01"
        cursor = await db_conn.execute(
            "SELECT COUNT(*) FROM artifacts WHERE artifact_type = 'windows.system.host_profile'")
        assert (await cursor.fetchone())[0] == 1


class TestStrings:
    def test_boundaries_and_encodings(self, monkeypatch):
        monkeypatch.setattr(strings_native, "CHUNK", 64)
        monkeypatch.setattr(strings_native, "KEEP", 16)
        data = b"\x00" * 50 + b"http://evil.example/x.exe" + b"\x01" * 20 + \
            "C:\\Temp\\mimi.exe".encode("utf-16-le") + b"\x02\x02" + b"ab\x00cd"
        found = list(strings_native.extract_strings(io.BytesIO(data), 6))
        assert (50, "ascii", "http://evil.example/x.exe") in found
        assert any(e == "utf-16le" and t == "C:\\Temp\\mimi.exe" for _, e, t in found)
        assert not any(t in ("ab", "cd") for _, _, t in found)
        assert len({(o, e) for o, e, _ in found}) == len(found)

    @pytest.mark.asyncio
    async def test_tool_on_collection(self, tmp_path):
        folder = tmp_path / "C"
        folder.mkdir()
        (folder / "pagefile.sys").write_bytes(b"\x00" * 10 + b"password=Winter2024!" + b"\x00" * 10)
        (folder / "hiberfil.sys").write_bytes(b"HIBR" + b"\x00" * 100)
        (folder / "other.bin").write_bytes(b"not extracted" * 3)
        tool = strings_native.StringsNativeTool()
        run = await tool.run(str(tmp_path), str(tmp_path / "out"), case_id="c")
        assert run.status == "completed"
        tsv = (tmp_path / "out" / "pagefile.sys.tsv").read_text()
        assert tsv == "10\tascii\tpassword=Winter2024!\n"
        normalizer = get_normalizer("strings_native")
        arts = normalizer.normalize_directory(tmp_path / "out")
        assert len(arts) == 1 and arts[0]["data"]["strings"] == 1 and arts[0]["data"]["sha256"]
        assert "hiberfil.sys" in next(iter(normalizer.stats["skip_reasons"]))
        assert not (tmp_path / "out" / "other.bin.tsv").exists()

    def test_non_image_file_is_not_extracted_whole(self, tmp_path):
        pytest.importorskip("dissect.target")
        raw = tmp_path / "disk.raw"
        raw.write_bytes(b"\x00" * 4096)
        # opened as a (raw) disk image: only its pagefile / swapfile would be read
        assert list(strings_native._sources(raw, strings_native.DEFAULT_SOURCES)) == []
        assert [n for n, _, _ in strings_native._sources(raw, strings_native.DEFAULT_SOURCES, True)] == ["disk.raw"]


@pytest.fixture(params=["rg", "python"])
def matcher(request, monkeypatch):
    from defair.services import watchlist_service

    if request.param == "rg":
        if not shutil.which("rg"):
            pytest.skip("ripgrep not installed")
    else:
        monkeypatch.setattr(watchlist_service.shutil, "which", lambda name: None)
    return request.param


class TestWatchlists:
    def test_builtin_lists(self):
        from defair.services.watchlist_service import get_watchlist, list_watchlists

        names = {w.name for w in list_watchlists(Path("/nonexistent"))}
        assert {"offensive_tools", "lolbins", "rmm", "exfiltration"} <= names
        assert any(t.pattern == "mimikatz" for t in get_watchlist("offensive_tools", Path("/x")).terms)

    def test_case_list_overrides(self, tmp_path):
        from defair.services.watchlist_service import get_watchlist

        (tmp_path / "mine.yaml").write_text("name: rmm\nseverity: low\nterms: [mycorp-rmm]\n")
        wl = get_watchlist("rmm", tmp_path)
        assert wl.severity == "low" and [t.pattern for t in wl.terms] == ["mycorp-rmm"]

    @pytest.mark.asyncio
    async def test_search_all_scopes(self, db_conn, tmp_path, monkeypatch, matcher):
        from defair.services import watchlist_service

        monkeypatch.setenv("DEFAIR_WORKSPACE", str(tmp_path / "ws"))
        case, _ = await _case_with_run(db_conn, tmp_path, ARTIFACTS)
        # a strings index for the case
        tsv = tmp_path / "pagefile.sys.tsv"
        tsv.write_text("123\tascii\thttps://transfer.sh/abc/loot.7z\n456\tutf-16le\tnothing\n")
        from defair.services.analysis_service import _save_artifact

        await _save_artifact(db_conn, {"case_id": case.id, "artifact_type": "windows.strings.extract",
                                       "source_tool": "strings_native", "data": {"tsv": str(tsv)}})
        custom = tmp_path / "custom"
        custom.mkdir()
        report = await watchlist_service.search_watchlist(
            db_conn, case.id, watchlists=["offensive_tools", "rmm", "exfiltration"],
            terms=["WS01"], create_findings=True, extra_dir=custom)
        by_term = {(w["name"], e["term"]): e for w in report["watchlists"] for e in w["terms_hit"]}

        mimikatz = by_term[("offensive_tools", "mimikatz")]
        assert mimikatz["hits"]["artifacts"] == 1
        assert mimikatz["first_hits"][0]["artifact"].startswith("ART-")
        assert by_term[("offensive_tools", "sekurlsa::")]["hits"]["artifacts"] == 1
        assert by_term[("exfiltration", r"transfer\.sh|file\.io|gofile\.io|temp\.sh|anonfiles")]["hits"]["strings"] == 1
        strings_hit = by_term[("exfiltration", r"transfer\.sh|file\.io|gofile\.io|temp\.sh|anonfiles")]["first_hits"][0]
        assert strings_hit["offset"] == 123
        assert by_term[("rmm", "anydesk")]["hits"]["evidence"] == 1  # raw collection file
        assert by_term[("exfiltration", "rclone")]["hits"]["evidence"] == 1  # UTF-16 in a binary
        assert by_term[("adhoc", "WS01")]["hits"]["artifacts"] == 1
        assert report["findings"] and report["report_path"]
        assert Path(report["report_path"]).is_file()
        cursor = await db_conn.execute(
            "SELECT source, artifact_ids FROM findings WHERE title LIKE '%mimikatz%'")
        source, ids = await cursor.fetchone()
        assert source == "watchlist" and json.loads(ids)

    @pytest.mark.asyncio
    async def test_unknown_scope(self, db_conn, tmp_path):
        from defair.services import case_service, watchlist_service

        case = await case_service.create_case(db_conn, "x")
        with pytest.raises(ValueError, match="scope"):
            await watchlist_service.search_watchlist(db_conn, case.id, terms=["a"], scopes=["nope"])


class TestInterfaces:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool, args, expected", [
        ("get_host_profile", {"case_id": "C", "refresh": True},
         ["host", "profile", "--case", "C", "--json", "--refresh"]),
        ("list_watchlists", {}, ["watchlist", "list", "--json"]),
        ("search_watchlist", {"case_id": "C", "terms": ["1.2.3.4"], "scopes": ["artifacts"],
                              "create_findings": True},
         ["watchlist", "search", "--case", "C", "--json", "--term", "1.2.3.4", "--scope", "artifacts",
          "--findings"]),
    ])
    @patch("defair.mcp_server.server.container_service")
    async def test_mcp_proxies(self, mock_cs, tool, args, expected):
        from defair.mcp_server.server import mcp

        mock_cs.exec_in_container = AsyncMock(return_value={"exit_code": 0, "stdout": "{}", "stderr": ""})
        await mcp.call_tool(tool, {"container": "defair-case", **args})
        assert mock_cs.exec_in_container.call_args.args[1] == ["defair", *expected]

    @pytest.mark.asyncio
    async def test_host_profile_action(self):
        from defair.orchestrator.profile import Step
        from defair.orchestrator.steps import StepContext, run_step

        ctx = StepContext(conn=None, case_id="c", evidence_id="e", prepared={})
        profile = {"summary": {"hostname": "WS01"}, "artifact": "ART-009", "conflicts": []}
        with patch("defair.services.host_profile_service.build_host_profile",
                   AsyncMock(return_value=profile)):
            detail = await run_step(ctx, Step(id="host_profile", action="host_profile"))
        assert detail == {"host_profile": {"hostname": "WS01"}, "artifact_number": "ART-009",
                          "conflicts": 0}
