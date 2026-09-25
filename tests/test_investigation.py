"""Tests for case names, finding match details, artifact inspection and logging."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from defair.services import artifact_service, case_service, finding_service
from defair.services.artifact_service import (
    explain_match,
    hex_dump,
    resolve_evidence_path,
    scan_root,
)

FIXTURE = Path(__file__).parent / "fixtures" / "raijin_sample.jsonl"


# ---------------------------------------------------------------------------
# 1. Cases by name
# ---------------------------------------------------------------------------


class TestCaseByName:
    @pytest.mark.asyncio
    async def test_resolve_by_name_number_and_id(self, db_conn):
        case = await case_service.create_case(db_conn, "test_case_img")
        assert await case_service.resolve_case_id(db_conn, "test_case_img") == case.id
        assert await case_service.resolve_case_id(db_conn, "TEST_CASE_IMG") == case.id
        assert await case_service.resolve_case_id(db_conn, case.case_number.lower()) == case.id
        assert await case_service.resolve_case_id(db_conn, case.id) == case.id
        assert (await case_service.get_case(db_conn, "test_case_img")).id == case.id

    @pytest.mark.asyncio
    async def test_ambiguous_name(self, db_conn):
        await case_service.create_case(db_conn, "same")
        await case_service.create_case(db_conn, "same")
        with pytest.raises(ValueError, match="Several cases"):
            await case_service.resolve_case_id(db_conn, "same")

    @pytest.mark.asyncio
    async def test_unknown(self, db_conn):
        with pytest.raises(ValueError, match="Case not found"):
            await case_service.resolve_case_id(db_conn, "nope")

    @pytest.mark.asyncio
    async def test_evidence_add_by_case_name(self, db_conn, tmp_path):
        from defair.services import evidence_service

        case = await case_service.create_case(db_conn, "by-name")
        f = tmp_path / "x.bin"
        f.write_bytes(b"x")
        ev = await evidence_service.add_evidence(db_conn, "by-name", f)
        assert ev.case_id == case.id
        assert len(await evidence_service.list_evidence(db_conn, "by-name")) == 1


# ---------------------------------------------------------------------------
# 2. What matched
# ---------------------------------------------------------------------------


class TestExplainMatch:
    def test_sigma_event_and_fields(self, tmp_path):
        logs = tmp_path / "content" / "C" / "Windows" / "Logs"
        logs.mkdir(parents=True)
        (logs / "Sec.evtx").write_bytes(b"ElfFile\x00")
        art = {"source_tool": "raijin", "artifact_number": "ART-1", "data": {
            "engine": "sigma", "host_path": "/C/Windows/Logs/Sec.evtx",
            "rule": {"engine": "sigma", "name": "R", "source": "sigmahq_core", "file": "rules/r.yml"},
            "matched_strings": ["EventID=4688 Channel=Security RecordID=42 Computer=PC1 Level=high RuleID=x",
                                "CommandLine: whoami /all"],
        }}
        info = explain_match(art, str(tmp_path / "content"))
        assert info["evidence_path"] == str(logs / "Sec.evtx")
        assert info["event"]["RecordID"] == "42" and info["event"]["EventID"] == "4688"
        assert info["matched_fields"] == ["CommandLine: whoami /all"]
        assert info["rule_file"].endswith("sigma/sigmahq_core/rules/r.yml")

    def test_yara_patterns(self):
        art = {"source_tool": "raijin", "data": {
            "engine": "yara", "host_path": "/nope/eicar.com",
            "rule": {"engine": "yara", "name": "EICAR", "namespace": "00_yaraforge_full"},
            "matched_strings": ["$s1: 'X5O!P%@AP' @ 0", "$s2: 'EICAR-STANDARD' @ 33"],
        }}
        info = explain_match(art)
        assert info["matched_patterns"][1] == {"identifier": "$s2", "value": "'EICAR-STANDARD'", "offset": 33}

    def test_windows_path_in_kape_layout(self, tmp_path):
        target = tmp_path / "triage" / "C" / "Windows" / "x.evtx"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"x")
        assert resolve_evidence_path(str(tmp_path), "C:\\Windows\\x.evtx") == str(target)

    def test_scan_root_from_parameters_or_command(self):
        assert scan_root({"parameters": {"input_path": "/workspace/a b"}}) == "/workspace/a b"
        cmd = "raijin --lab --folder /workspace/sources/EVD-1/content --signatures /sig --jsonl x"
        assert scan_root({"parameters": {}, "command": cmd}) == "/workspace/sources/EVD-1/content"

    def test_hex_dump_marks_match(self, tmp_path):
        f = tmp_path / "bin"
        f.write_bytes(b"A" * 40 + b"EVIL" + b"B" * 40)
        lines = hex_dump(str(f), 40, length=4, around=8)
        joined = "\n".join(lines)
        assert "[45] [56] [49] [4c]" in joined
        assert lines[0].startswith("00000020")

    def test_raw_evtx_event_by_record(self, tmp_path):
        evtx = tmp_path / "Sec.evtx"
        evtx.write_bytes(b"ElfFile\x00")
        parser = MagicMock()
        parser.return_value.records_json.return_value = [
            {"event_record_id": 41, "timestamp": "t", "data": json.dumps({"Event": {"System": {"EventID": 1}}})},
            {"event_record_id": 42, "timestamp": "t2", "data": json.dumps(
                {"Event": {"System": {"EventID": 4688, "Channel": "Security"},
                           "EventData": {"CommandLine": "whoami"}}})},
        ]
        with patch.dict(sys.modules, {"evtx": MagicMock(PyEvtxParser=parser)}):
            raw = artifact_service.raw_source({"evidence_path": str(evtx), "event": {"RecordID": "42"}})
        assert raw["evtx_event"]["fields"]["CommandLine"] == "whoami"


@pytest.mark.asyncio
async def test_finding_detail_lists_matches(db_conn):
    from defair.normalizers.raijin import RaijinNormalizer
    from defair.services import scanning_service
    from defair.services.analysis_service import _save_artifact

    case = await case_service.create_case(db_conn, "detail")
    await db_conn.execute(
        "INSERT INTO tool_runs (id, run_number, case_id, tool_name, command, created_at) "
        "VALUES ('r1', 'RUN-001', ?, 'raijin', 'raijin --folder /evidence --signatures /s', 't')",
        (case.id,),
    )
    for art in RaijinNormalizer(Path("/nonexistent")).normalize_file(FIXTURE, case_id=case.id, run_id="r1"):
        await _save_artifact(db_conn, art)
    await scanning_service.auto_create_findings(db_conn, case.id, "r1", min_severity="informational")

    listed = await finding_service.list_findings(db_conn, case.id)
    lsass = next(f for f in listed if "LSASS" in f["title"])
    detail = await finding_service.get_finding_detail(db_conn, lsass["finding_number"].lower(),
                                                      case_id="detail")
    match = detail["matches"][0]
    assert match["artifact"].startswith("ART-")
    assert match["event"]["EventID"] == "10"
    assert any("lsass.exe" in f.lower() for f in match["matched_fields"])
    assert detail["detection_refs"][0]["rule_path"].endswith(".yaml")
    with pytest.raises(ValueError, match="does not belong"):
        other = await case_service.create_case(db_conn, "other")
        await finding_service.get_finding_detail(db_conn, lsass["finding_number"], case_id=other.id)


# ---------------------------------------------------------------------------
# 4. Artifact search / deep inspection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_and_get_artifact(db_conn):
    from defair.services.analysis_service import _save_artifact

    case = await case_service.create_case(db_conn, "arts")
    for i, (ts, desc, tool) in enumerate([
        ("2024-01-01T10:00:00Z", "powershell.exe -enc AAA", "evtxecmd"),
        ("2024-01-01T10:03:00Z", "cmd.exe /c whoami", "evtxecmd"),
        ("2024-01-01T12:00:00Z", "notepad.exe", "prefetch"),
    ]):
        await _save_artifact(db_conn, {"case_id": case.id, "artifact_type": "windows.evtx.process_creation",
                                       "timestamp": ts, "description": desc, "source_tool": tool,
                                       "hostname": "PC1", "data": {"CommandLine": desc, "i": i}})

    found = await artifact_service.search_artifacts(db_conn, case_id="arts", contains="whoami")
    assert found["total"] == 1 and found["items"][0]["description"] == "cmd.exe /c whoami"
    page = await artifact_service.search_artifacts(db_conn, case_id="arts", order="asc", limit=1, offset=1)
    assert page["total"] == 3 and page["items"][0]["description"].startswith("cmd.exe")
    ranged = await artifact_service.search_artifacts(db_conn, since="2024-01-01T11:00", tool="prefetch")
    assert [a["description"] for a in ranged["items"]] == ["notepad.exe"]

    number = found["items"][0]["artifact_number"]
    detail = await artifact_service.get_artifact(db_conn, number.lower(), case_id="arts", context_minutes=5)
    assert detail["artifact"]["data"]["CommandLine"] == "cmd.exe /c whoami"
    assert [c["description"] for c in detail["context"]] == ["powershell.exe -enc AAA", "cmd.exe /c whoami"]
    with pytest.raises(ValueError):
        await artifact_service.get_artifact(db_conn, "ART-99999")


# ---------------------------------------------------------------------------
# 3. Logging
# ---------------------------------------------------------------------------


class TestLogging:
    def test_redact_argv(self):
        from defair.logging import redact_argv

        assert redact_argv(["run", "start", "--password", "pw", "--passphrase=x", "--case", "C"]) == \
            ["run", "start", "--password", "***", "--passphrase=***", "--case", "C"]

    def test_cli_commands_logged_to_file(self, tmp_path, monkeypatch):
        from click.testing import CliRunner

        from defair.cli.main import cli

        log_file = tmp_path / "defair.log"
        monkeypatch.setenv("DEFAIR_LOG_FILE", str(log_file))
        monkeypatch.setattr(sys, "argv", ["defair", "profile", "list", "--json"])
        result = CliRunner().invoke(cli, ["--db", str(tmp_path / "x.db"), "profile", "list", "--json"])
        assert result.exit_code == 0
        events = [json.loads(line) for line in log_file.read_text().splitlines()]
        names = [e["event"] for e in events]
        assert "cli_command_started" in names and "cli_command_finished" in names
        finished = next(e for e in events if e["event"] == "cli_command_finished")
        assert finished["exit_code"] == 0 and "windows-triage" in finished["output"]
        assert finished["argv"] == ["profile", "list", "--json"]
        # results stay clean on stdout: no log lines mixed into JSON output
        json.loads(result.stdout)

    def test_secret_fields_redacted(self, tmp_path):
        import logging as stdlib_logging

        from defair.config import LoggingConfig
        from defair.logging import configure_logging, get_logger

        log_file = tmp_path / "l.log"
        configure_logging(LoggingConfig(level="INFO"), log_file=log_file)
        get_logger("t").info("x", password="hunter2", secrets=["password"])
        for h in stdlib_logging.getLogger().handlers:
            h.flush()
        line = json.loads(log_file.read_text().splitlines()[-1])
        assert line["password"] == "***" and line["secrets"] == ["password"]
        configure_logging(LoggingConfig(level="WARNING", format="console"), log_file=Path(""))


class TestContainerLogs:
    def test_pid1_follows_log_file(self):
        from defair.services.container_service import CONTAINER_ENTRY

        assert "tail -n 0 -F /workspace/logs/defair.log" in CONTAINER_ENTRY

    def test_unwritable_workspace_refused(self, tmp_path):
        from defair.services.container_service import check_workspace_writable

        (tmp_path / "defair.db").write_text("")
        (tmp_path / "defair.db").chmod(0o444)
        try:
            with pytest.raises(PermissionError, match="chown"):
                check_workspace_writable(tmp_path)
        finally:
            (tmp_path / "defair.db").chmod(0o644)


def test_rules_show_stays_in_store(tmp_path):
    from defair.services.rules_service import show_rule

    store = tmp_path / "store"
    rule = store / "sigma" / "sigmahq_core" / "rules" / "r.yml"
    rule.parent.mkdir(parents=True)
    rule.write_text("title: R\n")
    assert show_rule("sigmahq_core", "rules/r.yml", store)["content"] == "title: R\n"
    with pytest.raises(ValueError, match="inside"):
        show_rule("sigmahq_core", "../../../etc/passwd", store)
    with pytest.raises(ValueError, match="Unknown rule source"):
        show_rule("nope", "x", store)


@pytest.mark.asyncio
@pytest.mark.parametrize("tool, args, expected", [
    ("get_artifact", {"artifact": "ART-12", "context_minutes": 5},
     ["artifacts", "get", "ART-12", "--json", "--context", "5.0"]),
    ("get_finding", {"finding": "FND-001", "case_id": "test_case_img"},
     ["findings", "get", "FND-001", "--json", "--case", "test_case_img"]),
    ("show_rule", {"source": "sigmahq_core", "path": "rules/r.yml"},
     ["rules", "show", "sigmahq_core", "rules/r.yml"]),
    ("list_artifacts", {"contains": "whoami", "oldest_first": True},
     ["artifacts", "list", "--json", "--limit", "50", "--offset", "0", "--contains", "whoami", "--asc"]),
])
@patch("defair.mcp_server.server.container_service")
async def test_mcp_tools(mock_cs, tool, args, expected):
    from defair.mcp_server.server import mcp

    mock_cs.exec_in_container = AsyncMock(return_value={"exit_code": 0, "stdout": "{}", "stderr": ""})
    await mcp.call_tool(tool, {"container": "c", **args})
    assert mock_cs.exec_in_container.call_args.args[1] == ["defair", *expected]
