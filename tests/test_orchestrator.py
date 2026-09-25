"""Tests for profiles, the DAG executor, step execution and profile runs (v0.4)."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from defair.orchestrator.dag import StepFailed, StepSkipped, execute
from defair.orchestrator.profile import Fallback, Profile, Step, list_profiles, load_profile
from defair.orchestrator.steps import StepContext, _candidates, dissect_target, run_step

EVTX = b"ElfFile\x00" + b"\x00" * 120


def S(id, needs=(), **kw):
    return Step(id=id, tool=kw.pop("tool", "x"), needs=list(needs), **kw)


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------


class TestProfiles:
    def test_builtin_profiles_valid(self):
        names = {p["name"] for p in list_profiles()}
        assert {"windows-triage", "windows-full", "ransomware", "persistence",
                "registry-only", "scan-only"} <= names
        for name in names:
            profile = load_profile(name)
            assert profile.steps

    def test_builtin_tools_exist(self):
        from defair.tools.registry import get_default_registry

        registry = get_default_registry()
        known = {m.name for m in registry.list_all()} | {"dissect_plugin"}
        for p in list_profiles():
            for step in load_profile(p["name"]).steps:
                for tool in [step.tool, *[f.tool for f in step.fallbacks]]:
                    assert tool is None or tool in known, (p["name"], step.id, tool)

    def test_cycle_rejected(self):
        with pytest.raises(ValueError, match="cycle"):
            Profile(name="bad", steps=[S("a", ["b"]), S("b", ["a"])])

    def test_unknown_need_rejected(self):
        with pytest.raises(ValueError, match="unknown"):
            Profile(name="bad", steps=[S("a", ["zzz"])])

    def test_tool_xor_action(self):
        with pytest.raises(ValueError):
            Step(id="a", tool="x", action="scan")

    def test_fallback_strings_coerced(self):
        step = Step(id="a", tool="evtxecmd", fallbacks=["evtx_native", {"tool": "dissect_plugin", "plugin": "evtx"}])
        assert [f.tool for f in step.fallbacks] == ["evtx_native", "dissect_plugin"]
        assert step.fallbacks[1].is_dissect

    def test_unknown_profile(self):
        with pytest.raises(ValueError, match="Unknown profile"):
            load_profile("nope")


# ---------------------------------------------------------------------------
# DAG executor
# ---------------------------------------------------------------------------


class TestDag:
    @pytest.mark.asyncio
    async def test_dependencies_respected(self):
        order = []

        async def runner(step):
            order.append(step.id)
            await asyncio.sleep(0.01)
            return {}

        steps = [S("c", ["a", "b"]), S("a"), S("b", ["a"])]
        results = await execute(steps, runner)
        assert order == ["a", "b", "c"]
        assert all(r.status == "completed" for r in results.values())

    @pytest.mark.asyncio
    async def test_parallelism_bounded(self):
        active = peak = 0

        async def runner(step):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.05)
            active -= 1
            return {}

        await execute([S(f"s{i}") for i in range(8)], runner, max_parallel=3)
        assert peak == 3

    @pytest.mark.asyncio
    async def test_retry_then_success(self):
        calls = {"n": 0}

        async def runner(step):
            calls["n"] += 1
            if calls["n"] < 3:
                raise RuntimeError("flaky")
            return {"ok": True}

        results = await execute([S("a", retries=2)], runner, backoff=0)
        assert results["a"].status == "completed" and results["a"].attempts == 3

    @pytest.mark.asyncio
    async def test_timeout(self):
        async def runner(step):
            await asyncio.sleep(5)

        results = await execute([S("a", timeout=0.05)], runner)
        assert results["a"].status == "timeout"

    @pytest.mark.asyncio
    async def test_failure_skips_dependents_unless_optional(self):
        async def runner(step):
            if step.id in ("hard", "soft"):
                raise StepFailed("boom", {"tool_runs": [{"tool": "t"}]})
            return {}

        steps = [S("hard"), S("soft", optional=True), S("after_hard", ["hard"]), S("after_soft", ["soft"])]
        results = await execute(steps, runner)
        assert results["hard"].status == "failed"
        assert results["hard"].detail == {"tool_runs": [{"tool": "t"}]}  # StepFailed detail kept
        assert results["after_hard"].status == "skipped"
        assert results["after_soft"].status == "completed"

    @pytest.mark.asyncio
    async def test_skipped_step_does_not_block(self):
        async def runner(step):
            if step.id == "a":
                raise StepSkipped("no input")
            return {}

        results = await execute([S("a"), S("b", ["a"])], runner)
        assert results["a"].status == "skipped" and results["b"].status == "completed"

    @pytest.mark.asyncio
    async def test_cancel(self):
        cancel = asyncio.Event()

        async def runner(step):
            if step.id == "slow":
                cancel.set()
                await asyncio.sleep(10)
            return {}

        results = await execute([S("slow"), S("next", ["slow"])], runner, cancel_event=cancel)
        assert results["slow"].status == "cancelled"
        assert results["next"].status == "cancelled"

    @pytest.mark.asyncio
    async def test_resume_skips_completed(self):
        ran = []

        async def runner(step):
            ran.append(step.id)
            return {}

        previous = {"a": {"status": "completed", "attempts": 1, "artifacts": 7}, "b": {"status": "failed"}}
        results = await execute([S("a"), S("b", ["a"])], runner, previous=previous)
        assert ran == ["b"]
        assert results["a"].detail["resumed"] is True and results["a"].detail["artifacts"] == 7


# ---------------------------------------------------------------------------
# Steps: candidate chains, fallbacks, inputs
# ---------------------------------------------------------------------------

STEP = Step(id="evtx", tool="evtxecmd", input="evtx_dir",
            fallbacks=["evtx_native", {"tool": "dissect_plugin", "plugin": "evtx", "input": "target"}])


class TestCandidates:
    def test_auto(self):
        assert [c.tool for c in _candidates(STEP, "auto")] == ["evtxecmd", "evtx_native", "dissect_plugin"]

    def test_ez(self):
        assert [c.tool for c in _candidates(STEP, "ez")] == ["evtxecmd", "evtx_native"]

    def test_dissect(self):
        chain = _candidates(STEP, "dissect")
        assert [c.tool for c in chain] == ["dissect_plugin"] and chain[0].plugin == "evtx"

    def test_dissect_without_alternative_keeps_primary(self):
        step = Step(id="srum", tool="srumecmd", input="srum")
        assert [c.tool for c in _candidates(step, "dissect")] == ["srumecmd"]


class TestDissectTarget:
    def test_image_uses_original(self):
        prepared = {"source": {"kind": "disk_image"}, "target": "/evidence/d.E01", "kind": "kape",
                    "root": "/ws/c/C", "base": "/ws/c"}
        assert dissect_target(prepared) == "/evidence/d.E01"

    def test_kape_uses_folder_above_drive(self):
        prepared = {"source": {"kind": "kape"}, "target": "/evidence/k", "kind": "kape",
                    "root": "/evidence/k/triage/C", "base": "/evidence/k"}
        assert dissect_target(prepared) == "/evidence/k/triage"


def _ctx(tmp_path, selectors, engine="auto", kind="kape"):
    from unittest.mock import MagicMock

    registry = MagicMock()
    available = {"evtxecmd": False, "evtx_native": True, "dissect_plugin": True, "srumecmd": True}

    def get(name):
        if name not in available:
            return None
        tool = MagicMock()
        tool.is_available.return_value = available[name]
        tool.manifest.return_value.allowed_options = ["directory", "registry_hive"]
        return tool

    registry.get.side_effect = get
    prepared = {"kind": kind, "base": str(tmp_path), "root": str(tmp_path / "C"),
                "target": str(tmp_path), "source": {"kind": kind}, "selectors": selectors}
    return StepContext(conn=None, case_id="case", evidence_id="ev", prepared=prepared,
                       engine=engine, output_base=str(tmp_path / "analysis"), registry=registry)


def _fake_run(statuses: dict):
    async def fake(conn, tool, target, case_id, **kwargs):
        status = statuses.get(tool, "completed")
        return {"status": status, "run_number": f"RUN-{tool}", "artifacts_produced": 3,
                "exit_code": 0 if status == "completed" else 1, "kwargs": kwargs}
    return fake


class TestRunStep:
    @pytest.mark.asyncio
    async def test_falls_back_to_native_when_ez_unavailable(self, tmp_path):
        ctx = _ctx(tmp_path, {"evtx_dir": [str(tmp_path)]})
        with patch("defair.services.analysis_service.run_tool_and_normalize",
                   side_effect=_fake_run({})):
            detail = await run_step(ctx, STEP)
        assert [(r["tool"], r["status"]) for r in detail["tool_runs"]] == [
            ("evtxecmd", "unavailable"), ("evtx_native", "completed")]
        assert detail["used"] == ["evtx_native"] and detail["artifacts"] == 3

    @pytest.mark.asyncio
    async def test_dissect_fallback_after_native_fails(self, tmp_path):
        ctx = _ctx(tmp_path, {"evtx_dir": [str(tmp_path / "a"), str(tmp_path / "b")]})
        with patch("defair.services.analysis_service.run_tool_and_normalize",
                   side_effect=_fake_run({"evtx_native": "failed"})) as run:
            detail = await run_step(ctx, STEP)
        dissect_runs = [r for r in detail["tool_runs"] if r["tool"] == "dissect_plugin"]
        assert len(dissect_runs) == 1  # the whole target once, not once per location
        assert run.call_args_list[-1].kwargs["plugin"] == "evtx"
        # location b is not parsed again: Dissect already covered the target
        assert [r["input"] for r in detail["tool_runs"]].count(str(tmp_path / "b")) == 0

    @pytest.mark.asyncio
    async def test_all_fail(self, tmp_path):
        ctx = _ctx(tmp_path, {"evtx_dir": [str(tmp_path)]}, engine="ez")
        with patch("defair.services.analysis_service.run_tool_and_normalize",
                   side_effect=_fake_run({"evtx_native": "failed"})), \
             pytest.raises(StepFailed) as err:
            await run_step(ctx, STEP)
        assert err.value.detail["tool_runs"]

    @pytest.mark.asyncio
    async def test_missing_input_skips(self, tmp_path):
        with pytest.raises(StepSkipped, match="evtx_dir"):
            await run_step(_ctx(tmp_path, {}), STEP)

    @pytest.mark.asyncio
    async def test_dissect_engine_uses_target_even_without_input(self, tmp_path):
        ctx = _ctx(tmp_path, {}, engine="dissect")
        with patch("defair.services.analysis_service.run_tool_and_normalize",
                   side_effect=_fake_run({})):
            detail = await run_step(ctx, STEP)
        assert detail["used"] == ["dissect_plugin"]

    @pytest.mark.asyncio
    async def test_logs_evidence_has_no_dissect_target(self, tmp_path):
        ctx = _ctx(tmp_path, {}, engine="dissect", kind="logs")
        with pytest.raises(StepSkipped):
            await run_step(ctx, STEP)

    @pytest.mark.asyncio
    async def test_option_selector_and_directory(self, tmp_path):
        ctx = _ctx(tmp_path, {"srum": [str(tmp_path / "SRUDB.dat")], "software_hive": ["/x/SOFTWARE"]})
        step = Step(id="srum", tool="srumecmd", input="srum", options={"registry_hive": "$software_hive"})
        with patch("defair.services.analysis_service.run_tool_and_normalize",
                   side_effect=_fake_run({})) as run:
            await run_step(ctx, step)
        kwargs = run.call_args.kwargs
        assert kwargs["registry_hive"] == "/x/SOFTWARE" and kwargs["directory"] is False
        assert kwargs["auto_fallback"] is False


# ---------------------------------------------------------------------------
# Concurrency fixes
# ---------------------------------------------------------------------------


class TestConcurrency:
    @pytest.mark.asyncio
    async def test_parallel_runs_get_unique_numbers(self, db_conn):
        from defair.models.tool_run import ToolRun, ToolRunStatus
        from defair.services import analysis_service, case_service

        case = await case_service.create_case(db_conn, "parallel")

        class SlowTool:
            def is_available(self):
                return True

            def manifest(self):
                from defair.models.tool_manifest import ToolManifest
                return ToolManifest(name="slow", display_name="Slow")

            async def run(self, input_path, output_dir, case_id, evidence_id=None, run_number="", **kw):
                await asyncio.sleep(0.02)
                return ToolRun(run_number=run_number, case_id=case_id, tool_name="slow",
                               status=ToolRunStatus.COMPLETED)

        registry = analysis_service.ToolRegistry()
        registry._tools["slow"] = SlowTool()
        runs = await asyncio.gather(*[
            analysis_service.run_tool(db_conn, "slow", "/x", case.id, registry=registry)
            for _ in range(10)
        ])
        numbers = [r.run_number for r in runs]
        assert len(set(numbers)) == 10
        cursor = await db_conn.execute("SELECT COUNT(*) FROM tool_runs WHERE status = 'completed'")
        assert (await cursor.fetchone())[0] == 10

    @pytest.mark.asyncio
    async def test_parallel_findings_get_unique_numbers(self, db_conn):
        from defair.services import case_service, finding_service

        case = await case_service.create_case(db_conn, "findings")
        created = await asyncio.gather(*[
            finding_service.create_finding(db_conn, case.id, f"f{i}") for i in range(10)
        ])
        assert len({f["finding_number"] for f in created}) == 10

    @pytest.mark.asyncio
    async def test_cancelled_tool_kills_subprocess(self, tmp_path):
        from defair.models.tool_manifest import ToolManifest
        from defair.tools.base import BaseTool

        marker = tmp_path / "pid"

        class Sleeper(BaseTool):
            @staticmethod
            def manifest():
                return ToolManifest(name="sleeper", display_name="Sleeper", command="sh")

            def build_command(self, input_path, output_dir, **kw):
                return ["sh", "-c", f"echo $$ > {marker}; exec sleep 30"]

        task = asyncio.create_task(Sleeper().run("/x", str(tmp_path / "out"), "case"))
        for _ in range(50):
            if marker.exists() and marker.read_text().strip():
                break
            await asyncio.sleep(0.05)
        pid = int(marker.read_text())
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0.1)
        from defair.orchestrator.runs import is_alive
        assert not is_alive(pid)


# ---------------------------------------------------------------------------
# Profile runs
# ---------------------------------------------------------------------------


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    monkeypatch.setenv("DEFAIR_WORKSPACE", str(ws))
    return ws


async def _case_with_logs(db_conn, tmp_path):
    from defair.services import case_service, evidence_service

    case = await case_service.create_case(db_conn, "runs")
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "Security.evtx").write_bytes(EVTX)
    ev = await evidence_service.add_evidence(db_conn, case.id, logs)
    return case, ev


class TestRuns:
    @pytest.mark.asyncio
    async def test_create_numbers(self, db_conn, tmp_path, workspace):
        from defair.orchestrator import runs

        case, ev = await _case_with_logs(db_conn, tmp_path)
        a = await runs.create_run(db_conn, case.id, ev.evidence_number, "windows-triage")
        b = await runs.create_run(db_conn, case.id, ev.evidence_number, "auto", "dissect")
        assert (a["run_number"], b["run_number"]) == ("PRUN-001", "PRUN-002")
        with pytest.raises(ValueError, match="engine"):
            await runs.create_run(db_conn, case.id, ev.evidence_number, "auto", "fast")
        with pytest.raises(ValueError, match="Unknown profile"):
            await runs.create_run(db_conn, case.id, ev.evidence_number, "nope")

    @pytest.mark.asyncio
    async def test_execute_writes_manifest_and_status(self, db_conn, tmp_path, workspace):
        from defair.orchestrator import runs

        case, ev = await _case_with_logs(db_conn, tmp_path)
        run = await runs.create_run(db_conn, case.id, ev.evidence_number, "auto")

        async def fake_step(ctx, step):
            if step.id == "evtx":
                return {"tool_runs": [{"tool": "evtx_native", "status": "completed", "artifacts": 1}],
                        "artifacts": 1}
            raise StepSkipped("n/a")

        with patch("defair.orchestrator.runs.run_step", side_effect=fake_step):
            result = await runs.execute_run(db_conn, run["run_number"])
        assert result["status"] == "completed" and result["profile"] == "windows-triage"
        manifest = json.loads(Path(result["manifest"]).read_text())
        assert manifest["evidence"]["kind"] == "logs" and manifest["artifacts"] == 1
        assert {s["id"]: s["status"] for s in manifest["steps"]}["evtx"] == "completed"

    @pytest.mark.asyncio
    async def test_manifest_written_when_preparation_fails(self, db_conn, tmp_path, workspace):
        import pyzipper

        from defair.orchestrator import runs
        from defair.services import case_service, evidence_service

        case = await case_service.create_case(db_conn, "fail")
        enc = tmp_path / "e.zip"
        with pyzipper.AESZipFile(enc, "w", encryption=pyzipper.WZ_AES) as z:
            z.setpassword(b"pw")
            z.writestr("x.evtx", EVTX)
        ev = await evidence_service.add_evidence(db_conn, case.id, enc)
        run = await runs.create_run(db_conn, case.id, ev.evidence_number, "auto")
        result = await runs.execute_run(db_conn, run["run_number"])
        assert result["status"] == "failed" and "password" in result["error"]
        assert json.loads(Path(result["manifest"]).read_text())["status"] == "failed"

    @pytest.mark.asyncio
    async def test_dead_worker_detected(self, db_conn, tmp_path, workspace):
        from defair.orchestrator import runs

        case, ev = await _case_with_logs(db_conn, tmp_path)
        run = await runs.create_run(db_conn, case.id, ev.evidence_number, "auto")
        proc = await asyncio.create_subprocess_exec(sys.executable, "-c", "pass")
        await proc.wait()
        await runs._update(db_conn, run["id"], status="running", pid=proc.pid)
        status = await runs.run_status(db_conn, run["run_number"])
        assert status["status"] == "failed" and "unexpectedly" in status["error"]

    @pytest.mark.asyncio
    async def test_cancel_not_running(self, db_conn, tmp_path, workspace):
        from defair.orchestrator import runs

        case, ev = await _case_with_logs(db_conn, tmp_path)
        run = await runs.create_run(db_conn, case.id, ev.evidence_number, "auto")
        await runs._update(db_conn, run["id"], status="completed")
        with pytest.raises(ValueError, match="not running"):
            await runs.cancel_run(db_conn, run["run_number"])

    def test_secrets_file_read_once(self, tmp_path):
        from defair.orchestrator.runs import read_secrets_file

        f = tmp_path / "s.json"
        f.write_text(json.dumps({"password": "pw"}))
        assert read_secrets_file(str(f)) == {"password": "pw"}
        assert not f.exists()

    def test_real_background_worker(self, tmp_path, workspace):
        """spawn_worker → detached `defair run worker` → terminal status + run.json."""
        from defair.database import get_initialized_connection
        from defair.orchestrator import runs

        db = str(tmp_path / "w.db")

        async def setup():
            conn = await get_initialized_connection(db)
            try:
                case, ev = await _case_with_logs(conn, tmp_path)
                return await runs.create_run(conn, case.id, ev.evidence_number, "registry-only")
            finally:
                await conn.close()

        run = asyncio.run(setup())
        pid = runs.spawn_worker(run["run_number"], db, {"password": "unused"})
        deadline = time.time() + 60
        status = None
        while time.time() < deadline:
            async def poll():
                conn = await get_initialized_connection(db)
                try:
                    return await runs.run_status(conn, run["run_number"])
                finally:
                    await conn.close()
            status = asyncio.run(poll())
            if status["status"] not in runs.ACTIVE:
                break
            time.sleep(0.5)
        assert status["status"] in ("completed", "completed_with_errors"), status
        assert Path(status["manifest"]).exists()
        assert not list(Path("/tmp").glob(f"defair-secrets-*{pid}*"))
        assert os.environ.get("DEFAIR_WORKSPACE") == str(workspace)


# ---------------------------------------------------------------------------
# MCP
# ---------------------------------------------------------------------------


class TestMCPRuns:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool, args, expected", [
        ("list_profiles", {}, ["profile", "list", "--json"]),
        ("get_profile", {"name": "ransomware"}, ["profile", "show", "ransomware"]),
        ("run_profile", {"case_id": "C", "evidence_id": "EVD-001", "profile": "windows-full",
                         "engine": "dissect"},
         ["run", "start", "--case", "C", "--evidence", "EVD-001", "--profile", "windows-full",
          "--engine", "dissect", "--json"]),
        ("analyze_evidence", {"case_id": "C", "evidence_path": "/evidence/host.E01"},
         ["run", "start", "--case", "C", "--evidence", "/evidence/host.E01", "--profile", "auto",
          "--engine", "auto", "--json"]),
        ("get_run_status", {"run": "PRUN-001"}, ["run", "status", "PRUN-001", "--json"]),
        ("list_runs", {}, ["run", "list", "--json"]),
        ("cancel_run", {"run": "PRUN-001"}, ["run", "cancel", "PRUN-001", "--json"]),
        ("resume_run", {"run": "PRUN-001"}, ["run", "resume", "PRUN-001", "--json"]),
    ])
    @patch("defair.mcp_server.server.container_service")
    async def test_proxies(self, mock_cs, tool, args, expected):
        from defair.mcp_server.server import mcp

        mock_cs.exec_in_container = AsyncMock(return_value={"exit_code": 0, "stdout": "{}", "stderr": ""})
        await mcp.call_tool(tool, {"container": "c", **args})
        assert mock_cs.exec_in_container.call_args.args[1] == ["defair", *expected]

    @pytest.mark.asyncio
    @patch("defair.mcp_server.server.container_service")
    async def test_run_profile_secrets_by_env(self, mock_cs):
        from defair.mcp_server.server import mcp

        mock_cs.exec_in_container = AsyncMock(return_value={"exit_code": 0, "stdout": "{}", "stderr": ""})
        await mcp.call_tool("run_profile", {"container": "c", "case_id": "C", "evidence_id": "EVD-1",
                                            "password": "infected"})
        args, kwargs = mock_cs.exec_in_container.call_args
        assert "infected" not in args[1] and kwargs["env"] == {"DEFAIR_EVIDENCE_PASSWORD": "infected"}

    @pytest.mark.asyncio
    async def test_analyze_refuses_outside_paths(self):
        from defair.mcp_server.server import mcp

        with pytest.raises(Exception, match="under /evidence"):
            await mcp.call_tool("analyze_evidence", {"container": "c", "case_id": "C",
                                                     "evidence_path": "/etc/shadow"})


def test_fallback_model():
    assert Fallback(tool="dissect_plugin", plugin="evtx").is_dissect
