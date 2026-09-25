"""v0.5 — worker jobs, Plaso / Sleuth Kit normalization, supertimeline import, merged timeline."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from defair.config import ContainerConfig, WorkerConfig

FIXTURES = Path(__file__).parent / "fixtures"
PY = sys.executable

MMLS = """DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0001026047   0001024000   NTFS / exFAT (0x07)
003:  000:001   0001026048   0001026559   0000000512   Linux Swap / Solaris x86 (0x82)
004:  000:002   0001026560   0041943039   0040916480   Linux (0x83)
"""


# ---------------------------------------------------------------------------
# Sleuth Kit helpers
# ---------------------------------------------------------------------------


class TestTsk:
    def test_mmls(self):
        from defair.workers.tsk import parse_mmls

        sector, partitions = parse_mmls(MMLS)
        assert sector == 512
        assert [(p["offset"], p["description"]) for p in partitions] == [
            (2048, "NTFS / exFAT (0x07)"), (1026560, "Linux (0x83)")]  # swap < 1 MiB, meta, unallocated dropped
        assert [p["index"] for p in partitions] == [0, 1]

    def test_no_partition_table(self):
        from defair.workers.tsk import parse_mmls

        assert parse_mmls("") == (512, [])

    def test_bodyfile_and_macb(self):
        from defair.workers.tsk import macb_events, parse_bodyfile_line

        entry = parse_bodyfile_line("0|C:/a|b.txt|42-128-1|r/rrwxrwxrwx|0|0|10|100|200|100|300\n")
        assert entry["name"] == "C:/a|b.txt"  # "|" inside a file name
        # atime = ctime = 100: one event flagged ".ac."
        assert list(macb_events(entry)) == [(100.0, ".ac."), (200.0, "m..."), (300.0, "...b")]
        assert parse_bodyfile_line("garbage") is None

    def test_fs_type_order(self):
        from defair.workers.entry import order_fs_types

        assert order_fs_types(["ntfs", "fat", "ext"], "Linux (0x83)") == ["ext", "ntfs", "fat"]
        assert order_fs_types(["ntfs", "fat"], "") == ["ntfs", "fat"]


# ---------------------------------------------------------------------------
# Job runner (worker image)
# ---------------------------------------------------------------------------


def _run_job(tmp_path: Path, steps: list[dict], hashes: list[str] | None = None, monkeypatch=None) -> dict:
    from defair.workers import entry

    job = tmp_path / "jobs" / "RUN-009"
    job.mkdir(parents=True)
    (job / "job.json").write_text(json.dumps({"run_number": "RUN-009", "worker": "plaso",
                                              "steps": steps, "hash": hashes or []}))
    if monkeypatch:
        monkeypatch.setattr(entry, "LOG_FILE", tmp_path / "logs" / "defair.log")
    code = entry.main([str(job / "job.json")])
    status = json.loads((job / "status.json").read_text())
    status["_exit"] = code
    return status


class TestRunner:
    def test_steps_skip_stdout_hash(self, tmp_path, monkeypatch):
        out = tmp_path / "out.txt"
        status = _run_job(tmp_path, [
            {"name": "skipped", "argv": ["false"], "skip": True, "skip_reason": "reused"},
            {"name": "hello", "argv": [PY, "-c", "print('hi')"], "stdout": str(out)},
        ], hashes=[str(out)], monkeypatch=monkeypatch)
        assert status["_exit"] == 0 and status["state"] == "completed"
        assert [(s["name"], s["state"]) for s in status["steps"]] == [("skipped", "skipped"), ("hello", "completed")]
        assert out.read_text() == "hi\n" and status["hashes"][str(out)]
        log = (tmp_path / "logs" / "defair.log").read_text().splitlines()
        assert any(json.loads(line)["event"] == "worker_job_finished" for line in log)

    def test_failure_stops_the_job(self, tmp_path, monkeypatch):
        status = _run_job(tmp_path, [
            {"name": "boom", "argv": [PY, "-c", "import sys; sys.stderr.write('bad'); sys.exit(3)"]},
            {"name": "never", "argv": [PY, "-c", "pass"]},
        ], monkeypatch=monkeypatch)
        assert status["state"] == "failed" and status["_exit"] == 1
        assert status["steps"][0]["exit_code"] == 3 and status["steps"][0]["stderr_tail"] == "bad"
        assert len(status["steps"]) == 1

    def test_partitions_alternatives_and_strings(self, tmp_path, monkeypatch):
        fake_mmls = tmp_path / "mmls.py"
        fake_mmls.write_text(f"print({MMLS!r})")
        # "fls" that only understands ext: ntfs fails, ext succeeds
        fake_fls = tmp_path / "fls.py"
        fake_fls.write_text("import sys\nfs = sys.argv[sys.argv.index('-f') + 1]\n"
                            "print('body', fs, sys.argv[sys.argv.index('-o') + 1])\n"
                            "sys.exit(0 if fs == 'ext' else 1)\n")
        blob = tmp_path / "blkls.py"
        blob.write_text("import sys\nsys.stdout.buffer.write(b'\\x00' * 100 + b'http://evil.example/x' + b'\\x00')\n")
        status = _run_job(tmp_path, [
            {"name": "mmls", "argv": [PY, str(fake_mmls)], "parse": "mmls"},
            {"name": "fls", "for_each": "partition", "try": {"fstype": ["ntfs", "ext"]},
             "argv": [PY, str(fake_fls), "-f", "{fstype}", "-o", "{offset}"],
             "stdout": str(tmp_path / "body-{index}.txt"), "allow_failure": True},
            {"name": "blkls", "for_each": "partition", "try": {"fstype": ["ntfs"]},
             "argv": [PY, str(blob), "{fstype}", "{offset}"],
             "strings_to": str(tmp_path / "strings-{index}.tsv"), "allow_failure": True},
        ], monkeypatch=monkeypatch)
        assert status["state"] == "completed"
        assert [p["offset"] for p in status["partitions"]] == [2048, 1026560]
        fls = [s for s in status["steps"] if s["name"].startswith("fls")]
        assert [(s["name"], s["fstype"]) for s in fls] == [("fls[0]", "ext"), ("fls[1]", "ext")]
        # the Linux partition tries ext first (mmls description)
        assert [a["value"] for a in fls[1]["attempts"]] == ["ext"]
        assert (tmp_path / "body-1.txt").read_text() == "body ext 1026560\n"
        assert (tmp_path / "body-0.txt").read_text() == "body ext 2048\n"  # failed ntfs attempt removed
        blkls = [s for s in status["steps"] if s["name"].startswith("blkls")]
        assert blkls[0]["strings"]["strings"] == 1
        assert (tmp_path / "strings-0.tsv").read_text() == "100\tascii\thttp://evil.example/x\n"

    def test_missing_tool_and_crash_recorded(self, tmp_path, monkeypatch):
        status = _run_job(tmp_path, [{"name": "x", "argv": ["/nonexistent/tool"]}], monkeypatch=monkeypatch)
        assert status["state"] == "failed" and status["steps"][0]["exit_code"] == 127

    def test_check_module_reports(self, capsys):
        from defair.workers import check

        with patch.object(check, "TOOLS", {"python": [PY, "--version"]}):
            assert check.main() == 0
        assert "Python" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Worker service (host, Docker mocked)
# ---------------------------------------------------------------------------


def _case_container(workspace: Path, keys: bool = True):
    case = MagicMock()
    case.name = "defair-case-2026-001"
    case.labels = {"defair.case_id": "CASE-2026-001", "defair.workspace": str(workspace)}
    mounts = [
        {"Source": str(workspace), "Destination": "/workspace", "Mode": "rw"},
        {"Source": "/host/evidence/disk.E01", "Destination": "/evidence", "Mode": "ro"},
    ]
    if keys:
        mounts.append({"Source": "/host/keys", "Destination": "/keys", "Mode": "ro"})
    case.attrs = {"Mounts": mounts}
    return case


WORKERS = {"plaso": WorkerConfig(image="ghcr.io/joblinours/defair-worker-plaso:0.5.0", cpus=2, mem_limit="4g")}


class TestWorkerService:
    @pytest.mark.asyncio
    async def test_start_job_mounts_and_hardening(self, tmp_path):
        from defair.services import worker_service

        workspace = tmp_path / "ws"
        (workspace / "jobs" / "RUN-004").mkdir(parents=True)
        (workspace / "jobs" / "RUN-004" / "job.json").write_text("{}")
        client = MagicMock()
        client.containers.get.side_effect = lambda name: _case_container(workspace) if name == \
            "defair-case-2026-001" else (_ for _ in ()).throw(__import__("docker").errors.NotFound("x"))
        started = MagicMock()
        started.image.id = "sha256:abc"
        started.image.attrs = {"RepoDigests": ["ghcr.io/joblinours/defair-worker-plaso@sha256:def"]}
        client.containers.run.return_value = started
        with patch.object(worker_service, "_get_client", return_value=client):
            result = await worker_service.start_job("defair-case-2026-001", "plaso", "RUN-004", WORKERS,
                                                    ContainerConfig(network="bridge"))
        kwargs = client.containers.run.call_args.kwargs
        assert kwargs["image"] == "ghcr.io/joblinours/defair-worker-plaso:0.5.0"
        assert kwargs["command"] == ["python3", "-m", "defair.workers.entry", "/workspace/jobs/RUN-004/job.json"]
        assert kwargs["volumes"] == {str(workspace): {"bind": "/workspace", "mode": "rw"},
                                     "/host/evidence/disk.E01": {"bind": "/evidence", "mode": "ro"}}
        assert "/host/keys" not in kwargs["volumes"]  # keys stay with the case container
        assert kwargs["network_mode"] == "none"  # even if the case policy allowed a network
        assert kwargs["cap_drop"] == ["ALL"] and kwargs["read_only"] is True
        assert kwargs["mem_limit"] == "4g" and kwargs["nano_cpus"] == 2_000_000_000
        assert kwargs["labels"]["defair.job"] == "true" and kwargs["labels"]["defair.run"] == "RUN-004"
        start = json.loads((workspace / "jobs" / "RUN-004" / "start.json").read_text())
        assert start["image_id"] == "sha256:abc" and start["repo_digests"] == result["repo_digests"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("image, message", [
        ("ghcr.io/joblinours/defair-worker-plaso:latest", "pinned"),
        ("ghcr.io/joblinours/defair-worker-plaso", "pinned"),
        ("docker.io/evil/plaso:1.0", "not allowed"),
    ])
    async def test_image_policy(self, image, message):
        from defair.services import worker_service

        with pytest.raises(ValueError, match=message):
            await worker_service.start_job("c", "plaso", "RUN-1", {"plaso": WorkerConfig(image=image)},
                                           ContainerConfig())

    @pytest.mark.asyncio
    async def test_missing_spec(self, tmp_path):
        from defair.services import worker_service

        client = MagicMock()
        client.containers.get.return_value = _case_container(tmp_path)
        with patch.object(worker_service, "_get_client", return_value=client), \
             pytest.raises(FileNotFoundError, match="prepare"):
            await worker_service.start_job("defair-case-2026-001", "plaso", "RUN-7", WORKERS, ContainerConfig())

    @pytest.mark.asyncio
    async def test_status_states(self, tmp_path):
        import docker.errors

        from defair.services import worker_service

        workspace = tmp_path / "ws"
        job = workspace / "jobs" / "RUN-004"
        job.mkdir(parents=True)
        running = MagicMock(status="running", attrs={"State": {"ExitCode": 0}}, labels={})
        running.image.tags = ["img:0.5.0"]
        client = MagicMock()

        def get(name):
            if name == "defair-case-2026-001":
                return _case_container(workspace)
            return current["job"]

        client.containers.get.side_effect = get
        current = {"job": running}
        with patch.object(worker_service, "_get_client", return_value=client):
            assert (await worker_service.job_status("defair-case-2026-001", "RUN-004"))["state"] == "running"
            exited = MagicMock(status="exited", attrs={"State": {"ExitCode": 1}}, labels={})
            exited.image.tags = []
            current["job"] = exited
            assert (await worker_service.job_status("defair-case-2026-001", "RUN-004"))["state"] == "failed"
            (job / "status.json").write_text(json.dumps({"state": "completed"}))
            current["job"] = exited
            exited.attrs = {"State": {"ExitCode": 0}}
            assert (await worker_service.job_status("defair-case-2026-001", "RUN-004"))["state"] == "completed"

            def gone(name):
                if name == "defair-case-2026-001":
                    return _case_container(workspace)
                raise docker.errors.NotFound("gone")

            client.containers.get.side_effect = gone
            status = await worker_service.job_status("defair-case-2026-001", "RUN-004")
            assert status["container"] == "removed" and status["state"] == "completed"


# ---------------------------------------------------------------------------
# Normalizers
# ---------------------------------------------------------------------------


class TestNormalizers:
    def test_plaso_events(self):
        from defair.normalizers.plaso import iter_plaso

        events = list(iter_plaso(FIXTURES / "plaso_json_line.jsonl"))
        assert len(events) == 4 and all(e for e in events)
        by_type = {e["source_long"]: e for e in events}
        prefetch = by_type["windows:prefetch:execution"]
        assert prefetch["source"] == "plaso" and prefetch["parser"] == "prefetch"
        assert prefetch["source_short"] == "LOG"
        # FILETIME keeps its 100 ns precision
        assert prefetch["timestamp"].endswith("Z") and len(prefetch["timestamp"].split(".")[1]) == 8
        assert by_type["fs:stat"]["source_short"] == "FILE"
        assert by_type["fs:stat"]["filename"].startswith("/evidence/")
        evtx = by_type["windows:evtx:record"]
        assert evtx["source_short"] == "EVT" and evtx["hostname"]
        assert len({e["record_key"] for e in events}) == 4

    def test_plaso_zero_time_is_none(self):
        from defair.normalizers.plaso import event_time, normalize_event

        assert event_time({"timestamp": 0}) is None
        event = normalize_event({"timestamp": 0, "data_type": "x", "message": "m"}, "line")
        assert event["timestamp"] is None and event["provenance"]["raw_timestamp"] == "0"

    def test_bodyfile(self):
        from defair.normalizers.bodyfile import iter_bodyfile

        events = [e for e in iter_bodyfile(FIXTURES / "fls_bodyfile.txt", {"index": 0, "offset": 0}) if e]
        assert events and all(e["source"] == "tsk" for e in events)
        first = events[0]
        assert first["timestamp_desc"].endswith("(macb)")  # four equal times grouped
        assert first["data"]["macb"] == "macb" and first["filename"].startswith("C:/Documents")
        keys = [e["record_key"] for e in events]
        assert len(keys) == len(set(keys))


# ---------------------------------------------------------------------------
# Supertimeline service (case container)
# ---------------------------------------------------------------------------


async def _image_evidence(conn, tmp_path, kind="disk_image"):
    from defair.services import case_service, evidence_service

    case = await case_service.create_case(conn, "super")
    image = tmp_path / "disk.E01"
    image.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 100)
    evidence = await evidence_service.add_evidence(conn, case.id, image, "disk_image")
    prepared = {"kind": "kape", "base": str(tmp_path / "content"), "root": str(tmp_path / "content" / "C"),
                "target": str(image), "source": {"kind": kind}}
    await conn.execute("UPDATE evidence SET prepared = ? WHERE id = ?", (json.dumps(prepared), evidence.id))
    await conn.commit()
    return case, evidence


def _finish_job(run: str, workspace: Path, status: dict, events: bool = True, bodyfile: bool = True):
    job = workspace / "jobs" / run
    if events:
        shutil.copy(FIXTURES / "plaso_json_line.jsonl", job / "events.jsonl")
    if bodyfile:
        shutil.copy(FIXTURES / "fls_bodyfile.txt", job / "bodyfile-0.txt")
    (job / "status.json").write_text(json.dumps(status))


class TestSupertimelineService:
    @pytest.mark.asyncio
    async def test_prepare_import_reuse(self, db_conn, tmp_path, monkeypatch):
        from defair.services import supertimeline_service, timeline_service

        monkeypatch.setenv("DEFAIR_WORKSPACE", str(tmp_path / "ws"))
        case, evidence = await _image_evidence(db_conn, tmp_path)
        job = await supertimeline_service.prepare_job(db_conn, case.id, evidence.evidence_number, mode="both",
                                                      parsers="winevtx", timezone="Europe/Paris")
        spec = json.loads(Path(job["job"]).read_text())
        names = [s["name"] for s in spec["steps"]]
        assert names == ["log2timeline", "psort", "mmls", "fls"]
        l2t = spec["steps"][0]["argv"]
        assert l2t[0] == "log2timeline" and ["--parsers", "winevtx"] == l2t[l2t.index("--parsers"):][:2]
        assert ["--timezone", "Europe/Paris"] == l2t[l2t.index("--timezone"):][:2]
        assert l2t[-1] == str(tmp_path / "disk.E01") and "--unattended" in l2t
        assert spec["steps"][0]["skip"] is False
        assert spec["steps"][3]["try"] == {"fstype": supertimeline_service.FS_TYPES}
        run = job["run_number"]

        # not finished yet: nothing imported
        assert (await supertimeline_service.import_job(db_conn, run))["imported"] is False

        storage = Path(job["plan"]["plaso"]["storage"])
        storage.write_bytes(b"plaso storage")
        from defair.normalizers.pipeline import sha256_file

        _finish_job(run, tmp_path / "ws", {
            "state": "completed", "completed_at": "2026-09-26T00:00:00Z",
            "versions": {"plaso": {"version": "20260720"}}, "hashes": {str(storage): sha256_file(storage)},
            "partitions": [], "steps": [{"name": n, "state": "completed"} for n in names]})
        result = await supertimeline_service.import_job(db_conn, run)
        assert result["imported"] and result["events"]["plaso"] == 4 and result["events"]["tsk"] > 0
        again = await supertimeline_service.import_job(db_conn, run)
        assert again["already_imported"]  # idempotent
        cursor = await db_conn.execute("SELECT status, tool_version FROM tool_runs WHERE run_number = ?", (run,))
        assert tuple(await cursor.fetchone()) == ("completed", "20260720")
        meta = json.loads(Path(job["plan"]["plaso"]["meta"]).read_text())
        assert meta["parsers"] == "winevtx" and meta["sha256"] == sha256_file(storage)
        manifest = json.loads((tmp_path / "ws" / "jobs" / run / "manifest.json").read_text())
        assert manifest["import"]["events"]["plaso"] == 4

        # merged timeline
        summary = await timeline_service.build_timeline(db_conn, case.id)
        assert summary["by_source"]["plaso"] == 4 and summary["supertimeline_events"] > 4
        plaso_only = await timeline_service.search_timeline(db_conn, case.id, sources="plaso", limit=10)
        assert len(plaso_only) == 4 and {e["record"] for e in plaso_only} == {"event"}
        fts = await timeline_service.search_timeline(db_conn, case.id, query="ProgramData", sources="tsk")
        assert fts and all("ProgramData" in e["source_file"] for e in fts)
        assert await timeline_service.search_timeline(db_conn, case.id, parser="prefetch")
        assert not await timeline_service.search_timeline(db_conn, case.id, severity="high", sources="plaso")

        # same parameters → the storage is reused (only psort runs)
        reuse = await supertimeline_service.prepare_job(db_conn, case.id, evidence.evidence_number,
                                                        mode="plaso", parsers="winevtx", timezone="Europe/Paris")
        assert reuse["plan"]["plaso"]["reused"] is True
        assert json.loads(Path(reuse["job"]).read_text())["steps"][0]["skip"] is True
        # different parameters → refused, unless overwrite
        with pytest.raises(ValueError, match="built differently"):
            await supertimeline_service.prepare_job(db_conn, case.id, evidence.evidence_number, parsers="win7")
        rebuilt = await supertimeline_service.prepare_job(db_conn, case.id, evidence.evidence_number,
                                                          parsers="win7", overwrite=True)
        assert rebuilt["plan"]["plaso"]["reused"] is False and not storage.exists()

    @pytest.mark.asyncio
    async def test_tampered_storage_refused(self, db_conn, tmp_path, monkeypatch):
        from defair.services import supertimeline_service

        monkeypatch.setenv("DEFAIR_WORKSPACE", str(tmp_path / "ws"))
        case, evidence = await _image_evidence(db_conn, tmp_path)
        storage, meta = supertimeline_service.plaso_paths(evidence.evidence_number)
        storage.parent.mkdir(parents=True)
        storage.write_bytes(b"changed")
        meta.write_text(json.dumps({"evidence_sha256": evidence.sha256, "parsers": "auto", "timezone": "UTC",
                                    "target": str(tmp_path / "disk.E01"), "sha256": "0" * 64}))
        with pytest.raises(ValueError, match="SHA-256"):
            await supertimeline_service.prepare_job(db_conn, case.id, evidence.evidence_number)

    @pytest.mark.asyncio
    async def test_collection_has_no_bodyfile(self, db_conn, tmp_path, monkeypatch):
        from defair.services import supertimeline_service

        monkeypatch.setenv("DEFAIR_WORKSPACE", str(tmp_path / "ws"))
        case, evidence = await _image_evidence(db_conn, tmp_path, kind="kape")
        with pytest.raises(ValueError, match="not a disk image"):
            await supertimeline_service.prepare_job(db_conn, case.id, evidence.evidence_number, mode="bodyfile")

    @pytest.mark.asyncio
    async def test_failed_job_imports_what_exists(self, db_conn, tmp_path, monkeypatch):
        from defair.services import supertimeline_service

        monkeypatch.setenv("DEFAIR_WORKSPACE", str(tmp_path / "ws"))
        case, evidence = await _image_evidence(db_conn, tmp_path)
        job = await supertimeline_service.prepare_job(db_conn, case.id, evidence.evidence_number, mode="both")
        storage = Path(job["plan"]["plaso"]["storage"])
        storage.write_bytes(b"half written")
        _finish_job(job["run_number"], tmp_path / "ws", {
            "state": "failed", "error": "step log2timeline failed (exit 1)",
            "steps": [{"name": "log2timeline", "state": "failed", "stderr_tail": "no space"},
                      {"name": "mmls", "state": "completed"}, {"name": "fls[0]", "state": "completed"}]},
            events=False)
        result = await supertimeline_service.import_job(db_conn, job["run_number"])
        assert result["state"] == "failed" and "plaso" not in result["events"] and result["events"]["tsk"]
        assert not storage.exists()  # a half-built storage is never reused
        cursor = await db_conn.execute("SELECT status, stderr FROM tool_runs WHERE run_number = ?",
                                       (job["run_number"],))
        status, stderr = await cursor.fetchone()
        assert status == "failed" and "no space" in stderr

    @pytest.mark.asyncio
    async def test_unallocated_strings_registered(self, db_conn, tmp_path, monkeypatch):
        from defair.services import supertimeline_service

        monkeypatch.setenv("DEFAIR_WORKSPACE", str(tmp_path / "ws"))
        case, evidence = await _image_evidence(db_conn, tmp_path)
        job = await supertimeline_service.prepare_job(db_conn, case.id, evidence.evidence_number, mode="unallocated")
        assert [s["name"] for s in json.loads(Path(job["job"]).read_text())["steps"]] == ["mmls", "blkls"]
        tsv = tmp_path / "ws" / "strings" / "EVD-001" / "unallocated-0.tsv"
        tsv.parent.mkdir(parents=True)
        tsv.write_text("5\tascii\trclone copy\n")
        _finish_job(job["run_number"], tmp_path / "ws", {"state": "completed", "steps": [
            {"name": "blkls[0]", "state": "completed", "strings": {"tsv": str(tsv), "strings": 1, "sha256": "x"}}]},
            events=False, bodyfile=False)
        result = await supertimeline_service.import_job(db_conn, job["run_number"])
        assert result["strings"] == 1 and result["strings_indexes"][0]["artifact"].startswith("ART-")
        from defair.services import watchlist_service

        report = await watchlist_service.search_watchlist(db_conn, case.id, terms=["rclone"], scopes=["strings"])
        assert report["total_hits"] == 1

    @pytest.mark.asyncio
    async def test_replay_restores_events(self, db_conn, tmp_path, monkeypatch):
        from defair.services import normalization_service, supertimeline_service

        monkeypatch.setenv("DEFAIR_WORKSPACE", str(tmp_path / "ws"))
        case, evidence = await _image_evidence(db_conn, tmp_path)
        job = await supertimeline_service.prepare_job(db_conn, case.id, evidence.evidence_number, mode="bodyfile")
        _finish_job(job["run_number"], tmp_path / "ws", {"state": "completed", "steps": [
            {"name": "fls[0]", "state": "completed"}]}, events=False)
        imported = await supertimeline_service.import_job(db_conn, job["run_number"])
        count = imported["events"]["tsk"]
        await db_conn.execute("DELETE FROM timeline_events")
        await db_conn.commit()
        replayed = await normalization_service.replay(db_conn, case.id)
        assert replayed["timeline_events_restored"] == count
        cursor = await db_conn.execute("SELECT COUNT(*) FROM timeline_events_fts WHERE timeline_events_fts MATCH ?",
                                       ('"ProgramData"',))
        assert (await cursor.fetchone())[0] > 0


class TestTimelineExport:
    @pytest.mark.asyncio
    async def test_streamed_merge_in_time_order(self, db_conn, tmp_path, monkeypatch):
        from defair.normalizers.pipeline import bulk_insert, enrich, new_stats
        from defair.services import supertimeline_service, timeline_service

        monkeypatch.setenv("DEFAIR_WORKSPACE", str(tmp_path / "ws"))
        case, evidence = await _image_evidence(db_conn, tmp_path)
        job = await supertimeline_service.prepare_job(db_conn, case.id, evidence.evidence_number, mode="bodyfile")
        _finish_job(job["run_number"], tmp_path / "ws", {"state": "completed", "steps": []}, events=False)
        await supertimeline_service.import_job(db_conn, job["run_number"])
        run = {"id": job["run_id"], "run_number": job["run_number"], "case_id": case.id, "tool_name": "x"}
        art = enrich({"artifact_type": "windows.evtx.logon", "timestamp": "2024-12-01T08:00:00Z",
                      "description": "logon", "artifact_number": "ART-900", "record_key": "k"},
                     run, new_stats(), set())
        await bulk_insert(db_conn, [art])
        out = tmp_path / "t.jsonl"
        result = await timeline_service.export_timeline(db_conn, case.id, "timesketch", str(out))
        rows = [json.loads(line) for line in out.read_text().splitlines()]
        assert result["count"] == len(rows) > 1
        times = [r["datetime"] for r in rows]
        assert times == sorted(times)
        assert any(r.get("artifact_number") == "ART-900" for r in rows)
        only_events = await timeline_service.export_timeline(db_conn, case.id, "csv", str(tmp_path / "t.csv"),
                                                             sources="tsk")
        assert only_events["count"] == result["count"] - 1

    @pytest.mark.asyncio
    async def test_unknown_source(self, db_conn):
        from defair.services import case_service, timeline_service

        case = await case_service.create_case(db_conn, "x")
        with pytest.raises(ValueError, match="source"):
            await timeline_service.search_timeline(db_conn, case.id, sources="nope")


# ---------------------------------------------------------------------------
# Interfaces
# ---------------------------------------------------------------------------


class TestInterfaces:
    @pytest.mark.asyncio
    async def test_host_start_chains_prepare_and_job(self):
        from defair.services import supertimeline_host

        exec_result = {"exit_code": 0, "stderr": "", "stdout": json.dumps(
            {"run_number": "RUN-005", "worker": "plaso", "plan": {}})}
        with patch.object(supertimeline_host.container_service, "exec_in_container",
                          AsyncMock(return_value=exec_result)) as exec_, \
             patch.object(supertimeline_host.worker_service, "start_job",
                          AsyncMock(return_value={"job": "j"})) as start:
            result = await supertimeline_host.start("c", "CASE-1", "EVD-001", WORKERS, mode="both",
                                                    parsers="win7", overwrite=True)
        argv = exec_.call_args.args[1]
        assert argv[:3] == ["defair", "supertimeline", "prepare"] and "--overwrite" in argv
        assert ["--mode", "both", "--workers", "2"] == argv[argv.index("--mode"):][:4]
        assert start.call_args.args[:3] == ("c", "plaso", "RUN-005")
        assert result["run_number"] == "RUN-005" and result["job"] == {"job": "j"}

    @pytest.mark.asyncio
    async def test_host_status_imports_when_done(self):
        from defair.services import supertimeline_host

        with patch.object(supertimeline_host.worker_service, "job_status",
                          AsyncMock(return_value={"state": "completed"})), \
             patch.object(supertimeline_host.worker_service, "remove_job", AsyncMock()) as remove, \
             patch.object(supertimeline_host.container_service, "exec_in_container", AsyncMock(
                 return_value={"exit_code": 0, "stderr": "", "stdout": '{"imported": true}'})) as exec_:
            result = await supertimeline_host.status("c", "RUN-005")
        assert exec_.call_args.args[1] == ["defair", "supertimeline", "import", "RUN-005"]
        assert result["import"] == {"imported": True}
        remove.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_mcp_tools(self):
        from defair.mcp_server import server

        with patch("defair.services.supertimeline_host.start", AsyncMock(return_value={"run_number": "RUN-5"})) as start:
            result = await server.mcp.call_tool("build_supertimeline", {
                "container": "c", "case_id": "CASE-1", "evidence_id": "EVD-001", "mode": "all"})
        assert "RUN-5" in result.content[0].text and start.call_args.kwargs["mode"] == "all"
        with patch("defair.mcp_server.server.container_service") as cs:
            cs.exec_in_container = AsyncMock(return_value={"exit_code": 0, "stdout": "[]", "stderr": ""})
            await server.mcp.call_tool("search_timeline", {"container": "c", "case_id": "C", "sources": "plaso",
                                                           "parser": "winevtx"})
            argv = cs.exec_in_container.call_args.args[1]
        assert ["--sources", "plaso"] == argv[argv.index("--sources"):][:2] and argv[-1] == "--json"

    def test_host_commands_refused_inside_container(self):
        from click.testing import CliRunner

        from defair.cli.main import cli

        with patch("defair.cli.main._is_inside_container", return_value=True):
            result = CliRunner().invoke(cli, ["supertimeline", "jobs"])
        assert result.exit_code == 2 and "host" in result.output


def test_schema_v5(tmp_path):
    import asyncio

    from defair.database import SCHEMA_VERSION, get_initialized_connection

    async def run():
        conn = await get_initialized_connection(tmp_path / "db.sqlite")
        cursor = await conn.execute("SELECT name FROM sqlite_master WHERE name LIKE 'timeline_events%'")
        names = {r[0] for r in await cursor.fetchall()}
        await conn.close()
        return names

    assert SCHEMA_VERSION >= 5
    assert {"timeline_events", "timeline_events_fts"} <= asyncio.run(run())
