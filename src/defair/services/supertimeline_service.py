"""Supertimeline — Plaso + Sleuth Kit jobs, prepared and imported in the case container.

The job itself runs in the ``worker-plaso`` image, started by the host (see
``worker_service``). This module holds everything that needs the case
database:

- ``prepare_job``: reserves a ``RUN-NNN`` ToolRun, decides what to (re)build
  and writes ``/workspace/jobs/<RUN>/job.json`` (argv lists only):

  * ``plaso``: ``log2timeline`` into ``/workspace/plaso/<EVD>.plaso``, then
    ``psort -o json_line``. The storage lives outside the run directory and is
    **reused** when it was built from the same evidence (hash) with the same
    parsers and time zone and its SHA-256 still matches — only psort runs
    again. A storage built differently is refused unless ``overwrite``;
  * ``bodyfile`` (disk images): ``mmls`` → ``fls -r -m`` per partition, the
    filesystem type tried explicitly (``-f ntfs``, ``fat``…);
  * ``unallocated``: ``blkls`` per partition streamed into the strings
    extractor (``/workspace/strings/<EVD>/unallocated-<n>.tsv``);

- ``import_job``: once the job has finished, streams the events into
  ``timeline_events`` (no ART-NNN, bounded memory), registers the strings
  index, records versions / hashes / reuse in the ToolRun and in
  ``/workspace/jobs/<RUN>/manifest.json``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import aiosqlite
import structlog

log = structlog.get_logger(component="supertimeline")

MODES = ("plaso", "bodyfile", "both", "unallocated", "all")
FS_TYPES = ["ntfs", "fat", "exfat", "ext", "hfs", "iso9660"]
TOOL_NAME = "supertimeline"
PSORT_TIMEOUT = 6 * 3600


def workspace() -> Path:
    from defair.orchestrator.runs import workspace as ws

    return ws()


def plaso_paths(evidence_number: str) -> tuple[Path, Path]:
    base = workspace() / "plaso"
    return base / f"{evidence_number}.plaso", base / f"{evidence_number}.meta.json"


def job_dir(run_number: str) -> Path:
    return workspace() / "jobs" / run_number


def _steps_for(mode: str) -> set[str]:
    return {"plaso": {"plaso"}, "bodyfile": {"bodyfile"}, "both": {"plaso", "bodyfile"},
            "unallocated": {"unallocated"}, "all": {"plaso", "bodyfile", "unallocated"}}[mode]


def _read_meta(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def storage_decision(storage: Path, meta_path: Path, wanted: dict, overwrite: bool) -> dict:
    """Reuse, build or refuse the Plaso storage of an evidence.

    Returns:
        ``{"reuse": bool, "reason": str}``

    Raises:
        ValueError: A storage built differently exists and ``overwrite`` is off.
    """
    from defair.normalizers.pipeline import sha256_file

    if overwrite or not storage.exists():
        return {"reuse": False, "reason": "overwrite requested" if storage.exists() else "no storage yet"}
    meta = _read_meta(meta_path)
    if meta is None:
        raise ValueError(f"{storage.name} exists without its metadata ({meta_path.name}): "
                         "rebuild it with --overwrite")
    different = {k: (meta.get(k), v) for k, v in wanted.items() if meta.get(k) != v}
    if different:
        details = ", ".join(f"{k}: stored {old!r} ≠ requested {new!r}" for k, (old, new) in different.items())
        raise ValueError(f"{storage.name} was built differently ({details}); use --overwrite to rebuild it")
    if meta.get("sha256") and sha256_file(storage) != meta["sha256"]:
        raise ValueError(f"{storage.name} does not match its recorded SHA-256; use --overwrite to rebuild it")
    return {"reuse": True, "reason": f"built {meta.get('built_at')} by {meta.get('run_number')}"}


async def prepare_job(
    conn: aiosqlite.Connection,
    case_id: str,
    evidence_id: str,
    mode: str = "plaso",
    parsers: str | None = None,
    timezone: str | None = None,
    overwrite: bool = False,
    psort_filter: str | None = None,
    workers: int = 4,
    worker: str = "plaso",
) -> dict:
    """Reserve the run and write the job spec (see module docstring)."""
    from defair.models.tool_run import ToolRunStatus
    from defair.orchestrator.steps import dissect_target
    from defair.services.analysis_service import _reserve_tool_run, _save_tool_run
    from defair.services.case_service import resolve_case_id
    from defair.services.evidence_service import get_evidence
    from defair.sources.prepare import prepare_evidence

    if mode not in MODES:
        raise ValueError(f"Unknown mode '{mode}'. Use one of: {', '.join(MODES)}")
    case_id = await resolve_case_id(conn, case_id)
    evidence = await get_evidence(conn, evidence_id)
    if evidence is None or evidence.case_id != case_id:
        raise ValueError(f"Evidence {evidence_id} not found in this case")
    prepared = evidence.prepared or await prepare_evidence(conn, evidence.id)
    source_kind = (prepared.get("source") or {}).get("kind")
    is_image = source_kind == "disk_image"
    wanted = _steps_for(mode)
    if wanted & {"bodyfile", "unallocated"} and not is_image:
        raise ValueError(
            f"{evidence.evidence_number} is a {prepared.get('kind')} collection, not a disk image: "
            "the Sleuth Kit needs the image (for a collection, the $MFT timeline comes from MFTECmd)")
    target = dissect_target(prepared)
    image = prepared.get("target") if is_image else None

    tool_run = await _reserve_tool_run(conn, TOOL_NAME, case_id, evidence.id)
    run = tool_run.run_number
    rundir = job_dir(run)
    rundir.mkdir(parents=True, exist_ok=True)
    (rundir / "tmp").mkdir(exist_ok=True)

    steps: list[dict] = []
    hashes: list[str] = []
    plan: dict = {"mode": mode, "target": target, "evidence": evidence.evidence_number}

    if "plaso" in wanted:
        storage, meta_path = plaso_paths(evidence.evidence_number)
        storage.parent.mkdir(parents=True, exist_ok=True)
        params = {"evidence_sha256": evidence.sha256, "parsers": parsers or "auto",
                  "timezone": timezone or "UTC", "target": target}
        try:
            decision = storage_decision(storage, meta_path, params, overwrite)
        except ValueError:
            tool_run.status = ToolRunStatus.FAILED
            tool_run.completed_at = datetime.now(UTC)
            await _save_tool_run(conn, tool_run)
            raise
        if not decision["reuse"] and storage.exists():
            storage.unlink()
            meta_path.unlink(missing_ok=True)
        l2t = ["log2timeline", "--storage_file", str(storage), "--status_view", "none", "--unattended",
               "--vss_stores", "none", "--partitions", "all", "--volumes", "all", "--workers", str(workers),
               "--temporary_directory", str(rundir / "tmp"), "--logfile", str(rundir / "log2timeline.log.gz"),
               "--timezone", params["timezone"]]
        if parsers:
            l2t += ["--parsers", parsers]
        steps.append({"name": "log2timeline", "argv": [*l2t, target], "skip": decision["reuse"],
                      "skip_reason": decision["reason"] if decision["reuse"] else ""})
        psort = ["psort", "-o", "json_line", "-w", str(rundir / "events.jsonl"), "--status_view", "none",
                 "--unattended", "--output_time_zone", "UTC", "--temporary_directory", str(rundir / "tmp"),
                 "--logfile", str(rundir / "psort.log.gz"), str(storage)]
        if psort_filter:
            psort.append(psort_filter)
        steps.append({"name": "psort", "argv": psort, "timeout": PSORT_TIMEOUT})
        hashes.append(str(storage))
        plan["plaso"] = {"storage": str(storage), "meta": str(meta_path), "params": params,
                         "reused": decision["reuse"], "decision": decision["reason"]}

    if wanted & {"bodyfile", "unallocated"}:
        steps.append({"name": "mmls", "argv": ["mmls", image], "parse": "mmls", "allow_failure": True})
    if "bodyfile" in wanted:
        steps.append({"name": "fls", "for_each": "partition", "try": {"fstype": FS_TYPES},
                      "argv": ["fls", "-r", "-m", "vol{index}:", "-f", "{fstype}", "-o", "{offset}", image],
                      "stdout": str(rundir / "bodyfile-{index}.txt"), "allow_failure": True})
        plan["bodyfile"] = {"image": image}
    if "unallocated" in wanted:
        strings_dir = workspace() / "strings" / evidence.evidence_number
        steps.append({"name": "blkls", "for_each": "partition", "try": {"fstype": FS_TYPES},
                      "argv": ["blkls", "-f", "{fstype}", "-o", "{offset}", image],
                      "strings_to": str(strings_dir / "unallocated-{index}.tsv"),
                      "min_length": 6, "allow_failure": True})
        plan["unallocated"] = {"image": image, "strings_dir": str(strings_dir)}

    spec = {"run_number": run, "worker": worker, "created_at": datetime.now(UTC).isoformat(),
            "case_id": case_id, "evidence_id": evidence.id, "steps": steps, "hash": hashes, "plan": plan}
    (rundir / "job.json").write_text(json.dumps(spec, indent=2))
    tool_run.parameters = {"mode": mode, "parsers": parsers, "timezone": timezone or "UTC",
                           "overwrite": overwrite, "psort_filter": psort_filter, "worker": worker,
                           "input_path": target, "job": str(rundir / "job.json"), "plan": plan}
    tool_run.output_path = str(rundir)
    await _save_tool_run(conn, tool_run)
    log.info("supertimeline_prepared", run=run, mode=mode, evidence=evidence.evidence_number,
             reuse=plan.get("plaso", {}).get("reused"))
    return {"run_number": run, "run_id": tool_run.id, "worker": worker, "job": str(rundir / "job.json"),
            "mode": mode, "plan": plan, "steps": [s["name"] for s in steps]}


def read_status(run_number: str) -> dict:
    try:
        return json.loads((job_dir(run_number) / "status.json").read_text())
    except (OSError, ValueError):
        return {}


async def _tool_run(conn, run_number: str) -> dict:
    cursor = await conn.execute("SELECT * FROM tool_runs WHERE (run_number = ? OR id = ?) AND tool_name = ?",
                                (run_number.upper(), run_number, TOOL_NAME))
    row = await cursor.fetchone()
    if row is None:
        raise ValueError(f"Supertimeline run not found: {run_number}")
    return dict(row)


async def job_state(conn: aiosqlite.Connection, run_number: str) -> dict:
    """What the case container knows: runner status + import state."""
    run = await _tool_run(conn, run_number)
    stats = json.loads(run.get("normalization_stats") or "{}")
    status = read_status(run["run_number"])
    return {"run_number": run["run_number"], "tool_run_status": run["status"],
            "runner_state": status.get("state"), "imported": bool(stats.get("imported_at")),
            "steps": [{k: s.get(k) for k in ("name", "state", "exit_code", "duration_seconds")}
                      for s in status.get("steps", [])],
            "events": stats.get("events"), "error": status.get("error")}


async def import_job(conn: aiosqlite.Connection, run_number: str, force: bool = False) -> dict:
    """Import a finished job's outputs into the case (idempotent)."""
    from defair.normalizers.bodyfile import iter_bodyfile
    from defair.normalizers.pipeline import stream_timeline_events
    from defair.normalizers.plaso import iter_plaso
    from defair.services.analysis_service import _save_artifact

    run = await _tool_run(conn, run_number)
    stats = json.loads(run.get("normalization_stats") or "{}")
    if stats.get("imported_at") and not force:
        return {"run_number": run["run_number"], "already_imported": True, **stats}
    status = read_status(run["run_number"])
    state = status.get("state")
    if state not in ("completed", "failed", "cancelled"):
        return {"run_number": run["run_number"], "state": state or "not started", "imported": False}

    rundir = job_dir(run["run_number"])
    spec = json.loads((rundir / "job.json").read_text())
    plan = spec.get("plan", {})
    start = _read_meta(rundir / "start.json") or {}
    versions = status.get("versions") or {}
    plaso_version = (versions.get("plaso") or {}).get("version")
    ctx = {"id": run["id"], "run_number": run["run_number"], "case_id": run["case_id"],
           "evidence_id": run["evidence_id"], "tool_name": TOOL_NAME,
           "tool_version": plaso_version}
    steps = {s["name"]: s for s in status.get("steps", [])}
    result: dict = {"events": {}, "strings": [], "files": []}

    if plan.get("plaso") and not plan["plaso"].get("reused") \
            and steps.get("log2timeline", {}).get("state") != "completed":
        # a half-built storage must never be reused
        Path(plan["plaso"]["storage"]).unlink(missing_ok=True)
    events_file = rundir / "events.jsonl"
    if plan.get("plaso") and steps.get("psort", {}).get("state") == "completed" and events_file.exists():
        imported = await stream_timeline_events(
            conn, ctx, iter_plaso(events_file), "plaso", _normalized(run["run_number"], "plaso"))
        result["events"]["plaso"] = imported["normalized"]
        result["files"] += imported["files"]
        result["plaso_stats"] = {k: v for k, v in imported.items() if k != "files"}
        _write_meta(plan["plaso"], run["run_number"], status, plaso_version)

    partitions = {p["index"]: p for p in status.get("partitions", [])}
    bodyfiles = sorted(rundir.glob("bodyfile-*.txt"))
    if bodyfiles:
        def all_bodyfiles():
            for path in bodyfiles:
                index = int(path.stem.rsplit("-", 1)[-1])
                yield from iter_bodyfile(path, partitions.get(index, {"index": index, "offset": 0}))

        imported = await stream_timeline_events(
            conn, ctx, all_bodyfiles(), "tsk", _normalized(run["run_number"], "tsk"))
        result["events"]["tsk"] = imported["normalized"]
        result["files"] += imported["files"]

    for step in status.get("steps", []):
        info = step.get("strings")
        if info and step.get("state") == "completed":
            number = await _save_artifact(conn, {
                "case_id": run["case_id"], "evidence_id": run["evidence_id"],
                "artifact_type": "windows.strings.extract", "category": "other",
                "source_tool": "blkls", "source_file": plan.get("unallocated", {}).get("image", ""),
                "description": f"{info['strings']} strings from unallocated space ({step['name']})",
                "data": {**info, "source": "unallocated", "partition": step.get("partition")},
                "provenance": {"tool": "blkls", "run_number": run["run_number"]},
                "record_key": f"strings#unallocated#{run['run_number']}#{step['name']}",
            })
            result["strings"].append({**info, "artifact": number})

    run_status = {"completed": "completed", "cancelled": "cancelled"}.get(state, "failed")
    stderr = "\n".join(f"[{s['name']}] {s.get('stderr_tail', '')[-800:]}" for s in status.get("steps", [])
                       if s.get("state") in ("failed", "tolerated"))
    final_stats = {"imported_at": datetime.now(UTC).isoformat(), "events": result["events"],
                   "strings": len(result["strings"]), "runner_state": state, "error": status.get("error"),
                   "files": result["files"], "reused_storage": plan.get("plaso", {}).get("reused")}
    await conn.execute(
        """UPDATE tool_runs SET status = ?, completed_at = ?, tool_version = ?, stderr = ?,
        normalization_stats = ?, output_files = ? WHERE id = ?""",
        (run_status, status.get("completed_at") or datetime.now(UTC).isoformat(), plaso_version,
         (stderr or status.get("error") or "")[:10000], json.dumps(final_stats),
         json.dumps(sorted(p.name for p in rundir.iterdir() if p.is_file())), run["id"]),
    )
    await conn.commit()
    manifest = {"run_number": run["run_number"], "spec": spec, "runner": status, "start": start,
                "import": final_stats, "versions": versions}
    (rundir / "manifest.json").write_text(json.dumps(manifest, indent=2, default=str))
    log.info("supertimeline_imported", run=run["run_number"], state=state, events=result["events"],
             strings=len(result["strings"]))
    return {"run_number": run["run_number"], "state": state, "imported": True, **final_stats,
            "strings_indexes": result["strings"]}


def _normalized(run_number: str, source: str) -> Path:
    return workspace() / "normalized" / "timeline" / source / f"{run_number}.jsonl"


def _write_meta(plaso_plan: dict, run_number: str, status: dict, plaso_version: str | None) -> None:
    storage = plaso_plan["storage"]
    sha = (status.get("hashes") or {}).get(storage)
    meta_path = Path(plaso_plan["meta"])
    if plaso_plan.get("reused"):
        return  # the storage did not change: its metadata stays as built
    meta = {**plaso_plan["params"], "sha256": sha, "built_at": status.get("completed_at"),
            "run_number": run_number, "plaso_version": plaso_version}
    meta_path.write_text(json.dumps(meta, indent=2))
