"""Supertimeline orchestration on the HOST (shared by the CLI and the MCP).

1. ``defair supertimeline prepare`` runs in the case container (it owns the
   database): run reserved, job spec written;
2. the host starts the ``worker-plaso`` job (``worker_service.start_job``);
3. ``status`` follows the job and, once it has exited, runs
   ``defair supertimeline import`` in the case container.
"""

from __future__ import annotations

import json

from defair.config import ContainerConfig, WorkerConfig
from defair.services import container_service, worker_service


async def _exec_json(container: str, args: list[str]) -> dict:
    result = await container_service.exec_in_container(container, ["defair", *args])
    if result["exit_code"] != 0:
        raise RuntimeError((result.get("stderr") or result.get("stdout") or "command failed").strip()[-2000:])
    try:
        return json.loads(result["stdout"])
    except ValueError as e:
        raise RuntimeError(f"Unexpected output of `defair {' '.join(args[:2])}`: {result['stdout'][:500]}") from e


async def start(
    container: str,
    case_id: str,
    evidence_id: str,
    workers: dict[str, WorkerConfig],
    policy: ContainerConfig | None = None,
    mode: str = "plaso",
    parsers: str | None = None,
    timezone: str | None = None,
    overwrite: bool = False,
    psort_filter: str | None = None,
) -> dict:
    """Prepare the run in the case container, then start the worker job."""
    worker = workers.get("plaso")
    args = ["supertimeline", "prepare", "--case", case_id, "--evidence", evidence_id, "--mode", mode,
            "--workers", str(int(worker.cpus) if worker else 4)]
    for flag, value in (("--parsers", parsers), ("--timezone", timezone), ("--filter", psort_filter)):
        if value:
            args.extend([flag, value])
    if overwrite:
        args.append("--overwrite")
    prepared = await _exec_json(container, args)
    started = await worker_service.start_job(container, prepared["worker"], prepared["run_number"],
                                             workers, policy)
    return {**prepared, "job": started}


async def status(container: str, run_number: str, auto_import: bool = True) -> dict:
    """Job state; imports the results into the case once the job has finished."""
    job = await worker_service.job_status(container, run_number)
    result = {**job}
    if job["state"] in ("completed", "failed", "cancelled") and auto_import:
        imported = await _exec_json(container, ["supertimeline", "import", run_number])
        result["import"] = imported
        if imported.get("imported") or imported.get("already_imported"):
            await worker_service.remove_job(container, run_number)
    return result


async def cancel(container: str, run_number: str) -> dict:
    return await worker_service.cancel_job(container, run_number)


async def jobs(container: str | None = None) -> list[dict]:
    return await worker_service.list_jobs(container)
