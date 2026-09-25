"""Worker jobs — dedicated worker images run next to a case container.

Heavy engines (Plaso + Sleuth Kit today; malware, memory and carving tools
later) live in their own images, pulled from GHCR, not in the main one. The
case container cannot start containers (no Docker socket inside), so the
HOST starts a short-lived job container per request:

- the job is described by ``/workspace/jobs/<RUN>/job.json``, written by the
  case container (``defair supertimeline prepare``): argv lists only, never
  a shell;
- the job container gets exactly the case container's evidence (read-only,
  same paths) and workspace mounts — never ``/keys`` — and the same
  hardening (no network, every capability dropped, read-only rootfs, host
  user, resource limits from ``workers.<name>`` in the config);
- its runner (``python -m defair.workers.entry``) writes
  ``/workspace/jobs/<RUN>/status.json`` after every step, and logs to the
  shared ``/workspace/logs/defair.log`` (so ``docker logs`` of the case
  container shows the job too);
- the case container imports the results once the job has exited.

This module runs on the HOST (Docker SDK).
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import docker.errors
import structlog

from defair.config import ContainerConfig, WorkerConfig
from defair.services.container_service import (
    DEFAIR_CASE_LABEL,
    DEFAIR_LABEL,
    _get_client,
    hardening_kwargs,
    validate_image,
)

log = structlog.get_logger(component="worker_service")

JOB_LABEL = "defair.job"
JOB_RUN_LABEL = "defair.run"
JOB_PARENT_LABEL = "defair.parent"
JOB_WORKER_LABEL = "defair.worker"
JOB_ENTRY = ["python3", "-m", "defair.workers.entry"]


def job_name(case_container: str, run_number: str) -> str:
    return f"{case_container}-job-{run_number.lower()}"


def job_dir(workspace: Path, run_number: str) -> Path:
    return workspace / "jobs" / run_number


def _case_mounts(case) -> tuple[dict, Path]:
    """Volumes of the case container a job may reuse, and its host workspace."""
    volumes: dict = {}
    workspace = None
    for mount in case.attrs.get("Mounts", []):
        destination = mount.get("Destination", "")
        source = mount.get("Source", "")
        if destination == "/workspace":
            workspace = Path(source)
            volumes[source] = {"bind": "/workspace", "mode": "rw"}
        elif destination == "/evidence" or destination.startswith("/evidence/"):
            volumes[source] = {"bind": destination, "mode": "ro"}
        # /keys and anything else stay with the case container only
    if workspace is None:
        label = (case.labels or {}).get("defair.workspace")
        if not label:
            raise RuntimeError(f"Container {case.name} has no /workspace mount")
        workspace = Path(label)
        volumes[str(workspace)] = {"bind": "/workspace", "mode": "rw"}
    return volumes, workspace


def job_kwargs(worker: WorkerConfig, policy: ContainerConfig) -> dict:
    """Hardening of the case container, with the worker's own resource limits."""
    tuned = policy.model_copy(update={
        "mem_limit": worker.mem_limit, "cpus": worker.cpus, "pids_limit": worker.pids_limit,
        "tmpfs_size": worker.tmpfs_size,
    })
    kwargs = hardening_kwargs(tuned)
    # a job never talks to the network, whatever the case container allows
    kwargs["network_mode"] = "none"
    return kwargs


async def start_job(
    case_container: str,
    worker_name: str,
    run_number: str,
    workers: dict[str, WorkerConfig],
    policy: ContainerConfig | None = None,
) -> dict:
    """Start the job described by ``/workspace/jobs/<RUN>/job.json``.

    Returns:
        ``{"job": container name, "image": …, "run_number": …}``
    """
    policy = policy or ContainerConfig()
    if worker_name not in workers:
        raise ValueError(f"Unknown worker '{worker_name}'. Configured: {', '.join(sorted(workers))}")
    worker = workers[worker_name]
    validate_image(worker.image, policy)
    if worker.image.endswith(":latest") or ":" not in worker.image.rsplit("/", 1)[-1]:
        raise ValueError(f"Worker image '{worker.image}' must be pinned by a version tag")

    def _start() -> dict:
        client = _get_client()
        case = client.containers.get(case_container)
        volumes, workspace = _case_mounts(case)
        spec = job_dir(workspace, run_number) / "job.json"
        if not spec.is_file():
            raise FileNotFoundError(f"No job spec at {spec} (run `supertimeline prepare` first)")
        name = job_name(case_container, run_number)
        try:
            client.containers.get(name).remove(force=True)  # a previous attempt of the same run
        except docker.errors.NotFound:
            pass
        try:
            client.images.get(worker.image)
        except docker.errors.ImageNotFound:
            log.info("pulling_worker_image", image=worker.image)
            client.images.pull(worker.image)
        labels = {
            DEFAIR_LABEL: "true",
            JOB_LABEL: "true",
            JOB_RUN_LABEL: run_number,
            JOB_PARENT_LABEL: case_container,
            JOB_WORKER_LABEL: worker_name,
            "defair.workspace": str(workspace),
        }
        case_id = (case.labels or {}).get(DEFAIR_CASE_LABEL)
        if case_id:
            labels[DEFAIR_CASE_LABEL] = case_id
        container = client.containers.run(
            image=worker.image,
            name=name,
            command=[*JOB_ENTRY, f"/workspace/jobs/{run_number}/job.json"],
            labels=labels,
            volumes=volumes,
            environment={"HOME": "/tmp", "DEFAIR_WORKSPACE": "/workspace",
                         "DEFAIR_JOB_TIMEOUT": str(worker.timeout)},
            detach=True,
            **job_kwargs(worker, policy),
        )
        image_id = getattr(container.image, "id", None)
        started = {"job": name, "image": worker.image, "image_id": image_id,
                   "repo_digests": list(getattr(container.image, "attrs", {}).get("RepoDigests") or []),
                   "run_number": run_number, "worker": worker_name,
                   "started_at": datetime.now(UTC).isoformat()}
        # recorded next to the spec: the import puts it in the run manifest
        (job_dir(workspace, run_number) / "start.json").write_text(json.dumps(started, indent=2))
        log.info("worker_job_started", job=name, image=worker.image, image_id=image_id,
                 run=run_number, case_container=case_container)
        return started

    return await asyncio.to_thread(_start)


def read_status(workspace: Path, run_number: str) -> dict:
    try:
        return json.loads((job_dir(workspace, run_number) / "status.json").read_text())
    except (OSError, ValueError):
        return {}


async def job_status(case_container: str, run_number: str) -> dict:
    """Docker state of the job + the runner's ``status.json``."""

    def _status() -> dict:
        client = _get_client()
        case = client.containers.get(case_container)
        _, workspace = _case_mounts(case)
        status = read_status(workspace, run_number)
        result = {"run_number": run_number, "job": job_name(case_container, run_number),
                  "runner": status}
        try:
            container = client.containers.get(job_name(case_container, run_number))
            state = container.attrs.get("State", {})
            result.update(container=container.status, exit_code=state.get("ExitCode"),
                          finished_at=state.get("FinishedAt"), image=container.labels.get(
                              "org.opencontainers.image.version") or str(container.image.tags[:1]))
        except docker.errors.NotFound:
            result["container"] = "removed" if status else "missing"
        runner_state = status.get("state")
        if result["container"] in ("running", "created", "restarting"):
            result["state"] = "running"
        elif runner_state in ("completed", "failed", "cancelled"):
            result["state"] = runner_state
        elif result["container"] == "exited":
            result["state"] = "failed" if result.get("exit_code") else runner_state or "failed"
        else:
            result["state"] = runner_state or "unknown"
        return result

    return await asyncio.to_thread(_status)


async def cancel_job(case_container: str, run_number: str) -> dict:
    """Stop a running job (SIGTERM: the runner kills its tool and records it)."""

    def _cancel() -> dict:
        client = _get_client()
        try:
            container = client.containers.get(job_name(case_container, run_number))
        except docker.errors.NotFound:
            return {"run_number": run_number, "cancelled": False, "reason": "no such job"}
        container.stop(timeout=30)
        return {"run_number": run_number, "cancelled": True}

    return await asyncio.to_thread(_cancel)


async def remove_job(case_container: str, run_number: str) -> None:
    """Remove a finished job container (its outputs stay in the workspace)."""

    def _remove() -> None:
        client = _get_client()
        try:
            client.containers.get(job_name(case_container, run_number)).remove(force=True)
        except docker.errors.NotFound:
            pass

    await asyncio.to_thread(_remove)


async def list_jobs(case_container: str | None = None) -> list[dict]:
    def _list() -> list[dict]:
        client = _get_client()
        filters = {"label": [f"{JOB_LABEL}=true"]}
        if case_container:
            filters["label"].append(f"{JOB_PARENT_LABEL}={case_container}")
        return [{"job": c.name, "status": c.status, "run_number": c.labels.get(JOB_RUN_LABEL),
                 "worker": c.labels.get(JOB_WORKER_LABEL), "case_container": c.labels.get(JOB_PARENT_LABEL)}
                for c in client.containers.list(all=True, filters=filters)]

    return await asyncio.to_thread(_list)
