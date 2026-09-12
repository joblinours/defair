"""Container service — Docker orchestration for forensic investigations.

Manages DEFAIR forensic containers: one container per case/investigation.
Evidence is mounted read-only, workspace is persistent.

This runs on the HOST and communicates with Docker via the Docker SDK.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path

import docker
import docker.errors
import structlog

log = structlog.get_logger(component="container_service")

# DEFAIR label for identifying managed containers
DEFAIR_LABEL = "defair.managed"
DEFAIR_CASE_LABEL = "defair.case_id"
DEFAIR_CONTAINER_PREFIX = "defair-"
DEFAULT_IMAGE = "ghcr.io/joblinours/defair:latest"
WORKSPACE_BASE = Path.home() / ".defair" / "workspaces"


@dataclass
class ContainerInfo:
    """Represents a DEFAIR-managed container."""

    name: str
    container_id: str
    status: str  # created, running, paused, restarting, removing, exited, dead
    image: str
    case_id: str | None = None
    workspace: str | None = None
    evidence_mounts: list[str] = field(default_factory=list)
    created: str | None = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "container_id": self.container_id,
            "status": self.status,
            "image": self.image,
            "case_id": self.case_id,
            "workspace": self.workspace,
            "evidence_mounts": self.evidence_mounts,
            "created": self.created,
        }


def _get_client() -> docker.DockerClient:
    """Get a Docker client connected to the local daemon."""
    try:
        client = docker.from_env()
        client.ping()
        return client
    except docker.errors.DockerException as e:
        raise ConnectionError(
            f"Cannot connect to Docker daemon. Is Docker running? {e}"
        ) from e


def _container_to_info(container) -> ContainerInfo:
    """Convert a Docker container object to ContainerInfo."""
    labels = container.labels or {}
    mounts = []
    for mount in container.attrs.get("Mounts", []):
        if mount.get("Mode") == "ro":
            mounts.append(mount.get("Source", ""))

    return ContainerInfo(
        name=container.name,
        container_id=container.short_id,
        status=container.status,
        image=str(container.image.tags[0] if container.image.tags else container.image.short_id),
        case_id=labels.get(DEFAIR_CASE_LABEL),
        workspace=labels.get("defair.workspace"),
        evidence_mounts=mounts,
        created=container.attrs.get("Created", ""),
    )


async def create_container(
    case_id: str | None = None,
    name: str | None = None,
    image: str = DEFAULT_IMAGE,
    evidence_paths: list[str] | None = None,
    workspace: str | None = None,
    ports: dict[str, int] | None = None,
    env: dict[str, str] | None = None,
) -> ContainerInfo:
    """Create a new DEFAIR forensic container.

    Args:
        case_id: Case number or ID to associate (e.g. "CASE-2026-001").
        name: Container name. Auto-generated from case_id if not provided.
        image: Docker image to use (default: ghcr.io/joblinours/defair:latest).
        evidence_paths: List of host paths to mount as read-only evidence.
        workspace: Custom workspace path. Default: ~/.defair/workspaces/<name>/
        ports: Port mappings {container_port: host_port}.
        env: Environment variables to set in the container.

    Returns:
        ContainerInfo with the created container details.
    """

    def _create() -> ContainerInfo:
        client = _get_client()

        # Generate container name
        container_name = name
        if not container_name:
            if case_id:
                # CASE-2026-001 → defair-case-2026-001
                container_name = DEFAIR_CONTAINER_PREFIX + case_id.lower().replace("_", "-")
            else:
                # Auto-generate with timestamp
                import time
                container_name = f"{DEFAIR_CONTAINER_PREFIX}{int(time.time())}"

        # Setup workspace
        ws_path = Path(workspace) if workspace else WORKSPACE_BASE / container_name
        ws_path.mkdir(parents=True, exist_ok=True)

        # Build volume mounts
        volumes = {
            str(ws_path): {"bind": "/workspace", "mode": "rw"},
        }

        # Mount evidence as read-only.
        # Strategy: create a staging directory with symlinks to all evidence files,
        # then mount the ENTIRE /evidence directory as :ro so nothing is writable.
        evidence_list = evidence_paths or []
        if evidence_list:
            staging_dir = ws_path / ".evidence_staging"
            staging_dir.mkdir(parents=True, exist_ok=True)

            for ev_path in evidence_list:
                ev = Path(ev_path).resolve()
                if not ev.exists():
                    raise FileNotFoundError(f"Evidence path not found: {ev}")
                link = staging_dir / ev.name
                if not link.exists():
                    link.symlink_to(ev)

            # Mount the staging dir as /evidence — entirely read-only
            volumes[str(staging_dir)] = {"bind": "/evidence", "mode": "ro"}

        # Labels for identification
        labels = {
            DEFAIR_LABEL: "true",
            "defair.workspace": str(ws_path),
        }
        if case_id:
            labels[DEFAIR_CASE_LABEL] = case_id

        # Port bindings
        port_bindings = None
        if ports:
            port_bindings = {f"{cp}/tcp": hp for cp, hp in ports.items()}

        # Environment
        environment = {"DEFAIR_DB_PATH": "/workspace/defair.db"}
        if env:
            environment.update(env)

        # Ensure image exists
        try:
            client.images.get(image)
        except docker.errors.ImageNotFound:
            log.info("pulling_image", image=image)
            client.images.pull(image)

        container = client.containers.create(
            image=image,
            name=container_name,
            labels=labels,
            volumes=volumes,
            ports=port_bindings,
            environment=environment,
            stdin_open=True,
            tty=True,
            detach=True,
            command="sleep infinity",  # Keep container alive
        )

        log.info(
            "container_created",
            name=container_name,
            case_id=case_id,
            image=image,
            workspace=str(ws_path),
        )

        return _container_to_info(container)

    return await asyncio.to_thread(_create)


async def list_containers(
    all_states: bool = True,
    case_id: str | None = None,
) -> list[ContainerInfo]:
    """List DEFAIR-managed containers.

    Args:
        all_states: If True, include stopped containers. If False, only running.
        case_id: Filter by case ID/number.
    """

    def _list() -> list[ContainerInfo]:
        client = _get_client()
        filters = {"label": DEFAIR_LABEL}
        containers = client.containers.list(all=all_states, filters=filters)

        results = [_container_to_info(c) for c in containers]

        if case_id:
            results = [c for c in results if c.case_id == case_id]

        return results

    return await asyncio.to_thread(_list)


async def get_container(name_or_id: str) -> ContainerInfo | None:
    """Get details of a specific DEFAIR container.

    Args:
        name_or_id: Container name or ID.
    """

    def _get() -> ContainerInfo | None:
        client = _get_client()

        # Try with defair- prefix if not already
        names_to_try = [name_or_id]
        if not name_or_id.startswith(DEFAIR_CONTAINER_PREFIX):
            names_to_try.append(f"{DEFAIR_CONTAINER_PREFIX}{name_or_id.lower()}")

        for n in names_to_try:
            try:
                container = client.containers.get(n)
                labels = container.labels or {}
                if labels.get(DEFAIR_LABEL) == "true":
                    return _container_to_info(container)
            except docker.errors.NotFound:
                continue

        return None

    return await asyncio.to_thread(_get)


async def start_container(name_or_id: str) -> ContainerInfo:
    """Start a stopped DEFAIR container."""

    def _start() -> ContainerInfo:
        client = _get_client()
        container = _resolve_container(client, name_or_id)
        container.start()
        container.reload()
        log.info("container_started", name=container.name)
        return _container_to_info(container)

    return await asyncio.to_thread(_start)


async def stop_container(name_or_id: str, timeout: int = 10) -> ContainerInfo:
    """Stop a running DEFAIR container.

    Args:
        name_or_id: Container name or ID.
        timeout: Seconds to wait before killing.
    """

    def _stop() -> ContainerInfo:
        client = _get_client()
        container = _resolve_container(client, name_or_id)
        container.stop(timeout=timeout)
        container.reload()
        log.info("container_stopped", name=container.name)
        return _container_to_info(container)

    return await asyncio.to_thread(_stop)


async def remove_container(name_or_id: str, force: bool = False) -> dict:
    """Remove a DEFAIR container.

    Args:
        name_or_id: Container name or ID.
        force: Force removal even if running.

    Returns:
        Dict with name of removed container.
    """

    def _remove() -> dict:
        client = _get_client()
        container = _resolve_container(client, name_or_id)
        container_name = container.name
        container.remove(force=force)
        log.info("container_removed", name=container_name, force=force)
        return {"name": container_name, "removed": True}

    return await asyncio.to_thread(_remove)


async def exec_in_container(
    name_or_id: str,
    command: str | list[str],
    workdir: str | None = None,
    env: dict[str, str] | None = None,
) -> dict:
    """Execute a command inside a running DEFAIR container.

    Args:
        name_or_id: Container name or ID.
        command: Command to run (string or list).
        workdir: Working directory inside the container.
        env: Additional environment variables.

    Returns:
        Dict with exit_code, stdout, stderr.
    """

    def _exec() -> dict:
        client = _get_client()
        container = _resolve_container(client, name_or_id)

        if container.status != "running":
            raise RuntimeError(
                f"Container '{container.name}' is not running (status: {container.status}). "
                "Start it first with 'defair container start'."
            )

        # Build exec command
        if isinstance(command, str):
            exec_cmd = ["sh", "-c", command]
        else:
            exec_cmd = command

        kwargs = {"cmd": exec_cmd, "demux": True}
        if workdir:
            kwargs["workdir"] = workdir
        if env:
            kwargs["environment"] = env

        exit_code, output = container.exec_run(**kwargs)
        stdout_raw, stderr_raw = output if isinstance(output, tuple) else (output, b"")

        stdout = (stdout_raw or b"").decode("utf-8", errors="replace")
        stderr = (stderr_raw or b"").decode("utf-8", errors="replace")

        log.info(
            "container_exec",
            name=container.name,
            command=command if isinstance(command, str) else " ".join(command),
            exit_code=exit_code,
        )

        return {
            "container": container.name,
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
        }

    return await asyncio.to_thread(_exec)


async def container_logs(
    name_or_id: str,
    tail: int = 100,
    follow: bool = False,
) -> str:
    """Get logs from a DEFAIR container.

    Args:
        name_or_id: Container name or ID.
        tail: Number of lines from the end.
    """

    def _logs() -> str:
        client = _get_client()
        container = _resolve_container(client, name_or_id)
        logs = container.logs(tail=tail, follow=False, timestamps=True)
        return logs.decode("utf-8", errors="replace")

    return await asyncio.to_thread(_logs)


def _resolve_container(client: docker.DockerClient, name_or_id: str):
    """Resolve a container name/ID to a Docker container object.

    Tries the exact name first, then with defair- prefix.
    Only returns DEFAIR-managed containers.
    """
    names_to_try = [name_or_id]
    if not name_or_id.startswith(DEFAIR_CONTAINER_PREFIX):
        names_to_try.append(f"{DEFAIR_CONTAINER_PREFIX}{name_or_id.lower()}")

    for n in names_to_try:
        try:
            container = client.containers.get(n)
            labels = container.labels or {}
            if labels.get(DEFAIR_LABEL) != "true":
                raise ValueError(
                    f"Container '{n}' exists but is not managed by DEFAIR."
                )
            return container
        except docker.errors.NotFound:
            continue

    raise ValueError(f"DEFAIR container not found: {name_or_id}")
