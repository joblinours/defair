"""Container service — Docker orchestration for forensic investigations.

Manages DEFAIR forensic containers: one container per case/investigation.
Evidence is mounted read-only, workspace is persistent.

This runs on the HOST and communicates with Docker via the Docker SDK.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from pathlib import Path

import docker.errors
import structlog

import docker
from defair.config import ContainerConfig

log = structlog.get_logger(component="container_service")

# DEFAIR label for identifying managed containers
DEFAIR_LABEL = "defair.managed"
DEFAIR_CASE_LABEL = "defair.case_id"
DEFAIR_CONTAINER_PREFIX = "defair-"
DEFAULT_IMAGE = "ghcr.io/joblinours/defair:latest"
CONTAINER_ENTRY = (
    "mkdir -p /workspace/logs && touch /workspace/logs/defair.log "
    "&& exec tail -n 0 -F /workspace/logs/defair.log"
)
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


def validate_image(image: str, policy: ContainerConfig) -> None:
    """Refuse images outside the allowed registry prefixes."""
    if not any(image.startswith(prefix) for prefix in policy.allowed_image_prefixes):
        raise ValueError(
            f"Image '{image}' is not allowed. Allowed prefixes: "
            f"{', '.join(policy.allowed_image_prefixes) or '(none)'}"
        )


def validate_evidence_paths(
    evidence_paths: list[str],
    policy: ContainerConfig,
    strict: bool = False,
) -> list[Path]:
    """Resolve evidence paths and check them against the allowed roots.

    Symlinks are resolved first, so a link pointing outside a root is refused.

    Args:
        evidence_paths: Host paths requested for mounting.
        policy: Container policy holding ``evidence_roots``.
        strict: Refuse everything when no root is configured (MCP mode).

    Returns:
        The resolved paths.
    """
    roots = [Path(r).expanduser().resolve() for r in policy.evidence_roots]
    if not roots:
        if strict:
            raise PermissionError(
                "No evidence roots configured (container.evidence_roots in defair.yaml). "
                "Mounting evidence through MCP is refused."
            )
        log.warning("evidence_roots_not_configured")

    resolved = []
    for ev_path in evidence_paths:
        ev = Path(ev_path).expanduser().resolve()
        if not ev.exists():
            raise FileNotFoundError(f"Evidence path not found: {ev}")
        if roots and not any(ev == root or ev.is_relative_to(root) for root in roots):
            raise PermissionError(
                f"Evidence path '{ev}' is outside the allowed evidence roots: "
                f"{', '.join(str(r) for r in roots)}"
            )
        resolved.append(ev)
    return resolved


def check_workspace_writable(ws_path: Path) -> None:
    """The container runs as the host user: every file of the workspace it
    writes (database, analysis output, logs) must be writable by that user.

    Workspaces created by DEFAIR < 0.3.6 (containers running as root) are not.
    """
    blocked = [p for p in (ws_path, ws_path / "defair.db", ws_path / "analysis",
                           ws_path / "logs", ws_path / "sources")
               if p.exists() and not os.access(p, os.W_OK)]
    if blocked:
        raise PermissionError(
            f"Workspace {ws_path} is not writable by your user "
            f"({', '.join(p.name for p in blocked)}) — probably created by an older DEFAIR "
            f"running as root. Fix it with:  sudo chown -R {os.getuid()}:{os.getgid()} {ws_path}"
            f"   or use another workspace (--workspace DIR)."
        )


def hardening_kwargs(policy: ContainerConfig) -> dict:
    """Docker ``containers.create`` kwargs isolating a forensic container.

    The container runs as the host user so it can write the bind-mounted
    workspace without CAP_DAC_OVERRIDE, with every capability dropped.
    """
    kwargs: dict = {
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "network_mode": policy.network,
        "mem_limit": policy.mem_limit,
        "nano_cpus": int(policy.cpus * 1_000_000_000),
        "pids_limit": policy.pids_limit,
        "user": f"{os.getuid()}:{os.getgid()}",
        # docker-init as PID 1 reaps detached profile-run workers
        "init": True,
    }
    if policy.read_only_rootfs:
        kwargs["read_only"] = True
        kwargs["tmpfs"] = {"/tmp": f"size={policy.tmpfs_size}"}
    return kwargs


async def create_container(
    case_id: str | None = None,
    name: str | None = None,
    image: str = DEFAULT_IMAGE,
    evidence_paths: list[str] | None = None,
    workspace: str | None = None,
    ports: dict[str, int] | None = None,
    env: dict[str, str] | None = None,
    policy: ContainerConfig | None = None,
    strict_evidence_roots: bool = False,
    keys_path: str | None = None,
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
        policy: Container policy (image allowlist, evidence roots, hardening).
        strict_evidence_roots: Refuse mounts when no evidence root is configured.
        keys_path: Host directory of private keys (DFIR-ORC / Generaptor),
            mounted read-only at /keys; must be under ``policy.key_roots``.

    Returns:
        ContainerInfo with the created container details.
    """

    policy = policy or ContainerConfig()
    validate_image(image, policy)
    evidence_list = [
        str(p) for p in validate_evidence_paths(
            evidence_paths or [], policy, strict=strict_evidence_roots and bool(evidence_paths),
        )
    ]

    keys_dir = None
    if keys_path:
        key_policy = policy.model_copy(update={"evidence_roots": policy.key_roots})
        (keys_dir,) = validate_evidence_paths([keys_path], key_policy, strict=True)

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
        check_workspace_writable(ws_path)

        # Build volume mounts
        volumes = {
            str(ws_path): {"bind": "/workspace", "mode": "rw"},
        }

        # Mount evidence as read-only bind-mounts.
        # Single evidence path → mounted directly at /evidence
        # Multiple paths → mounted at /evidence/<dirname>
        if evidence_list:
            if len(evidence_list) == 1:
                # Single path: mount directly at /evidence
                ev = Path(evidence_list[0]).resolve()
                volumes[str(ev)] = {"bind": "/evidence", "mode": "ro"}
            else:
                # Multiple paths: mount each at /evidence/<name>
                for ev_path in evidence_list:
                    ev = Path(ev_path).resolve()
                    volumes[str(ev)] = {
                        "bind": f"/evidence/{ev.name}",
                        "mode": "ro",
                    }

        if keys_dir:
            volumes[str(keys_dir)] = {"bind": "/keys", "mode": "ro"}

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
        environment = {
            "DEFAIR_DB_PATH": "/workspace/defair.db",
            # Read-only rootfs + non-root user: every writable home is /tmp
            "HOME": "/tmp",
            "DOTNET_CLI_HOME": "/tmp",
            "DOTNET_BUNDLE_EXTRACT_BASE_DIR": "/tmp",
        }
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
            # PID 1 follows the shared log file: every DEFAIR process in the
            # container writes there, so `docker logs` shows all actions
            command=["sh", "-c", CONTAINER_ENTRY],
            **hardening_kwargs(policy),
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
