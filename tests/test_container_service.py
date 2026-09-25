"""Tests for the container service layer.

Uses mocked Docker SDK — these tests run without a Docker daemon.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from defair.services import container_service
from defair.services.container_service import ContainerInfo

# ---------------------------------------------------------------------------
# Fixtures — mock Docker client and containers
# ---------------------------------------------------------------------------


def _make_mock_container(
    name: str = "defair-case-2026-001",
    status: str = "created",
    short_id: str = "abc123",
    image_tags: list[str] | None = None,
    labels: dict | None = None,
    mounts: list[dict] | None = None,
):
    """Create a mock Docker container object."""
    container = MagicMock()
    container.name = name
    container.status = status
    container.short_id = short_id

    mock_image = MagicMock()
    mock_image.tags = image_tags or ["ghcr.io/joblinours/defair:latest"]
    mock_image.short_id = "sha256:abc"
    container.image = mock_image

    container.labels = labels or {
        "defair.managed": "true",
        "defair.case_id": "CASE-2026-001",
        "defair.workspace": "/home/user/.defair/workspaces/defair-case-2026-001",
    }

    container.attrs = {
        "Created": "2026-09-12T10:00:00Z",
        "Mounts": mounts or [
            {"Source": "/evidence/disk.E01", "Mode": "ro"},
        ],
    }

    container.reload = MagicMock()
    container.start = MagicMock()
    container.stop = MagicMock()
    container.remove = MagicMock()
    container.logs = MagicMock(return_value=b"container log output\n")
    container.exec_run = MagicMock(return_value=(0, (b"command output\n", b"")))

    return container


@pytest.fixture
def mock_docker_client():
    """Provide a mocked Docker client."""
    client = MagicMock()
    client.ping = MagicMock()
    return client


# ---------------------------------------------------------------------------
# Tests — ContainerInfo
# ---------------------------------------------------------------------------


class TestContainerInfo:
    def test_to_dict(self):
        info = ContainerInfo(
            name="defair-test",
            container_id="abc123",
            status="running",
            image="ghcr.io/joblinours/defair:latest",
            case_id="CASE-2026-001",
            workspace="/workspace",
            evidence_mounts=["/evidence/disk.E01"],
        )
        d = info.to_dict()
        assert d["name"] == "defair-test"
        assert d["status"] == "running"
        assert d["case_id"] == "CASE-2026-001"
        assert "/evidence/disk.E01" in d["evidence_mounts"]

    def test_to_dict_defaults(self):
        info = ContainerInfo(
            name="defair-test",
            container_id="abc123",
            status="created",
            image="defair:latest",
        )
        d = info.to_dict()
        assert d["case_id"] is None
        assert d["evidence_mounts"] == []


# ---------------------------------------------------------------------------
# Tests — create_container
# ---------------------------------------------------------------------------


class TestCreateContainer:
    @pytest.mark.asyncio
    async def test_create_with_case_id(self, mock_docker_client, tmp_path):
        mock_container = _make_mock_container()
        mock_docker_client.containers.create = MagicMock(return_value=mock_container)
        mock_docker_client.images.get = MagicMock()

        with patch.object(container_service, "_get_client", return_value=mock_docker_client), \
             patch.object(container_service, "WORKSPACE_BASE", tmp_path / "workspaces"):
            info = await container_service.create_container(case_id="CASE-2026-001")

        assert info.name == "defair-case-2026-001"
        mock_docker_client.containers.create.assert_called_once()
        call_kwargs = mock_docker_client.containers.create.call_args
        assert call_kwargs.kwargs["labels"]["defair.case_id"] == "CASE-2026-001"
        assert call_kwargs.kwargs["labels"]["defair.managed"] == "true"

    @pytest.mark.asyncio
    async def test_create_with_custom_name(self, mock_docker_client, tmp_path):
        mock_container = _make_mock_container(name="my-forensic-box")
        mock_docker_client.containers.create = MagicMock(return_value=mock_container)
        mock_docker_client.images.get = MagicMock()

        with patch.object(container_service, "_get_client", return_value=mock_docker_client), \
             patch.object(container_service, "WORKSPACE_BASE", tmp_path / "workspaces"):
            info = await container_service.create_container(name="my-forensic-box")

        assert info.name == "my-forensic-box"

    @pytest.mark.asyncio
    async def test_create_with_evidence(self, mock_docker_client, tmp_path):
        evidence_file = tmp_path / "disk.E01"
        evidence_file.write_text("fake evidence")

        mock_container = _make_mock_container()
        mock_docker_client.containers.create = MagicMock(return_value=mock_container)
        mock_docker_client.images.get = MagicMock()

        with patch.object(container_service, "_get_client", return_value=mock_docker_client), \
             patch.object(container_service, "WORKSPACE_BASE", tmp_path / "workspaces"):
            await container_service.create_container(
                case_id="CASE-2026-001",
                evidence_paths=[str(evidence_file)],
            )

        call_kwargs = mock_docker_client.containers.create.call_args
        volumes = call_kwargs.kwargs["volumes"]
        # Evidence should be mounted read-only
        assert any(v["mode"] == "ro" for v in volumes.values())

    @pytest.mark.asyncio
    async def test_create_evidence_not_found(self, mock_docker_client, tmp_path):
        mock_docker_client.images.get = MagicMock()

        with patch.object(container_service, "_get_client", return_value=mock_docker_client), \
             patch.object(container_service, "WORKSPACE_BASE", tmp_path / "workspaces"), \
             pytest.raises(FileNotFoundError):
            await container_service.create_container(
                evidence_paths=["/nonexistent/path"],
            )

    @pytest.mark.asyncio
    async def test_create_pulls_missing_image(self, mock_docker_client, tmp_path):
        import docker.errors

        mock_docker_client.images.get = MagicMock(
            side_effect=docker.errors.ImageNotFound("not found")
        )
        mock_docker_client.images.pull = MagicMock()
        mock_container = _make_mock_container()
        mock_docker_client.containers.create = MagicMock(return_value=mock_container)

        with patch.object(container_service, "_get_client", return_value=mock_docker_client), \
             patch.object(container_service, "WORKSPACE_BASE", tmp_path / "workspaces"):
            await container_service.create_container(case_id="CASE-2026-001")

        mock_docker_client.images.pull.assert_called_once()


# ---------------------------------------------------------------------------
# Tests — list_containers
# ---------------------------------------------------------------------------


class TestListContainers:
    @pytest.mark.asyncio
    async def test_list_all(self, mock_docker_client):
        c1 = _make_mock_container(name="defair-case-001", status="running")
        c2 = _make_mock_container(name="defair-case-002", status="exited")
        mock_docker_client.containers.list = MagicMock(return_value=[c1, c2])

        with patch.object(container_service, "_get_client", return_value=mock_docker_client):
            result = await container_service.list_containers()

        assert len(result) == 2
        assert result[0].name == "defair-case-001"

    @pytest.mark.asyncio
    async def test_list_filter_by_case(self, mock_docker_client):
        c1 = _make_mock_container(
            name="defair-case-001",
            labels={"defair.managed": "true", "defair.case_id": "CASE-2026-001"},
        )
        c2 = _make_mock_container(
            name="defair-case-002",
            labels={"defair.managed": "true", "defair.case_id": "CASE-2026-002"},
        )
        mock_docker_client.containers.list = MagicMock(return_value=[c1, c2])

        with patch.object(container_service, "_get_client", return_value=mock_docker_client):
            result = await container_service.list_containers(case_id="CASE-2026-001")

        assert len(result) == 1
        assert result[0].case_id == "CASE-2026-001"

    @pytest.mark.asyncio
    async def test_list_empty(self, mock_docker_client):
        mock_docker_client.containers.list = MagicMock(return_value=[])

        with patch.object(container_service, "_get_client", return_value=mock_docker_client):
            result = await container_service.list_containers()

        assert result == []


# ---------------------------------------------------------------------------
# Tests — get, start, stop, remove
# ---------------------------------------------------------------------------


class TestContainerLifecycle:
    @pytest.mark.asyncio
    async def test_get_container(self, mock_docker_client):
        mock_container = _make_mock_container()
        mock_docker_client.containers.get = MagicMock(return_value=mock_container)

        with patch.object(container_service, "_get_client", return_value=mock_docker_client):
            info = await container_service.get_container("defair-case-2026-001")

        assert info is not None
        assert info.name == "defair-case-2026-001"

    @pytest.mark.asyncio
    async def test_get_container_not_found(self, mock_docker_client):
        import docker.errors

        mock_docker_client.containers.get = MagicMock(
            side_effect=docker.errors.NotFound("not found")
        )

        with patch.object(container_service, "_get_client", return_value=mock_docker_client):
            info = await container_service.get_container("nonexistent")

        assert info is None

    @pytest.mark.asyncio
    async def test_start_container(self, mock_docker_client):
        mock_container = _make_mock_container(status="running")
        mock_docker_client.containers.get = MagicMock(return_value=mock_container)

        with patch.object(container_service, "_get_client", return_value=mock_docker_client):
            info = await container_service.start_container("defair-case-2026-001")

        mock_container.start.assert_called_once()
        assert info.status == "running"

    @pytest.mark.asyncio
    async def test_stop_container(self, mock_docker_client):
        mock_container = _make_mock_container(status="exited")
        mock_docker_client.containers.get = MagicMock(return_value=mock_container)

        with patch.object(container_service, "_get_client", return_value=mock_docker_client):
            await container_service.stop_container("defair-case-2026-001")

        mock_container.stop.assert_called_once_with(timeout=10)

    @pytest.mark.asyncio
    async def test_remove_container(self, mock_docker_client):
        mock_container = _make_mock_container()
        mock_docker_client.containers.get = MagicMock(return_value=mock_container)

        with patch.object(container_service, "_get_client", return_value=mock_docker_client):
            result = await container_service.remove_container("defair-case-2026-001")

        mock_container.remove.assert_called_once_with(force=False)
        assert result["removed"] is True

    @pytest.mark.asyncio
    async def test_remove_container_force(self, mock_docker_client):
        mock_container = _make_mock_container()
        mock_docker_client.containers.get = MagicMock(return_value=mock_container)

        with patch.object(container_service, "_get_client", return_value=mock_docker_client):
            await container_service.remove_container("defair-case-2026-001", force=True)

        mock_container.remove.assert_called_once_with(force=True)


# ---------------------------------------------------------------------------
# Tests — exec_in_container
# ---------------------------------------------------------------------------


class TestExecInContainer:
    @pytest.mark.asyncio
    async def test_exec_command(self, mock_docker_client):
        mock_container = _make_mock_container(status="running")
        mock_container.exec_run = MagicMock(
            return_value=(0, (b"file1.txt\nfile2.txt\n", b""))
        )
        mock_docker_client.containers.get = MagicMock(return_value=mock_container)

        with patch.object(container_service, "_get_client", return_value=mock_docker_client):
            result = await container_service.exec_in_container(
                "defair-case-2026-001", "ls /evidence"
            )

        assert result["exit_code"] == 0
        assert "file1.txt" in result["stdout"]
        assert result["stderr"] == ""

    @pytest.mark.asyncio
    async def test_exec_with_workdir(self, mock_docker_client):
        mock_container = _make_mock_container(status="running")
        mock_docker_client.containers.get = MagicMock(return_value=mock_container)

        with patch.object(container_service, "_get_client", return_value=mock_docker_client):
            await container_service.exec_in_container(
                "defair-case-2026-001", "ls", workdir="/workspace"
            )

        call_kwargs = mock_container.exec_run.call_args.kwargs
        assert call_kwargs["workdir"] == "/workspace"

    @pytest.mark.asyncio
    async def test_exec_not_running(self, mock_docker_client):
        mock_container = _make_mock_container(status="exited")
        mock_docker_client.containers.get = MagicMock(return_value=mock_container)

        with patch.object(container_service, "_get_client", return_value=mock_docker_client), \
             pytest.raises(RuntimeError, match="not running"):
            await container_service.exec_in_container(
                "defair-case-2026-001", "ls"
            )

    @pytest.mark.asyncio
    async def test_exec_nonzero_exit(self, mock_docker_client):
        mock_container = _make_mock_container(status="running")
        mock_container.exec_run = MagicMock(
            return_value=(1, (b"", b"command not found\n"))
        )
        mock_docker_client.containers.get = MagicMock(return_value=mock_container)

        with patch.object(container_service, "_get_client", return_value=mock_docker_client):
            result = await container_service.exec_in_container(
                "defair-case-2026-001", "nonexistent_command"
            )

        assert result["exit_code"] == 1
        assert "command not found" in result["stderr"]


# ---------------------------------------------------------------------------
# Tests — container_logs
# ---------------------------------------------------------------------------


class TestContainerLogs:
    @pytest.mark.asyncio
    async def test_get_logs(self, mock_docker_client):
        mock_container = _make_mock_container()
        mock_container.logs = MagicMock(return_value=b"2026-09-12 log line\n")
        mock_docker_client.containers.get = MagicMock(return_value=mock_container)

        with patch.object(container_service, "_get_client", return_value=mock_docker_client):
            logs = await container_service.container_logs("defair-case-2026-001")

        assert "log line" in logs
        mock_container.logs.assert_called_once_with(tail=100, follow=False, timestamps=True)


# ---------------------------------------------------------------------------
# Tests — Docker connection error
# ---------------------------------------------------------------------------


class TestDockerConnection:
    def test_connection_error(self):
        import docker.errors

        with patch("docker.from_env", side_effect=docker.errors.DockerException("connection refused")), \
             pytest.raises(ConnectionError, match="Cannot connect"):
            container_service._get_client()


# ---------------------------------------------------------------------------
# Tests — security policy (v0.3.6)
# ---------------------------------------------------------------------------


class TestContainerPolicy:
    def test_image_prefix_allowed(self):
        from defair.config import ContainerConfig

        container_service.validate_image("ghcr.io/joblinours/defair:0.3.6", ContainerConfig())

    def test_image_prefix_refused(self):
        from defair.config import ContainerConfig

        with pytest.raises(ValueError, match="not allowed"):
            container_service.validate_image("docker.io/evil/image:latest", ContainerConfig())

    def test_evidence_inside_root(self, tmp_path):
        from defair.config import ContainerConfig

        root = tmp_path / "evidence"
        (root / "case1").mkdir(parents=True)
        policy = ContainerConfig(evidence_roots=[root])
        resolved = container_service.validate_evidence_paths([str(root / "case1")], policy)
        assert resolved == [(root / "case1").resolve()]

    def test_evidence_outside_root_refused(self, tmp_path):
        from defair.config import ContainerConfig

        root = tmp_path / "evidence"
        root.mkdir()
        outside = tmp_path / "home"
        outside.mkdir()
        policy = ContainerConfig(evidence_roots=[root])
        with pytest.raises(PermissionError, match="outside the allowed evidence roots"):
            container_service.validate_evidence_paths([str(outside)], policy)

    def test_symlink_escaping_root_refused(self, tmp_path):
        from defair.config import ContainerConfig

        root = tmp_path / "evidence"
        root.mkdir()
        secret = tmp_path / "secret"
        secret.mkdir()
        (root / "link").symlink_to(secret)
        policy = ContainerConfig(evidence_roots=[root])
        with pytest.raises(PermissionError):
            container_service.validate_evidence_paths([str(root / "link")], policy)

    def test_no_roots_strict_refuses(self, tmp_path):
        from defair.config import ContainerConfig

        with pytest.raises(PermissionError, match="No evidence roots"):
            container_service.validate_evidence_paths(
                [str(tmp_path)], ContainerConfig(), strict=True,
            )

    def test_no_roots_lenient_allows(self, tmp_path):
        from defair.config import ContainerConfig

        resolved = container_service.validate_evidence_paths([str(tmp_path)], ContainerConfig())
        assert resolved == [tmp_path.resolve()]

    def test_hardening_kwargs(self):
        import os

        from defair.config import ContainerConfig

        kwargs = container_service.hardening_kwargs(ContainerConfig())
        assert kwargs["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in kwargs["security_opt"]
        assert kwargs["network_mode"] == "none"
        assert kwargs["read_only"] is True
        assert "/tmp" in kwargs["tmpfs"]
        assert kwargs["nano_cpus"] == 4_000_000_000
        assert kwargs["user"] == f"{os.getuid()}:{os.getgid()}"

    def test_hardening_rootfs_optional(self):
        from defair.config import ContainerConfig

        kwargs = container_service.hardening_kwargs(ContainerConfig(read_only_rootfs=False))
        assert "read_only" not in kwargs

    @pytest.mark.asyncio
    async def test_create_applies_hardening(self, mock_docker_client, tmp_path):
        mock_docker_client.containers.create = MagicMock(return_value=_make_mock_container())
        mock_docker_client.images.get = MagicMock()

        with patch.object(container_service, "_get_client", return_value=mock_docker_client), \
             patch.object(container_service, "WORKSPACE_BASE", tmp_path / "workspaces"):
            await container_service.create_container(case_id="CASE-2026-001")

        kwargs = mock_docker_client.containers.create.call_args.kwargs
        assert kwargs["cap_drop"] == ["ALL"]
        assert kwargs["network_mode"] == "none"
        assert kwargs["environment"]["HOME"] == "/tmp"

    @pytest.mark.asyncio
    async def test_create_refuses_foreign_image(self, mock_docker_client, tmp_path):
        with patch.object(container_service, "_get_client", return_value=mock_docker_client), \
             patch.object(container_service, "WORKSPACE_BASE", tmp_path / "workspaces"), \
             pytest.raises(ValueError, match="not allowed"):
            await container_service.create_container(image="alpine:latest")
        mock_docker_client.containers.create.assert_not_called()
