"""DEFAIR configuration — YAML + Pydantic with sensible defaults."""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class StorageConfig(BaseModel):
    """Paths for DEFAIR data storage."""

    database: Path = Path(os.environ.get("DEFAIR_DB_PATH", "~/.defair/defair.db"))
    evidence: Path = Path("/evidence")
    cases: Path = Path("~/.defair/cases")


class LoggingConfig(BaseModel):
    """Logging configuration."""

    level: str = "INFO"
    format: str = "console"  # "json" or "console"


class McpConfig(BaseModel):
    """MCP server policy."""

    # Arbitrary shell execution in containers via MCP. Off by default:
    # agents use run_tool (registered tools, validated arguments) instead.
    allow_exec: bool = False


class ContainerConfig(BaseModel):
    """Forensic container policy and hardening."""

    # Host directories evidence may be mounted from. Empty = unrestricted
    # for the CLI (with a warning); the MCP refuses to mount anything.
    evidence_roots: list[Path] = Field(default_factory=list)
    allowed_image_prefixes: list[str] = Field(
        default_factory=lambda: ["ghcr.io/joblinours/defair"]
    )
    network: str = "none"
    mem_limit: str = "8g"
    cpus: float = 4
    pids_limit: int = 2048
    read_only_rootfs: bool = True
    tmpfs_size: str = "2g"
    # Host directories private keys (DFIR-ORC / Generaptor) may be mounted from
    key_roots: list[Path] = Field(default_factory=list)


class ExtractionConfig(BaseModel):
    """Limits when extracting archives / carving images (anti archive-bomb)."""

    max_bytes: int = 200 * 1024**3
    max_files: int = 1_000_000


class OrchestratorConfig(BaseModel):
    """Profile run execution."""

    max_parallel: int = 4
    default_timeout: int = 7200  # seconds per step
    default_retries: int = 0


class WorkerConfig(BaseModel):
    """A dedicated worker image (heavy engines kept out of the main image).

    Workers run as short-lived jobs next to the case container, with the same
    hardening, evidence (read-only) and workspace mounts.
    """

    # Pinned by version tag — never ``latest``
    image: str
    mem_limit: str = "8g"
    cpus: float = 4
    pids_limit: int = 4096
    tmpfs_size: str = "4g"
    timeout: int = 12 * 3600  # seconds for the whole job


def _default_workers() -> dict[str, WorkerConfig]:
    return {"plaso": WorkerConfig(image="ghcr.io/joblinours/defair-worker-plaso:0.5.0")}


class DefairConfig(BaseModel):
    """Root configuration for DEFAIR."""

    storage: StorageConfig = StorageConfig()
    logging: LoggingConfig = LoggingConfig()
    mcp: McpConfig = McpConfig()
    container: ContainerConfig = ContainerConfig()
    extraction: ExtractionConfig = ExtractionConfig()
    orchestrator: OrchestratorConfig = OrchestratorConfig()
    workers: dict[str, WorkerConfig] = Field(default_factory=_default_workers)
    timezone: str = "UTC"

    def resolve_paths(self) -> DefairConfig:
        """Expand ~ in all paths and ensure directories exist."""
        self.storage.database = self.storage.database.expanduser()
        self.storage.evidence = self.storage.evidence.expanduser()
        self.storage.cases = self.storage.cases.expanduser()
        self.container.evidence_roots = [
            p.expanduser() for p in self.container.evidence_roots
        ]
        self.container.key_roots = [p.expanduser() for p in self.container.key_roots]
        # Ensure DB directory exists
        self.storage.database.parent.mkdir(parents=True, exist_ok=True)
        return self


# Config search order: ./defair.yaml → ~/.defair/config.yaml → defaults
_CONFIG_SEARCH_PATHS = [
    Path("defair.yaml"),
    Path("~/.defair/config.yaml"),
]


def load_config(config_path: Path | None = None) -> DefairConfig:
    """Load configuration from YAML file with fallback to defaults.

    Search order:
    1. Explicit path (if provided)
    2. ./defair.yaml
    3. ~/.defair/config.yaml
    4. Built-in defaults
    """
    if config_path and config_path.exists():
        return _load_from_file(config_path)

    for search_path in _CONFIG_SEARCH_PATHS:
        resolved = search_path.expanduser()
        if resolved.exists():
            return _load_from_file(resolved)

    return DefairConfig().resolve_paths()


def _load_from_file(path: Path) -> DefairConfig:
    """Load and validate config from a YAML file."""
    with open(path) as f:
        raw = yaml.safe_load(f) or {}
    return DefairConfig(**raw).resolve_paths()
