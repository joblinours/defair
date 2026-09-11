"""DEFAIR configuration — YAML + Pydantic with sensible defaults."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel


class StorageConfig(BaseModel):
    """Paths for DEFAIR data storage."""

    database: Path = Path("~/.defair/defair.db")
    evidence: Path = Path("/evidence")
    cases: Path = Path("~/.defair/cases")


class LoggingConfig(BaseModel):
    """Logging configuration."""

    level: str = "INFO"
    format: str = "console"  # "json" or "console"


class DefairConfig(BaseModel):
    """Root configuration for DEFAIR."""

    storage: StorageConfig = StorageConfig()
    logging: LoggingConfig = LoggingConfig()
    timezone: str = "UTC"

    def resolve_paths(self) -> DefairConfig:
        """Expand ~ in all paths and ensure directories exist."""
        self.storage.database = self.storage.database.expanduser()
        self.storage.evidence = self.storage.evidence.expanduser()
        self.storage.cases = self.storage.cases.expanduser()
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
