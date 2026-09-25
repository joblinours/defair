"""DEFAIR structured logging — structlog over stdlib logging.

- Console (stderr, never stdout: stdout carries command results / JSON):
  human-readable or JSON per ``logging.format``.
- Log file (JSON lines): every process in a forensic container — CLI
  commands, background run workers, tool runs — appends to
  ``/workspace/logs/defair.log``; the container's PID 1 follows that file, so
  ``docker logs <container>`` shows every action and its outcome. Set
  ``DEFAIR_LOG_FILE`` to override the path (empty string disables it).

Secrets are redacted: any field named like a password / passphrase / secret /
token / key material, and values following ``--password`` / ``--passphrase``
in logged command lines.
"""

from __future__ import annotations

import logging
import os
import sys
import uuid
from contextvars import ContextVar
from pathlib import Path

import structlog

from defair.config import LoggingConfig

CONTAINER_LOG_FILE = Path("/workspace/logs/defair.log")
SECRET_KEYS = ("password", "passphrase", "secret", "token", "private_key_pem", "api_key")
SECRET_FLAGS = ("--password", "--passphrase")
REDACTED = "***"

# Correlation ID for tracing requests across layers
correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")


def new_correlation_id() -> str:
    """Generate and set a new correlation ID."""
    cid = uuid.uuid4().hex[:12]
    correlation_id.set(cid)
    return cid


def _add_correlation_id(logger, method_name, event_dict):
    cid = correlation_id.get()
    if cid:
        event_dict["correlation_id"] = cid
    return event_dict


def _add_process(logger, method_name, event_dict):
    event_dict.setdefault("pid", os.getpid())
    return event_dict


def _redact(logger, method_name, event_dict):
    for key in list(event_dict):
        lowered = key.lower()
        # "secrets" / "secrets_used" hold the *names* of the secrets used, not values
        if (any(s in lowered for s in SECRET_KEYS) and lowered not in ("secrets", "secrets_used")
                and event_dict[key] not in (None, "", [], {})):
            event_dict[key] = REDACTED
    return event_dict


def redact_argv(argv: list[str]) -> list[str]:
    """Hide the value of secret options in a command line."""
    out, hide = [], False
    for arg in argv:
        if hide:
            out.append(REDACTED)
            hide = False
            continue
        flag, sep, _ = arg.partition("=")
        if flag in SECRET_FLAGS:
            if sep:
                out.append(f"{flag}={REDACTED}")
            else:
                out.append(arg)
                hide = True
            continue
        out.append(arg)
    return out


def default_log_file() -> Path | None:
    """The shared log file when running inside a forensic container."""
    env = os.environ.get("DEFAIR_LOG_FILE")
    if env is not None:
        return Path(env) if env else None
    workspace = CONTAINER_LOG_FILE.parent.parent
    if Path("/.dockerenv").exists() and workspace.is_dir() and os.access(workspace, os.W_OK):
        return CONTAINER_LOG_FILE
    return None


def configure_logging(config: LoggingConfig | None = None, log_file: Path | None = None) -> None:
    """Configure structlog → stdlib logging (stderr + optional JSON log file)."""
    if config is None:
        config = LoggingConfig()
    level = getattr(logging, config.level.upper(), logging.INFO)
    log_file = log_file if log_file is not None else default_log_file()

    shared = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _add_correlation_id,
        _add_process,
        _redact,
        structlog.processors.StackInfoRenderer(),
    ]
    structlog.configure(
        processors=[*shared, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.make_filtering_bound_logger(level),
        # False: loggers created at import time must pick up this configuration
        cache_logger_on_first_use=False,
    )

    console_renderer = (structlog.processors.JSONRenderer() if config.format == "json"
                        else structlog.dev.ConsoleRenderer())
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    root.setLevel(level)

    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(structlog.stdlib.ProcessorFormatter(
        processors=[structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                    structlog.processors.format_exc_info, console_renderer],
        foreign_pre_chain=shared,
    ))
    root.addHandler(console)

    if log_file:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
        except OSError:
            file_handler = None
        if file_handler:
            file_handler.setFormatter(structlog.stdlib.ProcessorFormatter(
                processors=[structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                            structlog.processors.dict_tracebacks,
                            structlog.processors.JSONRenderer(default=str)],
                foreign_pre_chain=shared,
            ))
            root.addHandler(file_handler)


def get_logger(name: str | None = None):
    """Get a structured logger, optionally bound to a component name."""
    log = structlog.get_logger()
    if name:
        log = log.bind(component=name)
    return log
