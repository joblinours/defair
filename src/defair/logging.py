"""DEFAIR structured logging — structlog with JSON and console renderers."""

from __future__ import annotations

import logging
import uuid
from contextvars import ContextVar

import structlog

from defair.config import LoggingConfig

# Correlation ID for tracing requests across layers
correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")


def new_correlation_id() -> str:
    """Generate and set a new correlation ID."""
    cid = uuid.uuid4().hex[:12]
    correlation_id.set(cid)
    return cid


def _add_correlation_id(
    logger: structlog.types.WrappedLogger,
    method_name: str,
    event_dict: structlog.types.EventDict,
) -> structlog.types.EventDict:
    """Structlog processor that injects the correlation ID."""
    cid = correlation_id.get()
    if cid:
        event_dict["correlation_id"] = cid
    return event_dict


def configure_logging(config: LoggingConfig | None = None) -> None:
    """Configure structlog with the given settings."""
    if config is None:
        config = LoggingConfig()

    # Choose renderer
    if config.format == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            _add_correlation_id,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, config.level.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Get a structured logger, optionally bound to a component name."""
    log = structlog.get_logger()
    if name:
        log = log.bind(component=name)
    return log
