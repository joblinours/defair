"""Dependency-aware parallel step executor.

The executor knows nothing about forensics: it schedules ``Step`` objects,
calls an injected ``runner`` for each, and handles

- dependencies (a step starts once all its ``needs`` are settled),
- bounded parallelism (``max_parallel``),
- per-step timeout and retry with exponential backoff,
- propagation (a step is skipped when a non-optional dependency failed),
- cancellation (``cancel_event``): running steps are cancelled — the tool
  wrappers kill their subprocess — and pending ones marked cancelled,
- resume (steps already ``completed`` in ``previous`` are not re-run).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

import structlog

from defair.orchestrator.profile import Step

log = structlog.get_logger(component="orchestrator.dag")

TERMINAL = ("completed", "failed", "skipped", "cancelled", "timeout")


class StepSkipped(Exception):
    """Raised by a runner when the step does not apply (e.g. input not found)."""


class StepFailed(RuntimeError):
    """Raised by a runner when the step failed; ``detail`` is kept in the result."""

    def __init__(self, message: str, detail: dict | None = None) -> None:
        super().__init__(message)
        self.detail = detail or {}


@dataclass
class StepResult:
    id: str
    status: str = "pending"
    attempts: int = 0
    started_at: str | None = None
    completed_at: str | None = None
    duration_seconds: float | None = None
    error: str | None = None
    detail: dict = field(default_factory=dict)  # runner output (tool runs, counts…)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "status": self.status, "attempts": self.attempts,
            "started_at": self.started_at, "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds, "error": self.error,
            **self.detail,
        }


Runner = Callable[[Step], Awaitable[dict]]
OnUpdate = Callable[[dict[str, StepResult]], Awaitable[None]]


async def execute(
    steps: list[Step],
    runner: Runner,
    max_parallel: int = 4,
    default_timeout: int | None = None,
    default_retries: int = 0,
    cancel_event: asyncio.Event | None = None,
    on_update: OnUpdate | None = None,
    previous: dict[str, dict] | None = None,
    backoff: float = 1.0,
) -> dict[str, StepResult]:
    """Run ``steps`` as a DAG and return their results by id."""
    cancel_event = cancel_event or asyncio.Event()
    by_id = {s.id: s for s in steps}
    results = {s.id: StepResult(s.id) for s in steps}
    for step_id, prev in (previous or {}).items():
        if step_id in results and prev.get("status") == "completed":
            results[step_id] = StepResult(
                step_id, status="completed", attempts=prev.get("attempts", 1),
                started_at=prev.get("started_at"), completed_at=prev.get("completed_at"),
                duration_seconds=prev.get("duration_seconds"),
                detail={k: v for k, v in prev.items() if k not in StepResult.__dataclass_fields__},
            )
            results[step_id].detail["resumed"] = True

    semaphore = asyncio.Semaphore(max(1, max_parallel))
    running: dict[str, asyncio.Task] = {}

    async def notify() -> None:
        if on_update:
            await on_update(results)

    async def run_one(step: Step) -> None:
        result = results[step.id]
        async with semaphore:
            if cancel_event.is_set():
                result.status = "cancelled"
                return
            result.status = "running"
            result.started_at = datetime.now(UTC).isoformat()
            await notify()
            start = time.monotonic()
            retries = step.retries if step.retries is not None else default_retries
            timeout = step.timeout or default_timeout
            for attempt in range(retries + 1):
                result.attempts = attempt + 1
                try:
                    coro = runner(step)
                    result.detail = await (asyncio.wait_for(coro, timeout) if timeout else coro)
                    result.status = "completed"
                    result.error = None
                    break
                except StepSkipped as e:
                    result.status = "skipped"
                    result.error = str(e) or None
                    break
                except TimeoutError:
                    result.status = "timeout"
                    result.error = f"timed out after {timeout}s"
                except asyncio.CancelledError:
                    result.status = "cancelled"
                    raise
                except Exception as e:  # noqa: BLE001 — recorded, the run goes on
                    result.status = "failed"
                    result.error = f"{type(e).__name__}: {e}"[:2000]
                    result.detail = getattr(e, "detail", None) or result.detail
                if attempt < retries and not cancel_event.is_set():
                    log.warning("step_retry", step=step.id, attempt=attempt + 1, error=result.error)
                    await asyncio.sleep(backoff * 2**attempt)
            result.duration_seconds = round(time.monotonic() - start, 3)
            result.completed_at = datetime.now(UTC).isoformat()
        await notify()

    def settled(step_id: str) -> bool:
        return results[step_id].status in TERMINAL

    def blocking_failure(step: Step) -> str | None:
        for need in step.needs:
            res = results[need]
            if res.status in ("failed", "timeout", "cancelled") and not by_id[need].optional:
                return need
        return None

    async def watch_cancel() -> None:
        await cancel_event.wait()
        for task in running.values():
            task.cancel()

    watcher = asyncio.create_task(watch_cancel())
    try:
        while True:
            for step in steps:
                result = results[step.id]
                if result.status != "pending" or step.id in running:
                    continue
                if cancel_event.is_set():
                    result.status = "cancelled"
                    continue
                if not all(settled(n) for n in step.needs):
                    continue
                failed_need = blocking_failure(step)
                if failed_need:
                    result.status = "skipped"
                    result.error = f"dependency '{failed_need}' did not complete"
                    continue
                running[step.id] = asyncio.create_task(run_one(step))

            if not running:
                if all(settled(s.id) for s in steps):
                    break
                # Nothing runnable and nothing running: remaining steps are stuck
                for s in steps:
                    if not settled(s.id):
                        results[s.id].status = "cancelled" if cancel_event.is_set() else "skipped"
                break

            done, _ = await asyncio.wait(running.values(), return_when=asyncio.FIRST_COMPLETED)
            for step_id in [k for k, t in running.items() if t in done]:
                task = running.pop(step_id)
                if task.cancelled() and results[step_id].status not in TERMINAL:
                    results[step_id].status = "cancelled"
    finally:
        watcher.cancel()
        for task in running.values():
            task.cancel()
        await notify()
    return results
