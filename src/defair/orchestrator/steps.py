"""Run one profile step against a prepared evidence.

A tool step runs once per location of its input selector. For each location
the candidates are tried in order until one completes:

- ``engine=auto``    : the step's tool (EZ Tools) → native fallbacks → Dissect plugins
- ``engine=ez``      : the step's tool → native fallbacks (no Dissect)
- ``engine=dissect`` : the step's Dissect alternative only (tools without one
  run normally)

A Dissect plugin reads the original target (image or collection) as a whole,
so it runs once per step, not once per location.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import aiosqlite
import structlog

from defair.orchestrator.dag import StepFailed, StepSkipped
from defair.orchestrator.profile import Fallback, Step, step_input
from defair.tools.registry import ToolRegistry, get_default_registry

log = structlog.get_logger(component="orchestrator.steps")


def dissect_target(prepared: dict) -> str:
    """What Dissect should open: the image itself, or the collection folder."""
    source_kind = (prepared.get("source") or {}).get("kind")
    if source_kind in ("disk_image", "kape_vhdx"):
        return prepared["target"]
    root = prepared.get("root")
    if prepared.get("kind") == "kape" and root:
        return str(Path(root).parent)  # Dissect's KAPE loader wants the folder above C/
    if prepared.get("kind") == "velociraptor":
        return prepared["base"]
    return root or prepared["base"]


@dataclass
class StepContext:
    conn: aiosqlite.Connection
    case_id: str
    evidence_id: str | None
    prepared: dict
    engine: str = "auto"
    output_base: str = "/workspace/analysis"
    registry: ToolRegistry = field(default_factory=get_default_registry)
    #: step id → output directories of its completed tool runs
    step_outputs: dict[str, list[str]] = field(default_factory=dict)

    def locations(self, selector: str) -> list[str]:
        source = step_input(selector)
        if source is not None:
            return [p for p in self.step_outputs.get(source, []) if _has_files(p)]
        if selector == "target":
            # Dissect needs a filesystem (image or collection), not loose logs
            if self.prepared.get("kind") == "logs":
                return []
            return [dissect_target(self.prepared)]
        if selector == "base":
            return [self.prepared["base"]]
        return list((self.prepared.get("selectors") or {}).get(selector) or [])

    def resolve_options(self, tool: str, options: dict, location: str) -> dict:
        resolved = {}
        for key, value in options.items():
            if isinstance(value, str) and value.startswith("$"):
                found = self.locations(value[1:])
                if not found:
                    continue  # optional tool argument whose artifact is absent
                value = found[0]
            resolved[key] = value
        manifest = self.registry.get(tool).manifest() if self.registry.get(tool) else None
        if manifest and "directory" in manifest.allowed_options:
            resolved.setdefault("directory", Path(location).is_dir())
        return resolved


def _has_files(path: str) -> bool:
    p = Path(path)
    return p.is_dir() and any(f.is_file() for f in p.rglob("*"))


def record_outputs(ctx: StepContext, step_id: str, detail: dict) -> None:
    """Remember where a step's tools wrote (inputs of ``step:<id>`` steps)."""
    paths = [r["output_path"] for r in detail.get("tool_runs", [])
             if r.get("status") == "completed" and r.get("output_path")]
    if paths:
        ctx.step_outputs[step_id] = paths


def _candidates(step: Step, engine: str) -> list[Fallback]:
    primary = Fallback(tool=step.tool, options=dict(step.options))
    chain = [primary, *step.fallbacks]
    if step.tool == "dissect_plugin":
        return [primary]
    if engine == "dissect":
        dissect = [f for f in step.fallbacks if f.is_dissect]
        return dissect[:1] or [primary]
    if engine == "ez":
        return [c for c in chain if not c.is_dissect]
    return chain


async def run_step(ctx: StepContext, step: Step) -> dict:
    """Runner used by the DAG executor."""
    if step.action:
        return await _run_action(ctx, step)

    candidates = _candidates(step, ctx.engine)
    uses_step_input = [c for c in candidates if not c.input]
    locations = ctx.locations(step.input) if uses_step_input else []
    input_note = None
    if uses_step_input and not locations and step.input_fallback:
        locations = ctx.locations(step.input_fallback)
        if locations:
            input_note = f"'{step.input}' produced nothing: used '{step.input_fallback}'"
            log.warning("step_input_fallback", step=step.id, detail=input_note)
    # The artifact is absent: nothing to parse — unless Dissect is asked to
    # look for it itself in the original target
    if uses_step_input and not locations and ctx.engine != "dissect":
        raise StepSkipped(f"no '{step.input}' found in this evidence")

    runs: list[dict] = []
    dissect_done: dict | None = None
    failures: list[str] = []
    for location in locations or [None]:
        if dissect_done is not None:
            break  # a Dissect plugin already parsed the whole target
        succeeded = False
        for candidate in candidates:
            if candidate.input:
                if dissect_done is not None:
                    succeeded = True  # already covered the whole target
                    break
                target_locations = ctx.locations(candidate.input)
                if not target_locations:
                    continue
                target = target_locations[0]
            elif location is None:
                continue
            else:
                target = location
            attempt = await _run_tool(ctx, candidate, target, step)
            runs.append(attempt)
            if attempt["status"] == "completed":
                succeeded = True
                if candidate.input:
                    dissect_done = attempt
                break
        if not succeeded:
            failures.append(location or step.input)

    detail = {
        "tool_runs": runs,
        "artifacts": sum(r.get("artifacts", 0) for r in runs if r["status"] == "completed"),
        "used": sorted({r["tool"] for r in runs if r["status"] == "completed"}),
    }
    if input_note:
        detail["warning"] = input_note
    record_outputs(ctx, step.id, detail)
    if not runs:
        raise StepSkipped(f"no applicable input for '{step.id}'")
    if all(r["status"] == "unavailable" for r in runs):
        tools = sorted({r["tool"] for r in runs})
        raise StepSkipped(f"no available tool ({', '.join(tools)} not installed)")
    if failures:
        raise StepFailed(f"no tool succeeded for {len(failures)} location(s): {failures[:3]}", detail)
    return detail


async def _run_tool(ctx: StepContext, candidate: Fallback, target: str, step: Step) -> dict:
    from defair.services import analysis_service

    tool = candidate.tool
    record = {"tool": tool, "input": target}
    if candidate.plugin:
        record["plugin"] = candidate.plugin
    registered = ctx.registry.get(tool)
    if registered is None or not registered.is_available():
        record.update(status="unavailable", error=f"tool '{tool}' is not available")
        return record

    options = ctx.resolve_options(tool, candidate.options, target)
    if candidate.plugin:
        options["plugin"] = candidate.plugin
    try:
        result = await analysis_service.run_tool_and_normalize(
            ctx.conn, tool, target, ctx.case_id,
            evidence_id=ctx.evidence_id,
            output_base=ctx.output_base,
            registry=ctx.registry,
            auto_fallback=False,
            timeout=step.timeout,
            **options,
        )
    except Exception as e:  # noqa: BLE001 — try the next candidate
        record.update(status="failed", error=f"{type(e).__name__}: {e}"[:500])
        return record
    status = getattr(result["status"], "value", result["status"])
    record.update(
        status=status,
        run_number=result["run_number"],
        output_path=result.get("output_path"),
        artifacts=result.get("artifacts_produced", 0),
        duration_seconds=result.get("duration_seconds"),
    )
    if status != "completed":
        record["error"] = f"exit code {result.get('exit_code')}"
    return record


async def _run_action(ctx: StepContext, step: Step) -> dict:
    from defair.services import hunting_service, scanning_service, timeline_service

    if step.action == "timeline_summary":
        summary = await timeline_service.build_timeline(ctx.conn, ctx.case_id)
        return {"timeline": summary}

    locations = ctx.locations(step.input)
    if not locations:
        raise StepSkipped(f"no '{step.input}' found in this evidence")

    runs = []
    for location in locations:
        if step.action == "hunt":
            result = await hunting_service.hunt_evtx(
                ctx.conn, location, ctx.case_id, evidence_id=ctx.evidence_id,
                output_base=ctx.output_base,
                engine=step.options.get("engine", "hayabusa"),
                rule_profile=step.options.get("rule_profile", "precise"),
            )
        else:  # scan
            result = await scanning_service.scan(
                ctx.conn, location, ctx.case_id,
                mode=step.options.get("mode", "all"),
                profile=step.options.get("rule_profile", "broad"),
                evidence_id=ctx.evidence_id,
                output_base=ctx.output_base,
            )
        status = getattr(result["status"], "value", result["status"])
        runs.append({
            "tool": result.get("tool"), "input": location, "status": status,
            "run_number": result.get("run_number"),
            "artifacts": result.get("artifacts_produced", 0),
            "findings": result.get("findings_created", 0),
        })
        if status != "completed":
            raise StepFailed(f"{step.action} on {location}: {status}", {"tool_runs": runs})
    return {
        "tool_runs": runs,
        "artifacts": sum(r["artifacts"] for r in runs),
        "findings": sum(r["findings"] for r in runs),
    }
