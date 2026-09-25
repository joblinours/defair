"""Declarative analysis profiles (``src/defair/profiles/*.yaml``)."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, model_validator

PROFILES_DIR = Path(__file__).resolve().parent.parent / "profiles"
ENGINES = ("auto", "ez", "dissect")
ACTIONS = ("hunt", "scan", "timeline_summary")


class Fallback(BaseModel):
    """An alternative tool tried when the step's tool fails."""

    tool: str
    plugin: str | None = None  # dissect_plugin: Dissect plugin name
    input: str | None = None  # selector override ("target" = original evidence)
    options: dict = Field(default_factory=dict)

    @property
    def is_dissect(self) -> bool:
        return self.tool == "dissect_plugin"


class Step(BaseModel):
    """One node of a profile's DAG."""

    id: str
    tool: str | None = None
    action: Literal["hunt", "scan", "timeline_summary"] | None = None
    input: str = "root"  # locate selector; the step runs once per location
    options: dict = Field(default_factory=dict)  # "$selector" → first path of that selector
    needs: list[str] = Field(default_factory=list)
    timeout: float | None = None  # seconds
    retries: int | None = None
    optional: bool = False
    fallbacks: list[Fallback] = Field(default_factory=list)
    description: str = ""

    @model_validator(mode="before")
    @classmethod
    def _coerce_fallbacks(cls, data):
        if isinstance(data, dict):
            data["fallbacks"] = [
                {"tool": f} if isinstance(f, str) else f for f in data.get("fallbacks") or []
            ]
        return data

    @model_validator(mode="after")
    def _one_kind(self):
        if bool(self.tool) == bool(self.action):
            raise ValueError(f"step '{self.id}': exactly one of tool / action is required")
        return self


class Profile(BaseModel):
    name: str
    description: str = ""
    platforms: list[str] = Field(default_factory=lambda: ["windows"])
    steps: list[Step]

    @model_validator(mode="after")
    def _valid_graph(self):
        ids = [s.id for s in self.steps]
        if len(ids) != len(set(ids)):
            raise ValueError(f"profile '{self.name}': duplicate step ids")
        known = set(ids)
        for step in self.steps:
            missing = set(step.needs) - known
            if missing:
                raise ValueError(f"profile '{self.name}': step '{step.id}' needs unknown {missing}")
        _topological_order(self.steps)  # raises on cycles
        return self

    def summary(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "platforms": self.platforms,
            "steps": [s.id for s in self.steps],
        }


def _topological_order(steps: list[Step]) -> list[str]:
    remaining = {s.id: set(s.needs) for s in steps}
    order: list[str] = []
    while remaining:
        ready = sorted(k for k, deps in remaining.items() if not deps)
        if not ready:
            raise ValueError(f"dependency cycle between steps: {sorted(remaining)}")
        for k in ready:
            order.append(k)
            del remaining[k]
        for deps in remaining.values():
            deps.difference_update(ready)
    return order


def load_profile(name: str, directory: Path = PROFILES_DIR) -> Profile:
    path = directory / f"{name}.yaml"
    if not path.exists():
        available = ", ".join(p["name"] for p in list_profiles(directory))
        raise ValueError(f"Unknown profile '{name}'. Available: {available}")
    data = yaml.safe_load(path.read_text()) or {}
    return Profile(name=name, **data)


def list_profiles(directory: Path = PROFILES_DIR) -> list[dict]:
    return [load_profile(p.stem, directory).summary() for p in sorted(directory.glob("*.yaml"))]


def recommend_profiles(platform: str) -> list[str]:
    """Profiles applicable to a platform, most relevant first."""
    if platform == "windows":
        return ["windows-triage", "windows-full", "ransomware", "persistence", "registry-only"]
    return ["scan-only"]


def auto_profile(platform: str) -> str:
    return recommend_profiles(platform)[0]
