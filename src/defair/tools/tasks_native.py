"""Native Scheduled Tasks parser (``Windows/System32/Tasks/**`` XML).

Each registered task is an XML file (UTF-16): what it runs (Exec command
line, COM handler), when (triggers), as whom (principal, run level), who
registered it and when. A classic persistence mechanism — and the XML stays
even when the TaskScheduler event log was cleared.

``RegistrationInfo/Date`` is written in the host's local time, usually
without a zone: the time is then kept as text (``registration_date_local``),
never assumed to be UTC.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.native import NativeTool

_TZ = re.compile(r"(Z|[+-]\d{2}:\d{2})$")


class TasksNativeTool(NativeTool):
    """Parse Windows Scheduled Task definitions."""

    module = "defusedxml"

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="tasks_native",
            display_name="Scheduled Tasks (native)",
            allowed_options=[],
            vendor="DEFAIR (defusedxml)",
            description="Scheduled Task XML definitions: actions, triggers, principal, author, registration date.",
            category=ToolCategory.PERSISTENCE,
            command="python-native",
            runtime="python",
            timeout=600,
            capabilities=["scheduled_tasks", "persistence"],
            input_types=["Windows/System32/Tasks directory", "task XML file"],
            output_formats=["jsonl"],
            artifact_types=["windows.scheduled_task.definition"],
            sans_categories=["persistence"],
        )

    def _inputs(self, input_path: str) -> list[Path]:
        path = Path(input_path)
        if path.is_dir():
            return sorted(p for p in path.rglob("*") if p.is_file() and not p.name.startswith("$"))
        return [path]

    def parse_file(self, path: Path) -> Iterator[dict]:
        raw = path.read_bytes()
        if b"<Task" not in raw and "<Task".encode("utf-16-le") not in raw:
            return  # not a task definition (e.g. a .job or stray file)
        task = parse_task(raw)
        task["task_path"] = task_path(path)
        yield task


def task_path(path: Path) -> str:
    parts = list(path.parts)
    lower = [p.lower() for p in parts]
    if "tasks" in lower:
        index = len(lower) - 1 - lower[::-1].index("tasks")
        return "\\" + "\\".join(parts[index + 1:])
    return path.name


def _text(node, path: str, ns: dict) -> str | None:
    found = node.find(path, ns)
    return found.text.strip() if found is not None and found.text else None


def parse_task(raw: bytes) -> dict:
    from defusedxml import ElementTree

    root = ElementTree.fromstring(raw)
    uri = root.tag.split("}")[0].strip("{") if root.tag.startswith("{") else ""
    ns = {"t": uri} if uri else {}
    p = "t:" if uri else ""

    task: dict = {
        "uri": _text(root, f"{p}RegistrationInfo/{p}URI", ns),
        "author": _text(root, f"{p}RegistrationInfo/{p}Author", ns),
        "description": _text(root, f"{p}RegistrationInfo/{p}Description", ns),
        "source": _text(root, f"{p}RegistrationInfo/{p}Source", ns),
        "enabled": _text(root, f"{p}Settings/{p}Enabled", ns),
        "hidden": _text(root, f"{p}Settings/{p}Hidden", ns),
        "user_id": _text(root, f"{p}Principals/{p}Principal/{p}UserId", ns),
        "group_id": _text(root, f"{p}Principals/{p}Principal/{p}GroupId", ns),
        "logon_type": _text(root, f"{p}Principals/{p}Principal/{p}LogonType", ns),
        "run_level": _text(root, f"{p}Principals/{p}Principal/{p}RunLevel", ns),
    }
    date = _text(root, f"{p}RegistrationInfo/{p}Date", ns)
    if date:
        if _TZ.search(date):
            task["registration_date"] = date
        else:
            task["registration_date_local"] = date

    actions = []
    for exec_node in root.findall(f"{p}Actions/{p}Exec", ns):
        actions.append({
            "type": "exec",
            "command": _text(exec_node, f"{p}Command", ns),
            "arguments": _text(exec_node, f"{p}Arguments", ns),
            "working_directory": _text(exec_node, f"{p}WorkingDirectory", ns),
        })
    for com in root.findall(f"{p}Actions/{p}ComHandler", ns):
        actions.append({"type": "com_handler", "class_id": _text(com, f"{p}ClassId", ns),
                        "data": _text(com, f"{p}Data", ns)})
    task["actions"] = actions

    triggers = []
    node = root.find(f"{p}Triggers", ns)
    for trigger in list(node) if node is not None else []:
        triggers.append({
            "type": trigger.tag.split("}")[-1],
            "start": _text(trigger, f"{p}StartBoundary", ns),
            "enabled": _text(trigger, f"{p}Enabled", ns),
            "user_id": _text(trigger, f"{p}UserId", ns),
            "interval": _text(trigger, f"{p}Repetition/{p}Interval", ns),
        })
    task["triggers"] = triggers
    return {k: v for k, v in task.items() if v not in (None, [], "")}
