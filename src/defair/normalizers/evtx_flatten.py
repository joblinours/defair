"""Generic EVTX record flattening and the EventID knowledge base.

Two record shapes are supported:
- EvtxECmd ``Payload`` JSON: ``{"EventData": {"Data": [{"@Name": ..., "#text": ...}]}}``
- pyevtx-rs / python-evtx JSON: ``{"Event": {"System": {...}, "EventData": {...}}}``

Both become one flat dict: ``System`` fields under stable names (EventID,
Channel, Computer, Provider, TimeCreated, EventRecordID, ...) and every
``EventData`` / ``UserData`` value under its ``Name`` (unnamed values as
``Data_<n>``, nested ``UserData`` keys dotted).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

CATALOG_FILE = Path(__file__).resolve().parent.parent / "data" / "evtx_catalog.yaml"

_SYSTEM_FIELDS = (
    "EventID", "Version", "Level", "Task", "Opcode", "Keywords",
    "EventRecordID", "Channel", "Computer",
)


def _text(value: Any) -> Any:
    """Unwrap ``{"#text": x}`` / ``{"Value": x}`` wrappers."""
    if isinstance(value, dict):
        for key in ("#text", "Value", "value"):
            if key in value:
                return value[key]
    return value


def _attrs(value: Any) -> dict:
    if not isinstance(value, dict):
        return {}
    attrs = value.get("#attributes") or {}
    # python-evtx / xmltodict style: "@Name"
    attrs.update({k[1:]: v for k, v in value.items() if k.startswith("@")})
    return attrs


def _flatten_data(data: Any, flat: dict, prefix: str = "") -> None:
    """EventData / UserData content → flat keys."""
    if data is None:
        return
    if isinstance(data, list):
        for i, item in enumerate(data):
            attrs = _attrs(item)
            if "Name" in attrs:
                flat[f"{prefix}{attrs['Name']}"] = _text(item) if isinstance(item, dict) else item
            elif isinstance(item, dict) and "#text" not in item:
                _flatten_data(item, flat, prefix)
            else:
                flat[f"{prefix}Data_{i}"] = _text(item)
        return
    if isinstance(data, dict):
        if "Data" in data and len([k for k in data if not k.startswith(("#", "@"))]) == 1:
            _flatten_data(data["Data"], flat, prefix)
            return
        for key, value in data.items():
            if key.startswith(("#attributes", "@xmlns")):
                continue
            if isinstance(value, dict) and "#text" not in value and "Value" not in value:
                _flatten_data(value, flat, f"{prefix}{key}.")
            elif isinstance(value, list) and key == "Data":
                _flatten_data(value, flat, prefix)
            else:
                flat[f"{prefix}{key}"] = _text(value)
        return
    flat[f"{prefix}Data" if prefix else "Data"] = data


def flatten_event(record: dict) -> dict:
    """Flatten one EVTX record (any supported shape) into a single-level dict."""
    event = record.get("Event", record)
    flat: dict = {}

    system = event.get("System") or {}
    for name in _SYSTEM_FIELDS:
        if name in system:
            flat[name] = _text(system[name])
    provider = system.get("Provider")
    if provider is not None:
        flat["Provider"] = _attrs(provider).get("Name") or _text(provider)
    time_created = system.get("TimeCreated")
    if time_created is not None:
        flat["TimeCreated"] = _attrs(time_created).get("SystemTime") or _text(time_created)
    execution = _attrs(system.get("Execution"))
    if execution:
        flat["ProcessID"] = execution.get("ProcessID")
        flat["ThreadID"] = execution.get("ThreadID")
    security = _attrs(system.get("Security"))
    if security.get("UserID"):
        flat["UserID"] = security["UserID"]

    _flatten_data(event.get("EventData"), flat)
    user_data = event.get("UserData")
    if isinstance(user_data, dict):
        for value in user_data.values():  # single wrapper element, e.g. <LogFileCleared>
            _flatten_data(value, flat)

    return {k: v for k, v in flat.items() if v is not None}


# ---------------------------------------------------------------------------
# EventID catalog
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def load_catalog(path: Path = CATALOG_FILE) -> dict[tuple[str, str], dict]:
    """``(channel lowercase, event id) → entry``; ``""`` channel = any channel."""
    data = yaml.safe_load(path.read_text()) or {}
    catalog: dict[tuple[str, str], dict] = {}
    for channel, events in (data.get("channels") or {}).items():
        for event_id, entry in (events or {}).items():
            catalog[(channel.lower(), str(event_id))] = entry
    return catalog


def lookup_event(channel: str | None, event_id: Any) -> dict | None:
    """Catalog entry for an event: exact channel first, then channel-agnostic."""
    catalog = load_catalog()
    eid = str(event_id).strip() if event_id is not None else ""
    return catalog.get(((channel or "").lower(), eid)) or catalog.get(("*", eid))
