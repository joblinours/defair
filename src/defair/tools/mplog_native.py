"""Native Microsoft Defender MPLog parser.

``ProgramData/Microsoft/Windows Defender/Support/MPLog-*.log`` (UTF-16) is
Defender's support log. Kept for weeks, it survives event log clearing and
records far more than detections:

- detections (``DETECTIONEVENT``, ``DETECTION_ADD``, ``threat:``);
- processes Defender measured (``ProcessImageName``, with the slowest file):
  evidence of execution;
- files hashed by cloud lookups (``SDN query`` lines with SHA-1 / SHA-256);
- exclusions, original file names of renamed binaries, blocked files.

Times carry a ``Z`` / offset on recent versions; a line without one is local
time with no zone recorded — its time is kept as text, never assumed UTC.

References: CrowdStrike "How to use Microsoft Protection Logging for forensic
investigations"; Intrinsec "Hunt MPLogs".
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.native import NativeTool

TS = r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?P<tz>Z|[+-]\d{2}:\d{2})?)"

# (event kind, pattern) — the first match wins
PATTERNS: list[tuple[str, re.Pattern]] = [
    ("detection", re.compile(TS + r"\s.*DETECTIONEVENT\s(?P<source>MPSOURCE_\S+)\s(?P<threat>\S+)"
                                  r"\s(?P<target>.*)$")),
    ("detection", re.compile(TS + r"\s.*DETECTION_ADD\S*\s(?P<threat>\S+)\s(?P<target>.*)$")),
    ("detection", re.compile(TS + r"\s.*[Tt]hreat(?:\s[Nn]ame)?:\s(?P<threat>.+)$")),
    ("process", re.compile(TS + r"\sProcessImageName:\s(?P<process>.*?),\s(?:Pid:\s(?P<pid>\d*),\s)?"
                                r"TotalTime:\s(?P<total_time>\d*),\sCount:\s(?P<count>\d*),\s"
                                r"MaxTime:\s(?P<max_time>\d*),\sMaxTimeFile:\s(?P<max_time_file>.*?),\s"
                                r"EstimatedImpact:\s(?P<impact>\d*)")),
    ("file_hash", re.compile(TS + r"\s.*SDN:Issuing SDN query for (?P<target>.+?)\s\((?P<path>.*?)\)"
                                  r"\s\(sha1=(?P<sha1>[0-9a-fA-F]+),\s?sha2=(?P<sha256>[0-9a-fA-F]+)\)")),
    ("exclusion", re.compile(TS + r"\s\[Exclusion\]\s(?P<target>.+?)\s->\s(?P<device_path>.+)$")),
    ("original_file_name", re.compile(TS + r"\s.*original file name \"(?P<original>.*)\" for "
                                           r"\"(?P<target>.*)\", hr=(?P<hr>\w+)")),
    ("blocked_file", re.compile(TS + r"\s.*\[Mini-filter\]\sBlocked file:\s(?P<target>.+?)\s"
                                     r"Process:\s(?P<process>.+?),")),
]


class MplogNativeTool(NativeTool):
    """Parse Microsoft Defender MPLog files."""

    module = "re"  # pure Python: always available

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="mplog_native",
            display_name="Defender MPLog (native)",
            allowed_options=[],
            vendor="DEFAIR",
            description="Microsoft Defender MPLog: detections, measured processes, file hashes, exclusions.",
            category=ToolCategory.DETECTION,
            command="python-native",
            runtime="python",
            timeout=1800,
            capabilities=["defender", "mplog", "detections", "program_execution", "file_hashes"],
            input_types=["MPLog-*.log", "Defender Support directory"],
            output_formats=["jsonl"],
            artifact_types=["windows.defender.mplog"],
            sans_categories=["program_execution"],
        )

    def _inputs(self, input_path: str) -> list[Path]:
        path = Path(input_path)
        if path.is_dir():
            return sorted(p for p in path.rglob("*") if p.is_file() and p.name.lower().startswith("mplog"))
        return [path]

    def parse_file(self, path: Path) -> Iterator[dict]:
        with path.open("rb") as fh:
            raw = fh.read()
        text = decode_log(raw)
        for number, line in enumerate(text.splitlines(), 1):
            event = parse_line(line)
            if event:
                event["line_number"] = number
                yield event


def decode_log(raw: bytes) -> str:
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff") or (len(raw) > 1 and raw[1] == 0):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8", errors="replace")


def parse_line(line: str) -> dict | None:
    line = line.strip()
    for kind, pattern in PATTERNS:
        match = pattern.match(line)
        if match:
            fields = {k: v for k, v in match.groupdict().items() if v not in (None, "")}
            ts = fields.pop("ts")
            tz = fields.pop("tz", None)
            event = {"event": kind, **fields, "line": line[:2000]}
            if tz:
                event["time"] = ts
            else:
                event["local_time"] = ts  # zone not recorded: not assumed UTC
            return event
    return None
