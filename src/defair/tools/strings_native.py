"""Native strings extraction (ASCII + UTF-16LE), streamed, for IOC search.

Extracts every printable string of at least ``min_length`` characters from
``pagefile.sys`` / ``swapfile.sys`` (memory paged to disk: command lines,
URLs, credentials, fragments of deleted files) or any file, and writes them
as ``offset<TAB>encoding<TAB>string`` lines — the index the watchlist search
(ripgrep) reads. Strings are not inserted in the case database (there are
millions); each source gets one summary artifact with the TSV path, count
and SHA-256.

Input:
- ``pagefile.sys`` / ``swapfile.sys``, or any file with ``whole_file=true``:
  extracted as is;
- a collection folder: its ``pagefile.sys`` / ``swapfile.sys`` / ``hiberfil.sys``;
- any other file is opened as a disk image: the same files read through
  Dissect, streamed — never copied to the workspace (a raw image is never
  mistaken for a file to extract whole).

``hiberfil.sys`` is compressed (Xpress): it is reported as skipped until the
memory worker (v0.8) decompresses it. Unallocated space comes from the
Sleuth Kit worker (v0.5, ``blkls``).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator
from pathlib import Path

from defair.models.tool_manifest import ToolCategory, ToolManifest
from defair.tools.native import NativeTool

CHUNK = 4 * 1024 * 1024
KEEP = 64 * 1024  # bytes re-scanned with the next chunk (strings crossing a boundary)
MAX_STRING = 32 * 1024
DEFAULT_SOURCES = ("pagefile.sys", "swapfile.sys", "hiberfil.sys")
COMPRESSED = {"hiberfil.sys"}


def _patterns(min_length: int) -> tuple[tuple[str, re.Pattern], ...]:
    return (
        ("ascii", re.compile(rb"[\x20-\x7e]{%d,%d}" % (min_length, MAX_STRING))),
        ("utf-16le", re.compile(rb"(?:[\x20-\x7e]\x00){%d,%d}" % (min_length, MAX_STRING))),
    )


def extract_strings(fh, min_length: int = 6) -> Iterator[tuple[int, str, str]]:
    """Yield (offset, encoding, string) for every string of the stream, in order per encoding."""
    patterns = _patterns(min_length)
    carry = b""
    base = 0  # absolute offset of the next chunk
    next_start = {name: 0 for name, _ in patterns}
    while True:
        chunk = fh.read(CHUNK)
        final = not chunk
        buf = carry + chunk
        buf_base = base - len(carry)
        limit = len(buf) if final else len(buf) - KEEP
        resume = len(buf) if final else max(0, len(buf) - KEEP)
        found: list[tuple[int, str, str]] = []
        for name, pattern in patterns:
            for match in pattern.finditer(buf):
                if not final and match.end() > limit:
                    resume = min(resume, match.start())  # may continue in the next chunk
                    break
                start = buf_base + match.start()
                if start < next_start[name]:
                    continue  # already emitted from the previous buffer
                raw = match.group()
                text = raw.decode("ascii") if name == "ascii" else raw.decode("utf-16-le")
                found.append((start, name, text))
                next_start[name] = start + len(raw)
        found.sort()
        yield from found
        if final:
            return
        carry = buf[resume:]
        base += len(chunk)


class StringsNativeTool(NativeTool):
    """Extract strings from pagefile / swapfile (or any file) into a searchable index."""

    module = "re"  # pure Python: always available

    @staticmethod
    def manifest() -> ToolManifest:
        return ToolManifest(
            name="strings_native",
            display_name="Strings extraction (native)",
            allowed_options=["min_length", "sources", "whole_file"],
            vendor="DEFAIR",
            description="ASCII + UTF-16LE strings of pagefile.sys / swapfile.sys (or any file), streamed, for IOC search.",
            category=ToolCategory.GENERAL,
            command="python-native",
            runtime="python",
            timeout=14400,
            capabilities=["strings", "pagefile", "swapfile", "ioc_search"],
            input_types=["pagefile.sys", "swapfile.sys", "any file", "collection", "disk image"],
            output_formats=["tsv", "jsonl"],
            artifact_types=["windows.strings.extract"],
            sans_categories=[],
        )

    def _inputs(self, input_path: str) -> list[Path]:
        return [Path(input_path)]

    def parse_file(self, path: Path) -> Iterator[dict]:
        options = getattr(self, "_options", {})
        min_length = int(options.get("min_length") or 6)
        wanted = tuple(s.strip().lower() for s in str(options.get("sources") or "").split(",") if s.strip()) \
            or DEFAULT_SOURCES
        for name, opener, origin in _sources(path, wanted, bool(options.get("whole_file"))):
            yield self._extract(name, opener, origin, min_length)

    async def run(self, input_path: str, output_dir: str, case_id: str, **kwargs):
        self._options = {k: kwargs.get(k) for k in ("min_length", "sources", "whole_file")}
        return await super().run(input_path, output_dir, case_id, **kwargs)

    def _extract(self, name: str, opener, origin: str, min_length: int) -> dict:
        record = {"source": name, "origin": origin, "min_length": min_length}
        if name.lower() in COMPRESSED:
            return {**record, "skipped": "compressed (Xpress) — decompressed by the memory worker (v0.8)"}
        out = (self.output_dir or Path(".")) / f"{name}.tsv"
        digest = hashlib.sha256()
        counts = {"ascii": 0, "utf-16le": 0}
        with opener() as fh, out.open("w", encoding="utf-8") as fo:
            for offset, encoding, text in extract_strings(fh, min_length):
                line = f"{offset}\t{encoding}\t{text}\n"
                fo.write(line)
                digest.update(line.encode("utf-8"))
                counts[encoding] += 1
        return {**record, "tsv": str(out), "sha256": digest.hexdigest(), "strings": sum(counts.values()),
                "ascii": counts["ascii"], "utf16": counts["utf-16le"]}


def _sources(path: Path, wanted: tuple[str, ...], whole_file: bool = False) -> Iterator[tuple[str, object, str]]:
    """(name, opener, origin) of each file to extract."""
    if path.is_dir():
        for candidate in sorted(path.rglob("*")):
            if candidate.is_file() and candidate.name.lower() in wanted:
                yield candidate.name, (lambda c=candidate: c.open("rb")), str(candidate)
        return
    if whole_file or path.name.lower() in wanted:
        yield path.name, lambda: path.open("rb"), str(path)
        return
    yield from _image_sources(path, wanted)


def _image_sources(path: Path, wanted: tuple[str, ...]) -> Iterator[tuple[str, object, str]]:
    from dissect.target import Target

    try:
        target = Target.open(str(path))
    except Exception as e:
        raise ValueError(f"{path.name} is not a disk image Dissect can open "
                         "(use whole_file=true to extract this file itself)") from e
    for name in wanted:
        entry = target.fs.path(f"sysvol/{name}")
        try:
            if not entry.is_file():
                continue
        except Exception:
            continue
        yield name, entry.open, f"{path.name}:sysvol/{name}"
