"""Streamed ASCII + UTF-16LE strings extraction (standard library only).

Shared by ``strings_native`` (main image) and the worker runner (``blkls``
output of unallocated space), which installs DEFAIR without dependencies.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

CHUNK = 4 * 1024 * 1024
KEEP = 64 * 1024  # bytes re-scanned with the next chunk (strings crossing a boundary)
MAX_STRING = 32 * 1024


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
