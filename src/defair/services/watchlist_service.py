"""Keyword / IOC watchlists — batch search over a whole case, ripgrep-backed.

A watchlist is a YAML file of terms (literal or regex, case-insensitive),
with a severity and tags. Built-in lists ship in ``defair/data/watchlists``
(offensive tools, suspicious LOLBin command lines, RMM, exfiltration); a
case adds its own in ``/workspace/watchlists/*.yaml``.

Scopes searched:

- ``artifacts`` — the case's normalized JSONL files (the same rows as the
  database, one artifact per line), so a hit points to an ``ART-NNN``;
- ``strings``  — the strings index (``strings_native`` TSV files: pagefile,
  swapfile, unallocated space);
- ``evidence`` — the raw files of a collection (read-only; ASCII and UTF-16),
  never a disk image container.

ripgrep does the scanning; without it (dev machine) a pure-Python scan gives
the same results, slower. Each search writes a JSON report under
``/workspace/watchlists/results/`` and can create one finding per term hit.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import aiosqlite
import structlog
import yaml

log = structlog.get_logger(component="watchlist")

BUILTIN_DIR = Path(__file__).resolve().parent.parent / "data" / "watchlists"
SCOPES = ("artifacts", "strings", "evidence")
MAX_HITS_PER_TERM = 200
MAX_COUNT_PER_FILE = 10000
TEXT_PREVIEW = 300


@dataclass
class Term:
    pattern: str
    regex: bool = False
    note: str | None = None
    compiled: re.Pattern = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.compiled = re.compile(self.pattern if self.regex else re.escape(self.pattern), re.IGNORECASE)


@dataclass
class Watchlist:
    name: str
    terms: list[Term]
    description: str = ""
    severity: str = "medium"
    tags: list[str] = field(default_factory=list)
    origin: str = "builtin"


def workspace() -> Path:
    from defair.orchestrator.runs import workspace as ws

    return ws()


def case_dir() -> Path:
    return workspace() / "watchlists"


def _parse(data: dict, origin: str, fallback_name: str) -> Watchlist:
    terms = []
    for entry in data.get("terms") or []:
        if isinstance(entry, str):
            terms.append(Term(entry))
        elif isinstance(entry, dict) and entry.get("pattern"):
            terms.append(Term(str(entry["pattern"]), bool(entry.get("regex")), entry.get("note")))
    return Watchlist(
        name=str(data.get("name") or fallback_name), terms=terms,
        description=data.get("description", ""), severity=data.get("severity", "medium"),
        tags=list(data.get("tags") or []), origin=origin,
    )


def list_watchlists(extra_dir: Path | None = None) -> list[Watchlist]:
    """Built-in lists, then the case's own (a case list may override a built-in name)."""
    found: dict[str, Watchlist] = {}
    for directory, origin in ((BUILTIN_DIR, "builtin"), (extra_dir or case_dir(), "case")):
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.y*ml")):
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
                wl = _parse(data, origin if origin == "builtin" else str(path), path.stem)
            except (yaml.YAMLError, re.error) as e:
                log.warning("watchlist_invalid", path=str(path), error=str(e))
                continue
            found[wl.name] = wl
    return list(found.values())


def get_watchlist(name: str, extra_dir: Path | None = None) -> Watchlist:
    for wl in list_watchlists(extra_dir):
        if wl.name == name:
            return wl
    available = ", ".join(sorted(w.name for w in list_watchlists(extra_dir)))
    raise ValueError(f"Unknown watchlist '{name}'. Available: {available}")


def summary(wl: Watchlist) -> dict:
    return {"name": wl.name, "description": wl.description, "severity": wl.severity,
            "tags": wl.tags, "origin": wl.origin, "terms": len(wl.terms)}


# ---------------------------------------------------------------------------
# Matching (ripgrep or pure Python)
# ---------------------------------------------------------------------------


def _rg_matches(files: list[str], terms: list[Term], binary: bool = False,
                encoding: str | None = None) -> Iterator[tuple[str, int | None, str]]:
    """(file, line number / byte offset, line) of every line matching any term."""
    if not files or not terms:
        return
    literals = [t.pattern for t in terms if not t.regex]
    regexes = [t.pattern for t in terms if t.regex]
    base = ["rg", "--json", "--no-config", "-i", f"--max-count={MAX_COUNT_PER_FILE}", "--no-messages"]
    if binary:
        # raw files have no real lines: report the matched bytes only
        base += ["-a", "-b", "-o"]
    if encoding:
        base += ["-E", encoding]
    runs = []
    if literals:
        with tempfile.NamedTemporaryFile("w", suffix=".pat", delete=False, encoding="utf-8") as fh:
            fh.write("\n".join(literals) + "\n")
            runs.append((base + ["-F", "-f", fh.name], fh.name))
    if regexes:
        args = base.copy()
        for pattern in regexes:
            args += ["-e", pattern]
        runs.append((args, None))
    for args, tmp in runs:
        try:
            proc = subprocess.run([*args, "--", *files], capture_output=True, timeout=3600, check=False)
        finally:
            if tmp:
                Path(tmp).unlink(missing_ok=True)
        for line in proc.stdout.splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if event.get("type") != "match":
                continue
            data = event["data"]
            text = data["lines"].get("text")
            if text is None:  # non-UTF-8 bytes (binary scope)
                import base64

                text = base64.b64decode(data["lines"].get("bytes", "")).decode("latin-1")
            where = data.get("absolute_offset") if binary else data.get("line_number")
            yield data["path"].get("text", ""), where, text


def _py_matches(files: list[str], terms: list[Term], binary: bool = False,
                encoding: str | None = None) -> Iterator[tuple[str, int | None, str]]:
    for name in files:
        path = Path(name)
        paths = [p for p in path.rglob("*") if p.is_file()] if path.is_dir() else [path]
        for item in paths:
            try:
                raw = item.read_bytes()
            except OSError:
                continue
            text = raw.decode(encoding or "utf-8", errors="replace")
            offset = 0
            for number, line in enumerate(text.splitlines(keepends=True), 1):
                if any(t.compiled.search(line) for t in terms):
                    yield str(item), offset if binary else number, line
                offset += len(line.encode(encoding or "utf-8", errors="replace"))


def find(files: list[str], terms: list[Term], **kwargs) -> Iterator[tuple[str, int | None, str]]:
    matcher = _rg_matches if shutil.which("rg") else _py_matches
    yield from matcher(files, terms, **kwargs)


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------


async def _artifact_files(conn, case_id: str) -> list[str]:
    cursor = await conn.execute("SELECT DISTINCT path FROM normalized_files WHERE case_id = ?", (case_id,))
    return [row[0] for row in await cursor.fetchall() if Path(row[0]).is_file()]


async def _strings_files(conn, case_id: str) -> list[str]:
    cursor = await conn.execute(
        "SELECT data FROM artifacts WHERE case_id = ? AND artifact_type = 'windows.strings.extract'",
        (case_id,))
    paths = []
    for (data,) in await cursor.fetchall():
        tsv = (json.loads(data or "{}")).get("tsv")
        if tsv and Path(tsv).is_file():
            paths.append(tsv)
    return paths


async def _evidence_roots(conn, case_id: str) -> list[str]:
    from defair.services.evidence_service import list_evidence

    roots = []
    for evidence in await list_evidence(conn, case_id=case_id):
        prepared = evidence.prepared or {}
        kind = (prepared.get("source") or {}).get("kind") or prepared.get("kind")
        if kind in ("disk_image", "kape_vhdx"):
            # search the files carved from the image, not the container format
            base = prepared.get("base")
            if base and Path(base).exists():
                roots.append(base)
            continue
        base = prepared.get("base") or evidence.original_path
        if base and Path(base).exists():
            roots.append(base)
    return roots


def _terms_for(line: str, terms: list[Term]) -> list[Term]:
    return [t for t in terms if t.compiled.search(line)]


async def search_watchlist(
    conn: aiosqlite.Connection,
    case_id: str,
    watchlists: list[str] | None = None,
    terms: list[str] | None = None,
    scopes: tuple[str, ...] | list[str] = SCOPES,
    create_findings: bool = False,
    extra_dir: Path | None = None,
) -> dict:
    """Search watchlists (or ad-hoc terms) across a case.

    Args:
        watchlists: Watchlist names; all of them when neither this nor
            ``terms`` is given.
        terms: Ad-hoc literal terms (an ``adhoc`` watchlist).
        scopes: Any of ``artifacts``, ``strings``, ``evidence``.
        create_findings: One finding per term with hits.

    Returns:
        Report: per watchlist and term, hit counts per scope and the first hits.
    """
    from defair.services.case_service import resolve_case_id

    unknown = set(scopes) - set(SCOPES)
    if unknown:
        raise ValueError(f"Unknown scope(s) {sorted(unknown)}; use {', '.join(SCOPES)}")
    case_id = await resolve_case_id(conn, case_id)
    selected: list[Watchlist] = []
    if terms:
        selected.append(Watchlist(name="adhoc", terms=[Term(t) for t in terms], origin="adhoc"))
    if watchlists:
        selected.extend(get_watchlist(name, extra_dir) for name in watchlists)
    if not selected:
        selected = list_watchlists(extra_dir)
    all_terms = [t for wl in selected for t in wl.terms]

    sources = {
        "artifacts": await _artifact_files(conn, case_id) if "artifacts" in scopes else [],
        "strings": await _strings_files(conn, case_id) if "strings" in scopes else [],
        "evidence": await _evidence_roots(conn, case_id) if "evidence" in scopes else [],
    }
    hits: dict[int, list[dict]] = {id(t): [] for t in all_terms}
    counts: dict[int, dict[str, int]] = {id(t): dict.fromkeys(SCOPES, 0) for t in all_terms}
    artifact_ids: dict[int, set[str]] = {id(t): set() for t in all_terms}

    def record(term: Term, scope: str, hit: dict) -> None:
        counts[id(term)][scope] += 1
        if len(hits[id(term)]) < MAX_HITS_PER_TERM:
            hits[id(term)].append({"scope": scope, **hit})

    for path, line_number, line in find(sources["artifacts"], all_terms):
        try:
            art = json.loads(line)
        except ValueError:
            art = {}
        for term in _terms_for(line, all_terms):
            if art.get("id"):
                artifact_ids[id(term)].add(art["id"])
            record(term, "artifacts", {
                "artifact": art.get("artifact_number"), "artifact_type": art.get("artifact_type"),
                "timestamp": art.get("timestamp"), "description": (art.get("description") or "")[:TEXT_PREVIEW],
                "file": path, "line": line_number,
            })
    for path, _, line in find(sources["strings"], all_terms):
        offset, encoding, text = (line.rstrip("\n").split("\t", 2) + ["", ""])[:3]
        for term in _terms_for(text or line, all_terms):
            record(term, "strings", {"file": path, "offset": int(offset) if offset.isdigit() else None,
                                     "encoding": encoding, "text": text[:TEXT_PREVIEW]})
    seen_evidence: set[tuple] = set()
    for encoding in (None, "utf-16le"):
        for path, offset, line in find(sources["evidence"], all_terms, binary=True, encoding=encoding):
            for term in _terms_for(line, all_terms):
                key = (id(term), path, offset)
                if key in seen_evidence:
                    continue
                seen_evidence.add(key)
                match = term.compiled.search(line)
                context = line[max(0, match.start() - 80):match.end() + 80] if match else line[:160]
                record(term, "evidence", {"file": path, "offset": offset,
                                          "encoding": encoding or "ascii/utf-8",
                                          "text": "".join(c if c.isprintable() else "." for c in context)})

    report_lists = []
    total = 0
    for wl in selected:
        entries = []
        for term in wl.terms:
            n = sum(counts[id(term)].values())
            if not n:
                continue
            total += n
            entries.append({"term": term.pattern, "regex": term.regex, "note": term.note,
                            "hits": counts[id(term)], "total": n, "first_hits": hits[id(term)],
                            "_artifact_ids": sorted(artifact_ids[id(term)])})
        report_lists.append({**summary(wl), "matched_terms": len(entries), "terms_hit": entries})

    report = {
        "case_id": case_id,
        "generated_at": datetime.now(UTC).isoformat(),
        "engine": "ripgrep" if shutil.which("rg") else "python",
        "scopes": {scope: len(files) for scope, files in sources.items() if scope in scopes},
        "total_hits": total,
        "watchlists": report_lists,
        "findings": [],
    }
    if create_findings:
        report["findings"] = await _create_findings(conn, case_id, selected, report_lists)
    for wl in report_lists:
        for entry in wl["terms_hit"]:
            entry.pop("_artifact_ids", None)
    report["report_path"] = _write_report(report, [w.name for w in selected])
    log.info("watchlist_search_completed", case_id=case_id, watchlists=[w.name for w in selected],
             hits=total, engine=report["engine"])
    return report


async def _create_findings(conn, case_id: str, selected: list[Watchlist], lists: list[dict]) -> list[str]:
    from defair.services.finding_service import create_finding

    by_name = {wl.name: wl for wl in selected}
    created = []
    for entry_list in lists:
        wl = by_name[entry_list["name"]]
        for entry in entry_list["terms_hit"]:
            finding = await create_finding(
                conn, case_id=case_id,
                title=f"Watchlist {wl.name}: {entry['term']}",
                description=(f"'{entry['term']}' ({entry['note'] or wl.description}) found "
                             f"{entry['total']} time(s): " +
                             ", ".join(f"{scope} {n}" for scope, n in entry["hits"].items() if n)),
                severity=wl.severity, confidence="low", source="watchlist",
                artifact_ids=entry["_artifact_ids"][:500],
                detection_refs=[{"engine": "watchlist", "watchlist": wl.name, "origin": wl.origin,
                                 "term": entry["term"], "regex": entry["regex"], "hits": entry["hits"]}],
            )
            created.append(finding.get("finding_number"))
    return created


def _write_report(report: dict, names: list[str]) -> str | None:
    try:
        directory = case_dir() / "results"
        directory.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        path = directory / f"{stamp}_{'-'.join(names)[:80] or 'all'}.json"
        path.write_text(json.dumps(report, indent=2, default=str))
        return str(path)
    except OSError as e:  # read-only workspace (tests, dev)
        log.warning("watchlist_report_not_written", error=str(e))
        return None
