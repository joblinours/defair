# DEFAIR — Project Guide

## What is this?

DEFAIR is a MCP-first DFIR (Digital Forensics & Incident Response) platform.
Every forensic capability is exposed simultaneously via CLI and MCP.

## Architecture

```
CLI (click)          MCP (FastMCP)
     │                     │
     └─────────┬───────────┘
               │
        Service Layer (async)
               │
     ┌─────────┴──────────┐
     │                    │
  SQLite              Docker SDK
  (aiosqlite)         (container_service)
                          │
               Forensic Containers
               (evidence :ro, workspace :rw)
```

**Rule:** No business logic in CLI or MCP layers. Both call the same async service functions.

**Container pattern:** The wrapper runs on the HOST and orchestrates Docker containers
via the Docker SDK. One container per investigation. Evidence is mounted read-only.

## Development

```bash
# Install in dev mode (use the venv)
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# CLI
defair --help
defair case create "My case"
defair cases list

# MCP server (stdio)
defair-mcp
```

## Adding a new MCP tool

1. Add the service function in `src/defair/services/`
2. Add the CLI command in `src/defair/cli/`
3. Add the MCP tool in `src/defair/mcp_server/server.py` using `@mcp.tool()`
4. Add tests in `tests/` (unit + CLI + MCP integration)
5. Both CLI and MCP must call the same service function

## Key files

- `src/defair/services/` — shared service layer (the core)
- `src/defair/services/container_service.py` — Docker orchestration (runs on HOST)
- `src/defair/services/hunting_service.py` — Hayabusa hunting orchestration (v0.3)
- `src/defair/services/finding_service.py` — Findings CRUD + auto-creation (v0.3)
- `src/defair/services/timeline_service.py` — Timeline search/export (v0.3)
- `src/defair/services/search_service.py` — IOC search across artifacts (v0.3)
- `src/defair/cli/` — click commands
- `src/defair/cli/containers.py` — container management CLI
- `src/defair/cli/hunt.py` — `defair hunt` command (v0.3)
- `src/defair/cli/timeline.py` — `defair timeline` commands (v0.3)
- `src/defair/cli/findings.py` — `defair findings` commands (v0.3)
- `src/defair/cli/search.py` — `defair search` command (v0.3)
- `src/defair/mcp_server/server.py` — FastMCP tools
- `src/defair/models/` — Pydantic data models
- `src/defair/models/finding.py` — Finding model (v0.3)
- `src/defair/tools/hayabusa.py` — Hayabusa tool wrapper (v0.3)
- `src/defair/tools/prefetch.py` — Cross-platform Prefetch parser (v0.3.1, replaces PECmd)
- `src/defair/tools/yara_scanner.py` — YARA rule scanner (v0.3.5)
- `src/defair/normalizers/hayabusa.py` — Hayabusa normalizer (v0.3)
- `src/defair/normalizers/yara.py` — YARA normalizer (v0.3.5)
- `src/defair/services/scanning_service.py` — Mass scanning orchestration (v0.3.5)
- `src/defair/tools/raijin.py` — Raijin YARA + Sigma scanner wrapper (v0.3.7, replaces yara_scanner)
- `src/defair/normalizers/raijin.py` — Raijin normalizer, resolves rule provenance (v0.3.7)
- `src/defair/rules/` — rule supply chain: `sources.yaml`, `lock/` (pinned refs + per-file SHA-256), sync / verify / assemble / conflicts (v0.3.7)
- `engines/raijin/` — vendored Raijin (Rust); changes listed in `engines/raijin/LICENSING.md`
- `src/defair/normalizers/pipeline.py` — normalization pipeline: envelope, UTC timestamps, deterministic ids, JSONL, bulk insert (v0.3.8)
- `src/defair/normalizers/timestamps.py` — `to_utc_iso` / `parse_timestamp` (v0.3.8)
- `src/defair/normalizers/evtx_flatten.py` + `src/defair/data/evtx_catalog.yaml` — EVTX flattening + EventID knowledge base (v0.3.8)
- `src/defair/services/normalization_service.py` — replay / rerun / stats (v0.3.8)
- `src/defair/tools/native.py`, `evtx_native.py`, `lnk_native.py` — pure-Python fallback parsers (v0.3.8)
- `src/defair/sources/` — evidence detection, preparation (ZIP / Generaptor / DFIR-ORC / Dissect image carving), artifact location (v0.4)
- `src/defair/orchestrator/` — profiles, DAG executor, step runner (fallback chains per engine), profile runs + background worker (v0.4)
- `src/defair/profiles/*.yaml` — built-in analysis profiles (v0.4)
- `src/defair/tools/dissect_plugin.py` + `normalizers/dissect.py` — Dissect plugins as a parsing engine (v0.4)
- `engines/orc-decrypt/` — vendored ANSSI orc-decrypt (LGPL-2.1), provides `unstream`
- `src/defair/tools/ntfs_parse.py`, `indx_native.py`, `logfile_native.py` — NTFS structures, $I30 slack, $LogFile (v0.4.5)
- `src/defair/tools/*_native.py` — MPLog, PSReadLine, Scheduled Tasks, WebCache, RDP cache, IIS, strings (v0.4.5)
- `src/defair/tools/chainsaw.py` + `normalizers/chainsaw.py` — Chainsaw on the pinned Sigma store (v0.4.5)
- `src/defair/data/evtx_views.yaml` + `services/evtx_view_service.py` — typed EVTX views (v0.4.5)
- `src/defair/services/host_profile_service.py` — host profile, a source per fact (v0.4.5)
- `src/defair/services/watchlist_service.py` + `data/watchlists/*.yaml` — ripgrep watchlists (v0.4.5)
- `src/defair/database.py` — SQLite schema, migrations (`PRAGMA user_version`) and connection management
- `src/defair/config.py` — YAML config with Pydantic validation

## v0.3 capabilities

- **Hunt**: `defair hunt /evidence/ --case CASE-xxx` — Hayabusa Sigma detection on EVTX
- **Timeline**: `defair timeline summary/search/export --case CASE-xxx`
- **Findings**: `defair findings list/get/create --case CASE-xxx`
- **Search**: `defair search "IOC" --case CASE-xxx`
- **Scan YARA**: `defair scan yara /evidence/ --case CASE-xxx` — mass YARA scanning (v0.3.5)
- **Scan Sigma**: `defair scan sigma /evidence/logs/ --case CASE-xxx` — mass Sigma scanning (v0.3.5)
- **MCP tools**: `hunt_evtx`, `build_timeline`, `search_timeline`, `list_findings`, `search_ioc`, `scan_yara`, `scan_sigma`
- **Finding IDs**: `FND-NNN` — auto-created from Hayabusa/YARA detections
- **Custom rules**: Mount `/rules/yara/` and `/rules/sigma/` for custom rule sets

## v0.4.5

- New EZ Tools: RecentFileCacheParser, SumECmd, bstrings (needs `stdin_tty`), rla; `input: step:<id>` feeds a step with another step's output
- Native parsers: `indx_native`, `logfile_native`, `mplog_native`, `psreadline_native`, `tasks_native`, `webcache_native`, `rdpcache_native`, `iis_native`, `strings_native`
- `defair evtx view <name>`, `defair host profile`, `defair watchlist search`, `defair hunt --engine chainsaw`
- A local time without a zone is kept as text (``*_local``), never passed as a timestamp

## v0.4.1

- `--case` takes a case number, name or id (`case_service.resolve_case_id`)
- `findings get FND-NNN` / `artifacts get ART-NNN` / `artifacts list --contains …` (`services/artifact_service.py`)
- Logs: stderr + JSON file `/workspace/logs/defair.log` in containers (PID 1 tails it → `docker logs`); never print logs on stdout

## v0.4

- **Investigate**: `defair run start --case CASE-xxx --evidence <EVD-NNN|path> --profile auto|windows-triage|… --engine auto|ez|dissect`, then `defair run status PRUN-NNN`
- **Prepare**: `defair evidence prepare EVD-NNN [--password] [--private-key /keys/x.pem]`
- Profile steps: EZ Tools first, native + Dissect plugin fallbacks; add a profile = add a YAML file

## v0.3.6 → v0.3.8

- **Hardening**: containers drop all capabilities, no network, read-only rootfs, host UID; evidence only from `container.evidence_roots`; MCP `run_tool` instead of shell
- **Scan**: `defair scan yara|sigma|evidence --profile precise|broad` (Raijin); `defair rules status|verify|conflicts|lock|sync`
- **Normalization**: `defair normalize replay|rerun|stats`; `defair timeline export --format timesketch`

## Conventions

- Python 3.13+
- Async-first services, `run_sync()` wrapper for CLI
- Structured logging with structlog (JSON in prod, console in dev)
- Case IDs: `CASE-YYYY-NNN`, Evidence IDs: `EVD-NNN`, Finding IDs: `FND-NNN`
- All timestamps in UTC, ISO 8601
- Evidence is always read-only — never modify the source file
- Docker images are always pulled from GHCR — never build locally
- Every download in the image is pinned (version/commit + SHA-256): `docker/checksums.sha256`, `src/defair/rules/lock/`
- Detection rules: never add a source without pinning it (`defair rules lock --refresh`, review + commit the lock)
- Timestamps: always through `to_utc_iso` / `parse_timestamp`; never substitute "now" for a missing time
- Artifacts are inserted through the normalization pipeline (`normalize_run` / `bulk_insert`), never row by row
- MCP never exposes arbitrary shell: `exec_in_container` only exists with `mcp.allow_exec: true`; agents use `run_tool`
- `external_tool/` holds reference sources and is never committed
- Secrets (archive passwords, key passphrases) never go on a command line, in logs, in the DB or in run.json: CLI envvars / exec environment / 0600 temp file
- Parallel DB writes: allocate human-readable numbers under `database.db_lock(conn)`
