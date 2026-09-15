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
- `src/defair/normalizers/hayabusa.py` — Hayabusa normalizer (v0.3)
- `src/defair/database.py` — SQLite schema and connection management
- `src/defair/config.py` — YAML config with Pydantic validation

## v0.3 capabilities

- **Hunt**: `defair hunt /evidence/ --case CASE-xxx` — Hayabusa Sigma detection on EVTX
- **Timeline**: `defair timeline summary/search/export --case CASE-xxx`
- **Findings**: `defair findings list/get/create --case CASE-xxx`
- **Search**: `defair search "IOC" --case CASE-xxx`
- **MCP tools**: `hunt_evtx`, `build_timeline`, `search_timeline`, `list_findings`, `search_ioc`
- **Finding IDs**: `FND-NNN` — auto-created from Hayabusa high/critical detections

## Conventions

- Python 3.13+
- Async-first services, `run_sync()` wrapper for CLI
- Structured logging with structlog (JSON in prod, console in dev)
- Case IDs: `CASE-YYYY-NNN`, Evidence IDs: `EVD-NNN`, Finding IDs: `FND-NNN`
- All timestamps in UTC, ISO 8601
- Evidence is always read-only — never modify the source file
- Docker images are always pulled from GHCR — never build locally
