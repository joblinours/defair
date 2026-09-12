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
- `src/defair/cli/` — click commands
- `src/defair/cli/containers.py` — container management CLI
- `src/defair/mcp_server/server.py` — FastMCP tools
- `src/defair/models/` — Pydantic data models
- `src/defair/database.py` — SQLite schema and connection management
- `src/defair/config.py` — YAML config with Pydantic validation

## Conventions

- Python 3.13+
- Async-first services, `run_sync()` wrapper for CLI
- Structured logging with structlog (JSON in prod, console in dev)
- Case IDs: `CASE-YYYY-NNN`, Evidence IDs: `EVD-NNN`
- All timestamps in UTC, ISO 8601
- Evidence is always read-only — never modify the source file
