# DEFAIR

**Digital Forensics & Incident Response platform** — MCP-first, containerized, modular.

> Une plateforme DFIR reproductible capable d'orchestrer de nombreux moteurs forensic, d'unifier leurs résultats et d'exposer l'investigation à un humain ou à un agent via CLI, API et MCP.

## Installation

```bash
pip install -e ".[dev]"
```

## Quickstart — CLI

```bash
defair --help
defair case create "Mon incident"
defair cases list
defair evidence add CASE-2026-001 /evidence/host01.E01
```

## Quickstart — MCP

Le serveur MCP s'utilise via stdio (Claude Desktop, Claude Code, etc.) :

```bash
defair-mcp
```

## Tests

```bash
pytest tests/ -v
```

## Architecture

```
CLI (click)          MCP (FastMCP)
     │                     │
     └─────────┬───────────┘
               │
        Service Layer (async)
               │
          SQLite (aiosqlite)
```

CLI et MCP appellent le même Service Layer — aucune logique métier dans les couches d'interface.

## Licence

MIT
