# DEFAIR

**Digital Forensics & Incident Response platform — MCP-first, containerized, modular.**

[![CI](https://github.com/joblinours/defair/actions/workflows/ci.yml/badge.svg)](https://github.com/joblinours/defair/actions/workflows/ci.yml)
[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## What is DEFAIR?

DEFAIR is a **reproducible DFIR platform** that orchestrates multiple forensic engines, unifies their results, and exposes the investigation to a human or an AI agent via **CLI**, **API**, and **MCP** (Model Context Protocol).

It is **not** "a giant Docker container with 50 forensic binaries". It is a **forensic orchestration platform** where external tools are specialized engines managed through a common architecture.

```
                     Analyst / AI Agent
                            │
                ┌───────────┴───────────┐
                │                       │
               CLI                     MCP
                │                       │
                └───────────┬───────────┘
                            │
                     Service Layer
                            │
                    ┌───────┴────────┐
                    │  Orchestrator  │
                    └───────┬────────┘
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
    Evidence Manager   Tool Registry     Job Engine
          │                 │                 │
          └─────────────────┼─────────────────┘
                            │
                  Normalization Layer
                            │
             ┌──────────────┼───────────────┐
             │              │               │
          Timeline       Findings          IOC
             │              │               │
             └──────────────┼───────────────┘
                            │
                     Reports / Export
```

### Core principles

1. **MCP-first** — every capability is exposed via CLI *and* MCP simultaneously
2. **Read-only on evidence** — source files are never modified
3. **Hash & provenance** — every result is traceable back to its source
4. **Reproducible** — every execution is logged, versioned, and replayable
5. **No shell via MCP** — the MCP exposes forensic operations, not arbitrary commands
6. **Offline-first** — designed to work without internet access

---

## Quick start

### Installation

```bash
# Clone
git clone https://github.com/joblinours/defair.git
cd defair

# Create venv and install (dev includes pytest, ruff, etc.)
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Verify installation
defair --version
pytest tests/ -v
```

### CLI usage

```bash
# Create a forensic case
defair case create "Incident 2026-09 — Host compromise"

# List cases
defair cases list

# Register evidence (computes SHA-256 automatically)
defair evidence add CASE-2026-001 /evidence/host01.E01 --type disk_image

# List evidence (all or filtered by case)
defair evidence list
defair evidence list --case CASE-2026-001

# Get details
defair case get CASE-2026-001
defair evidence get EVD-001

# Verify evidence integrity (re-hash and compare)
defair evidence verify EVD-001
```

### Container orchestration

DEFAIR runs forensic tools in isolated Docker containers — one per investigation:

```bash
# Create a forensic container linked to a case
defair container create --case CASE-2026-001 --evidence /evidence/host01.E01

# List containers
defair container list

# Execute a command inside the container
defair container exec defair-case-2026-001 ls -la /evidence

# Get container details / logs
defair container get defair-case-2026-001
defair container logs defair-case-2026-001

# Stop / remove
defair container stop defair-case-2026-001
defair container remove defair-case-2026-001
```

### MCP usage

DEFAIR exposes a MCP server over **stdio** — compatible with Claude Desktop, Claude Code, and any MCP client:

```bash
# Run the MCP server
defair-mcp
```

Available MCP tools:

| Tool | Description |
|------|-------------|
| **Case & Evidence** | |
| `create_case` | Create a new investigation case |
| `list_cases` | List all forensic cases |
| `get_case` | Get case details by ID or case number |
| `register_evidence` | Register evidence with SHA-256 hash |
| `list_evidence` | List evidence (optionally filtered by case) |
| `get_evidence` | Get evidence details by ID or number |
| `verify_evidence` | Re-hash evidence and verify integrity |
| **Container** | |
| `create_container` | Create an isolated forensic container |
| `list_containers` | List DEFAIR containers |
| `get_container_info` | Get container details |
| `start_container` | Start a stopped container |
| `stop_container` | Stop a running container |
| `remove_container` | Remove a container |
| `exec_in_container` | Execute a command inside a container |
| `container_logs` | Get container logs |
| **Discovery & Analysis** | |
| `discover_evidence` | Discover forensic artifacts on mounted evidence |
| `list_tools` | List available forensic tools |
| `tools_health` | Check tool availability in a container |
| `list_tool_runs` | List past analysis runs |
| `list_artifacts` | List normalized artifacts from analysis |
| `analyze_evtx` | Parse Windows Event Logs (EvtxECmd) |
| `analyze_mft` | Parse NTFS Master File Table (MFTECmd) |
| `analyze_registry` | Parse Windows Registry hives (RECmd) |
| `analyze_prefetch` | Parse Prefetch files (PECmd) |
| `analyze_amcache` | Parse Amcache.hve (AmcacheParser) |
| `analyze_shimcache` | Parse Shimcache (AppCompatCacheParser) |
| `analyze_jumplist` | Parse Jump Lists (JLECmd) |
| `analyze_lnk` | Parse LNK shortcuts (LECmd) |
| `analyze_recyclebin` | Parse Recycle Bin (RBCmd) |
| `analyze_shellbags` | Parse ShellBags (SBECmd) |
| `analyze_srum` | Parse SRUM database (SrumECmd) |
| `analyze_wintimeline` | Parse Windows Timeline (WxTCmd) |
| `analyze_sqlite` | Parse SQLite databases (SQLECmd) |
| **Detection & Hunting** *(v0.3)* | |
| `hunt_evtx` | Run Hayabusa Sigma detection on EVTX |
| `build_timeline` | Build unified timeline summary |
| `search_timeline` | Search/filter timeline with multi-criteria |
| `list_findings` | List investigation findings |
| `search_ioc` | Search IOC across all artifacts |

### Docker

```bash
# Build
docker compose build

# Run CLI
docker compose run --rm defair defair case create "Docker test"

# Run MCP server
docker compose run --rm mcp
```

---

## Architecture

DEFAIR follows a **triple-interface** architecture: CLI, MCP, and API all call the same async Service Layer. No business logic lives in the interface layers.

```
CLI (click)          MCP (FastMCP)          API (FastAPI — planned)
     │                     │                      │
     │  run_sync()         │  async direct         │  async direct
     └─────────┬───────────┴──────────────────────┘
               │
        Service Layer (async)
               │
     ┌─────────┴──────────┐
     │                    │
  SQLite            Docker SDK
  (aiosqlite)       (container_service)
                          │
              ┌───────────┴───────────┐
              │  DEFAIR Container 1   │  evidence :ro
              │  DEFAIR Container 2   │  workspace :rw
              └───────────────────────┘
```

### Project structure

```
src/defair/
├── config.py              # YAML + Pydantic configuration
├── logging.py             # Structured logging (structlog)
├── database.py            # SQLite schema & connection management
├── models/                # Pydantic data models (Case, Evidence, ...)
├── services/              # Async service layer (shared by CLI & MCP)
├── cli/                   # Click CLI commands
└── mcp_server/            # FastMCP server & tool definitions
```

### Tech stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.13 |
| CLI | Click + Rich |
| MCP server | FastMCP 4.x (stdio) |
| Database | SQLite via aiosqlite |
| Models | Pydantic v2 |
| Logging | structlog (JSON / console) |
| Config | YAML + Pydantic |
| Tests | pytest + pytest-asyncio |
| Lint | Ruff |
| Container | Docker + Compose |
| CI/CD | GitHub Actions |

---

## Roadmap

DEFAIR is built **MCP-first**: every phase delivers the forensic capability *and* its MCP exposure simultaneously.

### ✅ v0.1 — Core + Evidence Manager

- Case & Evidence models
- CLI: `case create`, `cases list`, `case get`, `evidence add/list/get/verify`
- MCP: `create_case`, `list_cases`, `get_case`, `register_evidence`, `list_evidence`, `get_evidence`, `verify_evidence`
- SQLite database with provenance
- SHA-256 hashing + integrity verification on evidence
- Structured logging with correlation IDs
- Docker + CI/CD

### ✅ v0.1.5 — Host Wrapper + Container Orchestration

- Docker SDK integration — orchestrate forensic containers from the host
- One container per investigation, evidence mounted read-only
- CLI: `container create/list/get/start/stop/exec/logs/remove`
- MCP: `create_container`, `list_containers`, `get_container_info`, `start_container`, `stop_container`, `exec_in_container`, `container_logs`, `remove_container`
- Persistent workspaces at `~/.defair/workspaces/`
- AI agent can create, control, and run commands in forensic containers via MCP

### ✅ v0.2 — Windows foundation + MCP analysis

- **Dissect** integration (host discovery, artifact identification)
- **14 EZ Tools** with BaseTool wrappers + normalizers: MFTECmd, EvtxECmd, RECmd, PECmd, AmcacheParser, AppCompatCacheParser, JLECmd, LECmd, RBCmd, SBECmd, SrumECmd, WxTCmd, SQLECmd, bstrings
- Normalization layer (BaseNormalizer → unified artifact schema)
- Evidence discovery with automatic tool recommendations
- MCP tools: `discover_evidence`, `analyze_evtx`, `analyze_mft`, `analyze_registry`, `analyze_prefetch`, `analyze_amcache`, `analyze_shimcache`, `analyze_jumplist`, `analyze_lnk`, `analyze_recyclebin`, `analyze_shellbags`, `analyze_srum`, `analyze_wintimeline`, `analyze_sqlite`
- Tested on HackTheBox DFIR challenges (Jingle Bell, Recollection)

### ✅ v0.3 — Detection + Timeline + MCP hunting (current)

- **Hayabusa v4.1** integration (4000+ Sigma rules, MITRE ATT&CK mapping)
- Timeline Engine — unified timeline over all artifacts (summary, search, export CSV/JSONL)
- Findings Engine — auto-created from Hayabusa high/critical detections (`FND-NNN`)
- IOC search across all artifacts (description, data, hostname, username)
- Hunting orchestration (`hunt_evtx` → detect → normalize → findings)
- CLI: `defair hunt`, `defair timeline`, `defair findings`, `defair search`
- MCP: `hunt_evtx`, `build_timeline`, `search_timeline`, `list_findings`, `search_ioc`
- 179 tests, 15 tool wrappers

### 🔜 v0.3.1 — Prefetch analysis fix

- **PECmd** uses a Windows-only API to parse Prefetch files — broken in Linux containers
- Replace PECmd with a cross-platform alternative (Python-native Prefetch parser)
- Ensure `analyze_prefetch` MCP tool works end-to-end in the container

### 🔜 v0.3.5 — Mass YARA + Sigma scanning

- **YARA** mass scanner on mounted evidence (files, memory dumps, disk images)
- **Sigma** mass scanner via Hayabusa on all EVTX sources
- Default rule sets embedded in the container (YARA community rules + Hayabusa Sigma rules)
- Custom rules mounting: users can bind-mount their own `/rules/yara/` and `/rules/sigma/` directories
- Scan results normalized as Findings with severity, confidence, and MITRE mapping
- MCP tools: `scan_yara`, `scan_sigma`
- CLI: `defair scan yara`, `defair scan sigma`

### 📋 v0.4 — Orchestration + MCP profiles

- DAG-based analysis orchestration
- Declarative profiles (`windows-triage`, `windows-full`, `ransomware`, `persistence`)
- **Plaso** integration (supertimeline)
- Worker scheduling, parallel jobs, retry, timeout
- MCP tools: `run_profile`, `analyze_evidence`
- **🎯 Milestone: MVP MCP — an AI agent can conduct a full Windows investigation via MCP**

### 📋 v0.5 — Reporting + API REST

- Forensic reports (Markdown, HTML)
- REST API (FastAPI + OpenAPI)
- MCP tools: `generate_report`, `export_case`

### 📋 v0.6+ — Extended forensics

- **Volatility 3** — memory forensics
- **Zeek / TShark / Suricata** — network DFIR
- **Linux DFIR** — journald, SSH, cron, systemd, Docker artifacts
- Web UI
- RBAC, audit trail, supply chain security

### 📋 v1.0 — DEFAIR

- Complete forensic workflow
- Windows + Linux + Memory + Network
- Stable MCP + API
- Reproducible reports
- Offline installation
- Production-ready security

> See [defair_Roadmap.md](defair_Roadmap.md) for the full detailed roadmap.

---

## Forensic engines (planned)

| Engine | Purpose | Phase | Status |
|--------|---------|-------|--------|
| **Dissect** | Host discovery, artifact identification, filesystem access | v0.2 | ✅ |
| **EZ Tools** (14 tools) | Windows artifacts (MFT, EVTX, Registry, Prefetch, Amcache, ...) | v0.2 | ✅ |
| **Hayabusa** | EVTX detection with 4000+ Sigma rules, MITRE ATT&CK | v0.3 | ✅ |
| **YARA** | File/memory pattern matching, malware detection | v0.3.5 | 🔜 |
| **Plaso** | Supertimeline, multi-source timestamp normalization | v0.4 | 📋 |
| **Volatility 3** | Memory forensics (processes, network, DLLs, persistence) | v0.6 | 📋 |
| **Chainsaw** | Fast EVTX search, Sigma detection | v0.6 | 📋 |
| **Zeek** | Network traffic analysis, protocol logs | v0.6 | 📋 |
| **TShark** | Packet capture analysis | v0.6 | 📋 |
| **Suricata** | Network IDS, alert generation | v0.6 | 📋 |

---

## Development

```bash
# Run tests
pytest tests/ -v

# Lint
ruff check src/ tests/

# Run CLI
defair --help

# Run MCP server
defair-mcp
```

### Adding a new MCP tool

1. Add the service function in `src/defair/services/`
2. Add the CLI command in `src/defair/cli/`
3. Add the MCP tool in `src/defair/mcp_server/server.py` with `@mcp.tool()`
4. Add tests (unit + CLI + MCP integration)
5. Both CLI and MCP **must** call the same service function

---

## License

MIT

---

> *DEFAIR: a reproducible DFIR platform capable of orchestrating forensic engines, unifying their results, and exposing the investigation to a human or an agent via CLI, API, and MCP.*
