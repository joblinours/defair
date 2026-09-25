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

DEFAIR runs forensic tools in isolated Docker containers — one per investigation.
Containers are hardened by default: all capabilities dropped, `no-new-privileges`, no network,
read-only root filesystem, CPU/memory/PID limits, running as your host user. Evidence can only
be mounted from the directories listed in `container.evidence_roots` (`defair.yaml`).
Hardening applies to containers created from v0.3.6 on — recreate older ones.

```bash
# Create a forensic container linked to a case
defair container create --case CASE-2026-001 --evidence /evidence/host01.E01

# List containers
defair container list

# Interactive analyst shell (CLI only — never exposed through MCP)
defair container shell defair-case-2026-001

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
| `run_tool` | Run a registered tool with validated options (recorded as a ToolRun) |
| `exec_in_container` | Arbitrary command — **disabled** unless `mcp.allow_exec: true` |
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

The roadmap below also closes the coverage gap with all-in-one DFIR toolboxes such as [Hecatrace](https://github.com/syscall80h/hecatrace) — **without becoming one**. Each tool they ship is integrated the DEFAIR way:

- **Wrapped, not exposed** — a `BaseTool` manifest + normalizer, never a raw binary reachable through MCP
- **Structured, not dumped** — results land as artifacts, timeline events and findings in the case database, not as loose CSV/TXT files
- **Specialized images, not a monolith** — heavy engines live in dedicated worker images (`worker-plaso`, `worker-malware`, `worker-memory`, …) pulled from GHCR
- **Pinned, not `latest`** — every tool and rule set is version-pinned and hash-verified, and its version is recorded in each `ToolRun`
- **Verified rule provenance** — every YARA / Sigma source (SigmaHQ, YARA Forge and community sets) is pinned by tag or commit and hash-verified file by file; no rule is ever silently overwritten
- **Offline & isolated** — workers run without network, with dropped capabilities and resource limits

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

### ✅ v0.2 — Windows foundation + MCP analysis

- **Dissect** integration (host discovery, artifact identification)
- **13 EZ Tools** with BaseTool wrappers + normalizers: MFTECmd, EvtxECmd, RECmd, PECmd, AmcacheParser, AppCompatCacheParser, JLECmd, LECmd, RBCmd, SBECmd, SrumECmd, WxTCmd, SQLECmd
- Normalization layer (BaseNormalizer → unified artifact schema)
- Evidence discovery with automatic tool recommendations
- MCP tools: `discover_evidence`, `analyze_evtx`, `analyze_mft`, `analyze_registry`, `analyze_prefetch`, `analyze_amcache`, `analyze_shimcache`, `analyze_jumplist`, `analyze_lnk`, `analyze_recyclebin`, `analyze_shellbags`, `analyze_srum`, `analyze_wintimeline`, `analyze_sqlite`
- Tested on HackTheBox DFIR challenges (Jingle Bell, Recollection)

### ✅ v0.3 — Detection + Timeline + MCP hunting

- **Hayabusa v4.1** integration (4000+ Sigma rules, MITRE ATT&CK mapping)
- Timeline Engine — unified timeline over all artifacts (summary, search, export CSV/JSONL)
- Findings Engine — auto-created from Hayabusa high/critical detections (`FND-NNN`)
- IOC search across all artifacts (description, data, hostname, username)
- Hunting orchestration (`hunt_evtx` → detect → normalize → findings)
- CLI: `defair hunt`, `defair timeline`, `defair findings`, `defair search`
- MCP: `hunt_evtx`, `build_timeline`, `search_timeline`, `list_findings`, `search_ioc`

### ✅ v0.3.1 — Prefetch analysis fix

- Replaced **PECmd** (Windows-only) with a cross-platform Prefetch parser based on **libscca**
- `analyze_prefetch` MCP tool works end-to-end in Linux containers

### ✅ v0.3.5 — Mass YARA + Sigma scanning

- **YARA** mass scanner on mounted evidence (files, memory dumps, disk images)
- **Sigma** mass scanner via Hayabusa on all EVTX sources
- Default rule sets embedded in the container (YARA community rules + Hayabusa Sigma rules)
- Custom rules mounting: bind-mount `/rules/yara/` and `/rules/sigma/` for custom rules
- Scan results normalized as Findings with severity, confidence, and MITRE mapping
- MCP: `scan_yara`, `scan_sigma` — CLI: `defair scan yara`, `defair scan sigma`
- 212 tests, 16 tool wrappers

### ✅ v0.3.6 — Hardening + reproducible images (current)

*Prerequisite: before adding more engines, make the platform match its own principles.*

- **No shell via MCP, for real**: `exec_in_container` removed from MCP (or gated behind an explicit `mcp.allow_exec: false` config flag, off by default) — kept in the CLI for humans
- **`run_tool` (MCP + CLI)** — run a *registered* tool with validated arguments, recorded as a `ToolRun` (replaces arbitrary exec for agents)
- **Evidence allowlist** — `create_container` only mounts paths under configured evidence roots; image restricted to `ghcr.io/joblinours/defair*`
- **Container hardening** — `cap_drop: ALL`, `no-new-privileges`, `network_mode: none`, CPU / memory / PIDs limits, read-only rootfs + tmpfs
- **Dockerfile**: multi-stage build (downloads in a `builder` stage, no compilers in the runtime image)
- **Pinned supply chain**: EZ Tools and Hayabusa pinned by version + SHA-256; tool versions stored in every `ToolRun` *(rule sets: see v0.3.7)*
- **Analyst shell (CLI only)**: `defair container shell <case>` — interactive session in the case container, evidence `:ro`, never exposed via MCP *(≈ `hecatrace shell`)*

### 📋 v0.3.7 — Raijin scan engine (vendored) + verified rule sets

*[Raijin](external_tool/raijin-main/) (Rust, YARA-X + sigma-rust) is integrated **in-tree** and becomes the single engine behind `scan_yara` and `scan_sigma`.*

**Engine**

- Raijin source **vendored in the repository** (`engines/raijin/`) as a DEFAIR-maintained fork, built in a Rust `builder` stage (CI → GHCR) — licensing arrangement with the author recorded in `engines/raijin/LICENSING.md`
- Run as a cold scanner only: `--lab --no-procs --no-tui --no-html --signatures /opt/defair/rules --jsonl …` — never live processes
- Replaces **yara-python** + the **Yara-Rules/rules** bundle for YARA, and **Hayabusa** for mass Sigma scanning
- Native layout detection (KAPE, Velociraptor, plain mount), original Windows path reconstructed, findings per matched event, ZIP content scanning
- Raijin JSONL → normalizer → artifacts + findings (score → severity, MITRE tags from Sigma)

**Rule sources — broad coverage**

| Engine | Sources |
|--------|---------|
| YARA | YARA Forge (core / extended / full), Elastic protections-artifacts, ESET malware-ioc, ReversingLabs, Malpedia signator-rules, Neo23x0 signature-base, Trellix ATR |
| Sigma | SigmaHQ (core / core+ / core++ / all + emerging-threats add-on), mdecrevoisier SIGMA-detection-rules, LOLRMM |

- Selectable rule profiles per scan: `precise` (YARA Forge core + SigmaHQ core) or `broad` (every source)

**Integrity — every source pinned and verified**

- **`rules.lock`**, one entry per source: repo, release tag *or* **commit SHA** (never a branch), archive SHA-256, and a **per-file SHA-256 manifest** of the extracted rules (stable even if GitHub re-compresses the archive), plus the source license
- Release assets verified against the GitHub release digest; branch-only sources fetched by pinned commit
- Verified at build time **and** re-verified at scan time — missing, extra or modified rule file → scan refused
- `raijin-util update` patched to be **lock-driven** (no hardcoded `latest` URLs); bumping the lock is a reviewed commit, CI diffs rule counts per source
- Offline updates: `defair rules status` / `defair rules update --bundle <tar>` (bundle checked against the lock)

**Collision handling — no rule silently overwritten**

- **No basename flattening**: rules stored as `rules/<engine>/<source>/<original path>`, so two files with the same name in different folders or sources both survive
- **YARA**: one namespace per source (identical rule names across sources no longer break compilation); cross-source duplicates resolved first-source-wins in a fixed, documented source order, at rule granularity
- **Sigma**: deduplicated by rule `id` (UUID); same `id` with *different* content is reported as a conflict, not dropped silently
- **`rules/CONFLICTS.json`** generated at build: every dropped duplicate and every conflict, with source, path and SHA-256
- `raijin-util validate` in CI: unloadable rules listed per source; build fails if a source loses loadable rules versus the previous lock

**Provenance in results**

- Findings carry: source, release tag / commit, rule id / name, rule file path + SHA-256, rule license
- **Custom rules** (`/rules/yara/`, `/rules/sigma/`) hashed and tagged `provenance: custom`, in their own namespace
- `NOTICE` lists every embedded rule set with its license (DRL 1.1, Elastic License 2.0, MIT, BSD…)
- MCP: `scan_yara`, `scan_sigma` (same names, new engine), `scan_evidence` (YARA + Sigma in one pass), `get_ruleset_info`, `list_rule_conflicts`
- Hayabusa kept only for `hunt_evtx` timeline enrichment, its rule set (`Yamato-Security/hayabusa-rules`) recorded as its own pinned source

### 📋 v0.3.8 — Preprocessing & normalization pipeline

*Inspired by [ArtefactProcessor / PyTriage](external_tool/artefactprocessor-master/), adapted to DEFAIR's provenance model.*

- **Two-stage normalization**: tool output → **normalized JSONL** in the workspace (`normalized/<artifact_type>/<source>.jsonl`, hashed) → **batched bulk insert** into the case database
- **Replay without re-running tools**: `defair normalize replay --case CASE-xxx` rebuilds artifacts / timeline from the JSONL files (e.g. after a normalizer fix or DB loss)
- **Common envelope on every record**: case, evidence, hostname, source file + original host path, channel / application slug, tool + version, `run_id`, record ID / offset
- **Generic EVTX flattening**: `System` fields + `EventData` / `UserData` `Data@Name` → flat keys, raw record kept for traceability
- **EventID knowledge base** (`evtx_catalog.yaml`): channel → EventID → description, artifact category, MITRE technique — drives descriptions and typed views
- **Timeline-ready fields** on every event: `timestamp` (ISO 8601 UTC, full precision), `timestamp_desc` (Created / Modified / Executed / Logon…), `message` — Timesketch-compatible export
- **Pure-Python fallback parsers** (EVTX, Prefetch, LNK, JumpList…) when an external tool fails or is unavailable
- Per-run counters: records read / normalized / rejected, with rejection reasons
- **Not copied from ArtefactProcessor**: lossy `dd/mm/YYYY HH:MM:SS` timestamps, `datetime.now()` substituted for missing timestamps (fabricated evidence), silently swallowed exceptions — DEFAIR keeps `null` + an explicit parse error

### 📋 v0.4 — Evidence sources + Orchestration + MCP profiles

- **Source auto-detection** in `discover_evidence`: Velociraptor, KAPE (ZIP / VHDX), FastIR, DFIR-ORC (encrypted `.7z.p7b`), Generaptor (encrypted ZIP), UAC (tar) collections, mounted filesystem, disk images (E01/Ex01, raw/dd, VHD/VHDX, VMDK, AFF) with automatic NTFS partition offset
- **Image access through Dissect** (no FUSE mount, no `SYS_ADMIN`)
- **Archive evidence**: ZIP collections (with or without password) registered and hashed as-is, extracted into the workspace
- DAG-based analysis orchestration, bounded parallel workers, per-tool timeout and retry
- Declarative profiles (`windows-triage`, `windows-full`, `ransomware`, `persistence`, `registry-only`)
- **Run manifest** — every profile run writes a `run.json` (tools, versions, durations, errors), even on failure
- CLI: `defair run --case CASE-xxx --profile windows-triage` *(≈ `hecatrace run -v -e`)*
- MCP: `run_profile`, `analyze_evidence`, `get_run_status`
- **🎯 Milestone: MVP MCP — an AI agent can conduct a full Windows investigation via MCP**

### 📋 v0.4.5 — Windows coverage completion

- **Remaining EZ Tools**: RecentFileCacheParser, SumECmd (UAL — Windows Server), bstrings, rla (dirty hive replay before RECmd)
- **NTFS depth**: USN Journal (`$J`), `$I30` INDX slack (INDXRipper), `$LogFile`
- **Extra Windows artefacts** (from ArtefactProcessor's KAPE plugin): Defender MPLog, PowerShell `ConsoleHost_history`, Scheduled Tasks XML, WebCache, RDP bitmap cache, IIS logs
- **Typed EVTX views** — built on the v0.3.8 EventID catalog, YAML-driven routing (4624, 4625, 4688, 7045, 4698, …) exposed as filtered artifact views instead of CSV files
- **Host profile** — hostname, OS build, users, timezone, network config, installed software, assembled from registry + Dissect *(≈ Hecatrace `systeminfo.txt`)*
- **Keyword / IOC watchlists** — generic + per-case keyword lists, batch search over artifacts, timeline and raw strings (ripgrep-backed)
- **Strings extraction** — ASCII + UTF-16LE from pagefile.sys, hiberfil.sys and unallocated space, indexed for IOC search
- MCP: `analyze_usn`, `analyze_ual`, `hunt_chainsaw`, `get_host_profile`, `search_watchlist`

### 📋 v0.5 — Supertimeline

- **Plaso** (log2timeline + psort) in a dedicated `worker-plaso` image
- **Sleuth Kit** bodyfile (`fls` → mactime) for fast filesystem timelines
- Plaso events imported into the Timeline Engine (same schema as EZ Tools / Hayabusa events, with source provenance)
- Incremental runs: existing `.plaso` storage reused unless `--overwrite`
- MCP: `build_supertimeline`, `search_timeline` extended to Plaso sources

### 📋 v0.6 — Reporting + REST API

- Forensic reports (Markdown, HTML, JSON) — findings, host profile, timeline highlights, tool runs and versions
- **Case export** — per-category CSV/JSONL tree for human review (Timeline Explorer, spreadsheets)
- Optional export connectors: **Timesketch** (timeline) and **OpenSearch** (bulk JSONL) — the case database stays the source of truth
- REST API (FastAPI + OpenAPI)
- MCP: `generate_report`, `export_case`

### 📋 v0.7 — Malware & document triage

- Dedicated `worker-malware` image (offline, no network)
- **File extraction** from evidence into the workspace with hash + source provenance (`extract_file`)
- **capa** (capabilities), **FLOSS** (obfuscated strings), **pefile** (PE metadata), **ssdeep / TLSH** (fuzzy hashing)
- **Documents**: oletools, oledump, pdfid, pdf-parser, **ExifTool** metadata
- **ClamAV** with a pinned, offline signature database
- YARA triage of extracted files through **Raijin** (same pinned rule sets as v0.3.7)
- Results normalized as artifacts + findings (MITRE ATT&CK from capa)
- MCP: `extract_file`, `triage_file`, `scan_clamav`

### 📋 v0.8 — Memory forensics

- **Volatility 3** in a dedicated `worker-memory` image (pinned symbol tables for offline use)
- Profiles: `memory-triage` (pslist/pstree, cmdline, netscan, malfind, svcscan, dlllist)
- Memory artifacts correlated with disk artifacts in the timeline and findings
- YARA + strings on memory dumps
- MCP: `analyze_memory`, `run_profile memory-triage`

### 📋 v0.9 — Carving + deep disk

- Dedicated `worker-carving` image: **bulk_extractor** (emails, URLs, IPs, credit cards…), **PhotoRec / foremost / scalpel**, **binwalk**
- Carved items registered as derived evidence (parent evidence + offset + hash)
- Image verification: `ewfverify`, `hashdeep` integrated into `verify_evidence`
- MCP: `carve_evidence`, `run_bulk_extractor`
- **🎯 Milestone: coverage parity with all-in-one DFIR toolboxes — with structured results, provenance and MCP access**

### 📋 v0.10+ — Beyond parity

- **Email**: PST/OST/MBOX parsing, attachment extraction, OCR on attachments
- **Cloud & AD sources** (ArtefactProcessor plugins): DFIR-O365RC, Google Workspace, ADTimeline, ADAudit
- **Zeek / TShark / Suricata** — network DFIR
- **Linux DFIR** — journald, SSH, cron, systemd, Docker artifacts; configurable log globs (auth, audit, nginx, apache…); Sigma on Linux logs via Raijin
- Web UI
- RBAC, audit trail, SBOM + image signing

### 📋 v1.0 — DEFAIR

- Complete forensic workflow
- Windows + Linux + Memory + Network
- Stable MCP + API
- Reproducible reports
- Offline installation
- Production-ready security

> See [defair_Roadmap.md](defair_Roadmap.md) for the full detailed roadmap.

---

## Forensic engines

| Engine | Purpose | Worker image | Phase | Status |
|--------|---------|--------------|-------|--------|
| **Dissect** | Host discovery, artifact identification, image & filesystem access | `defair` | v0.2 | ✅ |
| **EZ Tools** (13) | Windows artifacts (MFT, EVTX, Registry, Amcache, LNK, SRUM, ...) | `defair` | v0.2 | ✅ |
| **Hayabusa** | EVTX hunting timeline (hayabusa-rules, distinct provenance) | `defair` | v0.3 | ✅ |
| **YARA** (yara-python) | File/memory pattern matching — replaced by Raijin | `defair` | v0.3.5 | ✅ |
| **Raijin** (vendored) | YARA-X + Sigma cold scanner, 10+ pinned rule sources | `defair` | v0.3.7 | 📋 |
| **EZ Tools** (remaining) | RecentFileCacheParser, SumECmd, bstrings, rla | `defair` | v0.4.5 | 📋 |
| **INDXRipper / USN parsing** | `$I30` slack, USN Journal | `defair` | v0.4.5 | 📋 |
| **Plaso** | Supertimeline, multi-source timestamp normalization | `worker-plaso` | v0.5 | 📋 |
| **Sleuth Kit** | Bodyfile / mactime filesystem timeline | `worker-plaso` | v0.5 | 📋 |
| **capa / FLOSS / pefile** | Malware capabilities, obfuscated strings, PE metadata | `worker-malware` | v0.7 | 📋 |
| **oletools / Didier Stevens suite / ExifTool** | Office, PDF and metadata triage | `worker-malware` | v0.7 | 📋 |
| **ClamAV** | AV scanning (pinned offline signatures) | `worker-malware` | v0.7 | 📋 |
| **Volatility 3** | Memory forensics (processes, network, DLLs, persistence) | `worker-memory` | v0.8 | 📋 |
| **bulk_extractor / PhotoRec / foremost / scalpel** | Feature extraction and file carving | `worker-carving` | v0.9 | 📋 |
| **Zeek / TShark / Suricata** | Network traffic analysis, IDS | `worker-network` | v0.10+ | 📋 |

> **Out of scope:** acquisition tools (dc3dd, imaging) — DEFAIR analyses evidence, it does not acquire it.

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
