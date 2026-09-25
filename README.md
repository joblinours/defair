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

# Whole investigation in one command (v0.4): collection folders, archives,
# Generaptor / DFIR-ORC, disk images — prepared, then a profile runs in the background
defair run start --case CASE-2026-001 --evidence /evidence/host01.E01 --profile auto
defair run status PRUN-001
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
| `list_artifacts` | Search artifacts (text, tool, host, user, time range, run) with paging |
| `get_artifact` | Deep-inspect one artifact: data, provenance, raw EVTX event / YARA hex, timeline context |
| `get_finding` | A finding with every match explained (file, event / offset, matched values, rule file) |
| `show_rule` | Content of a YARA / Sigma rule from the verified store |
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
| **Scanning & rules** *(v0.3.7)* | |
| `scan_yara` | YARA scan of every file (Raijin, pinned rule sets) |
| `scan_sigma` | Sigma scan of EVTX / Linux logs (KAPE, Velociraptor, mount) |
| `scan_evidence` | YARA + Sigma in a single pass |
| `get_ruleset_info` | Pinned rule sources, installation and integrity status |
| `list_rule_conflicts` | Duplicate / conflicting rules across sources |
| **Investigations** *(v0.4)* | |
| `analyze_evidence` | Path → registered, prepared, profile chosen and run (background) |
| `prepare_evidence` | Extract / decrypt / carve an evidence (ZIP, Generaptor, DFIR-ORC, disk images) |
| `list_profiles` / `get_profile` | Analysis profiles and their steps |
| `run_profile` | Run a profile on an evidence in the background (`PRUN-NNN`) |
| `get_run_status` / `list_runs` | Follow profile runs (steps, tools, fallbacks, errors) |
| `cancel_run` / `resume_run` | Stop a run / resume it without re-running completed steps |
| **Windows coverage** *(v0.4.5)* | |
| `analyze_usn` | USN journal ($J) with MFTECmd, parent paths from the $MFT |
| `analyze_ual` | User Access Logging (Windows Server) with SumECmd |
| `hunt_chainsaw` | Sigma hunt with Chainsaw on the pinned rule store |
| `list_evtx_views` / `get_evtx_view` | Typed EVTX views (logons, services, RDP, PowerShell…) |
| `get_host_profile` | Host profile with a source per fact |
| `list_watchlists` / `search_watchlist` | Keyword / IOC watchlists over artifacts, strings, raw files |
| **Normalization & export** *(v0.3.8)* | |
| `export_timeline` | Export the timeline (Timesketch JSONL, JSONL, CSV) |
| `normalize_replay` | Rebuild a case's artifacts from its normalized JSONL |
| `normalize_rerun` | Re-normalize a tool run from its raw output |
| `get_normalization_stats` | Normalization counters of a run |

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

### ✅ v0.3.6 — Hardening + reproducible images

*Prerequisite: before adding more engines, make the platform match its own principles.*

- **No shell via MCP, for real**: `exec_in_container` removed from MCP (or gated behind an explicit `mcp.allow_exec: false` config flag, off by default) — kept in the CLI for humans
- **`run_tool` (MCP + CLI)** — run a *registered* tool with validated arguments, recorded as a `ToolRun` (replaces arbitrary exec for agents)
- **Evidence allowlist** — `create_container` only mounts paths under configured evidence roots; image restricted to `ghcr.io/joblinours/defair*`
- **Container hardening** — `cap_drop: ALL`, `no-new-privileges`, `network_mode: none`, CPU / memory / PIDs limits, read-only rootfs + tmpfs
- **Dockerfile**: multi-stage build (downloads in a `builder` stage, no compilers in the runtime image)
- **Pinned supply chain**: EZ Tools and Hayabusa pinned by version + SHA-256; tool versions stored in every `ToolRun` *(rule sets: see v0.3.7)*
- **Analyst shell (CLI only)**: `defair container shell <case>` — interactive session in the case container, evidence `:ro`, never exposed via MCP *(≈ `hecatrace shell`)*

### ✅ v0.3.7 — Raijin scan engine (vendored) + verified rule sets

*Raijin (Rust, YARA-X + sigma-rust) is integrated **in-tree** (`engines/raijin/`) and is the single engine behind `scan_yara`, `scan_sigma` and `scan_evidence`.*

**Engine**

- Raijin source **vendored** in `engines/raijin/` as a DEFAIR-maintained fork (changes listed in `engines/raijin/LICENSING.md`), built from source with a pinned Rust toolchain in the image's `raijin-build` stage
- Cold scan of the target folder only: `--lab --no-procs --scan-all-files` — never live processes, never other host drives
- Replaces **yara-python** + the unpinned **Yara-Rules/rules** bundle for YARA, and **Hayabusa** for mass Sigma scanning
- Native layout detection (KAPE, Velociraptor, plain mount), original Windows path and event time kept, one detection per matched event
- Raijin JSONL now carries a structured rule reference (`engine`, `name`, `id`, `namespace`, `file`, `tags`, `level`) → normalizer → artifacts + findings (Sigma level / YARA score → severity, MITRE techniques from Sigma tags)

**Rule sources — 13 pinned sources, ~35,000 loadable rules**

| Engine | Sources | Profile |
|--------|---------|---------|
| YARA | YARA Forge core | `precise` |
| YARA | YARA Forge full, Elastic protections-artifacts, ESET malware-ioc, ReversingLabs, Malpedia signator-rules, Neo23x0 signature-base, Trellix ATR | `broad` |
| Sigma | SigmaHQ core + emerging-threats add-on | `precise` |
| Sigma | SigmaHQ all rules, mdecrevoisier SIGMA-detection-rules, LOLRMM | `broad` |

**Integrity — every source pinned and verified**

- Sources declared in `src/defair/rules/sources.yaml`, pinned in **`src/defair/rules/lock/rules.lock`**: release tag *or* **commit SHA** (never a branch), archive SHA-256, license, and a **per-file SHA-256 manifest** (`lock/manifests/<source>.json`) — shipped inside the Python package
- `defair rules lock --refresh` re-pins (release archives checked against GitHub's published digest); bumping the lock is a reviewed commit
- `defair rules sync` (image build) installs each source into `/opt/defair/rules/<engine>/<source>/` and verifies every file — any missing, extra or modified file aborts the build
- **Re-verified before every scan**: a store that differs from the lock → scan refused
- `raijin-util validate` runs per source at build (`VALIDATION.txt`); the build fails if a source has no loadable rule
- `raijin-util update` / `upgrade` disabled — no unpinned `latest` downloads

**Collision handling — no rule silently overwritten**

- **No basename flattening**: each source keeps its upstream tree, so same-named files in different folders or sources all survive
- Per-run signature tree assembled as `NN_<source>` symlinks in lock order: first source wins on a duplicate Sigma `id`, each YARA source loads in its own namespace
- **`CONFLICTS.json`** per profile: identical Sigma duplicates, conflicting Sigma rules (same `id`, different content — first source wins) and YARA rule names shipped by several sources (`defair rules conflicts`, MCP `list_rule_conflicts`)
- YARA hits of the same rule from several sources are merged into one artifact listing every source

**Provenance in results**

- Every finding's `detection_refs`: engine, source, repo, pinned ref, rule id / name, rule file path + SHA-256, license
- **Custom rules** (`/rules/yara/`, `/rules/sigma/` or `--yara-rules-dir` / `--sigma-rules-dir`) linked as `99_custom`, hashed into the ToolRun, tagged `provenance: custom`
- `/opt/defair/rules/NOTICE` lists every embedded rule set with its license (DRL 1.1, Elastic License 2.0, CC BY-SA 4.0, MIT, BSD…)
- CLI: `defair scan yara|sigma|evidence --profile precise|broad`, `defair rules status|verify|conflicts|lock|sync`
- MCP: `scan_yara`, `scan_sigma`, `scan_evidence`, `get_ruleset_info`, `list_rule_conflicts`
- Fixed: scan findings were never created (the service read `artifact_count` instead of `artifacts_produced`)
- Hayabusa kept for `hunt_evtx` timeline enrichment, pinned by version + SHA-256
- *Deferred:* offline rule updates from a verified bundle (`defair rules update --bundle`) — rules are updated by re-pinning the lock and rebuilding the image

### ✅ v0.3.8 — Preprocessing & normalization pipeline

*Inspired by ArtefactProcessor / PyTriage, adapted to DEFAIR's provenance model.*

- **Two-stage normalization**: tool output → **normalized JSONL** (`/workspace/normalized/<artifact_type>/<RUN>.jsonl`, SHA-256 recorded in `normalized_files`) → **batched bulk insert** (2,000 rows per batch, numbering computed once per run instead of a `COUNT` + commit per row)
- **Deterministic artifact ids** (`uuid5(run_id, record_key)`) — re-normalizing the same output yields the same ids and `ART-NNN` numbers, so findings stay linked
- `defair normalize replay --case` rebuilds a case from its JSONL (files whose hash changed are refused); `defair normalize rerun RUN-xxx` re-normalizes from the raw tool output after a normalizer fix; `defair normalize stats RUN-xxx`
- **Common envelope** on every artifact (`provenance`): tool + pinned version, run, evidence, source file, host path, channel, record id, raw value of any unparseable timestamp
- **Timestamps**: ISO 8601 UTC with full source precision (EZ Tools' 7 fractional digits kept); an unparseable time stays `null` with a reason — never replaced by "now"; ambiguous `dd/mm` vs `mm/dd` formats are refused
- **Timeline fields** on every event: `timestamp_desc` (Created ($SI), Last Executed, Event Logged…) and `message`; `defair timeline export --format timesketch` (MCP `export_timeline`)
- **Generic EVTX flattening**: `System` + `EventData` / `UserData` → flat keys, for EvtxECmd's `Payload` and native records
- **EventID knowledge base** (`src/defair/data/evtx_catalog.yaml`, 89 events: Security, System, Sysmon, PowerShell, RDP, Task Scheduler, Defender, WMI, BITS, USB): channel-aware type, category, description and MITRE techniques — add an event without code
- **Pure-Python fallbacks**: `evtx_native` (pyevtx-rs) for EvtxECmd, `lnk_native` (LnkParse3) for LECmd — run automatically when the tool fails, as their own ToolRun linked by `fallback_of`
- **Per-run counters** in `tool_runs.normalization_stats`: rows read, normalized, skipped, errors, unparseable timestamps, reasons
- Schema migrations (`PRAGMA user_version`): databases from earlier versions upgrade in place
- MCP: `normalize_replay`, `normalize_rerun`, `get_normalization_stats`, `export_timeline`
- **Not copied from ArtefactProcessor**: lossy `dd/mm/YYYY HH:MM:SS` timestamps, `datetime.now()` substituted for missing times, silently swallowed exceptions
- *Deferred:* JumpList pure-Python fallback

### ✅ v0.4 — Evidence sources + Orchestration + MCP profiles

**🎯 Milestone: MVP MCP — one call runs a full Windows investigation, whatever the evidence format.**

**Evidence sources** (`src/defair/sources/`)

- **Detection**: KAPE (folder / VHDX), Velociraptor, FastIR, UAC, mounted filesystems, log folders, disk images (E01 / Ex01 / VMDK / VHD / VHDX / QCOW2 / raw), ZIP (plain, ZipCrypto, AES), Generaptor, DFIR-ORC — plus artifacts identified by content (magic bytes) when a collector renamed them
- **Collection folders** registered as evidence with a tree hash (`verify` detects any added / removed / modified file)
- **Preparation** (`defair evidence prepare`, MCP `prepare_evidence`): collections used in place, read-only; ZIP extracted (zip-slip and archive-bomb guards, ZIP-in-ZIP); **Generaptor** decrypted (RSA-OAEP + AES); **DFIR-ORC** decrypted with ANSSI's orc-decrypt (vendored in `engines/orc-decrypt/`, LGPL-2.1) + nested 7z; **disk images carved with Dissect** — no mount, no privilege, no partition offset to compute — plus a host profile artifact
- `manifest.json` records every derived file (origin, size, SHA-256); secrets (archive password, key passphrase) travel through the exec environment, never on a command line, never stored; private keys mounted read-only at `/keys` (`container create --keys`, validated against `container.key_roots`)

**Orchestration** (`src/defair/orchestrator/`, `src/defair/profiles/`)

- Declarative profiles: `windows-triage`, `windows-full`, `ransomware`, `persistence`, `registry-only`, `scan-only`
- DAG executor: dependencies, bounded parallelism (`orchestrator.max_parallel`), per-step timeout, retry with backoff, optional steps, cancellation (running tools are killed), resume (completed steps kept)
- **Engines**: `auto` = EZ Tools → pure-Python fallbacks → **Dissect plugins** on the original image / collection; `ez` = no Dissect; `dissect` = Dissect plugins only (`dissect_plugin` tool + generic normalizer, same artifact types as EZ Tools)
- **Background profile runs** `PRUN-NNN`: detached worker, status / list / cancel / resume, dead-worker detection
- **`run.json`** written after every step and always at the end — even on failure: DEFAIR version, profile, engine, evidence preparation, each step's tools, pinned versions, fallbacks used, durations, errors, rule lock
- Concurrency fixes: RUN / ART / FND numbers reserved under a lock (parallel steps collided on `RUN-NNN`)
- CLI: `defair profile list|show`, `defair run start --case CASE-xxx --evidence EVD-001 --profile windows-triage` *(≈ `hecatrace run -v -e`)*, `defair run status|list|cancel|resume`
- MCP: `prepare_evidence`, `list_profiles`, `get_profile`, `run_profile`, `analyze_evidence`, `get_run_status`, `list_runs`, `cancel_run`, `resume_run`
- *Not yet:* Linux disk images (UAC collections are scanned with Raijin only), BitLocker-encrypted volumes

### ✅ v0.4.1 — Investigation ergonomics (from the first real E01 run)

- `--case` accepts the case **name** everywhere (case-insensitive; ambiguous names refused), as well as `CASE-YYYY-NNN` or the id
- **`findings get`** explains every match: evidence file (real path in the container), event (EventID / RecordID / Computer) or YARA offset, and the **exact field values / pattern that hit the rule**; rule id, rule file and `defair rules show <source> <path>`; `--all`, `--json` (with the raw EVTX event / hex context)
- **`artifacts get ART-NNN`**: every field and the full data, provenance (tool, pinned version, RUN-NNN, input), linked findings, normalized JSONL, the **complete EVTX event** read back from the log by record id, a **hex dump** around each YARA match, `--context MIN` for the surrounding timeline
- **`artifacts list`**: `--contains` (any field), `--tool`, `--host`, `--user`, `--severity`, `--since/--until`, `--run`, `--asc`, paging (`--offset`), `--json`
- **Container logs**: every command (arguments with secrets redacted, output, exit code, duration), tool run (command, exit code, stderr), profile step and finding is logged as JSON to `/workspace/logs/defair.log`; the container's PID 1 follows it, so `docker logs <container>` shows everything. Console logs moved to stderr (stdout carries results only)
- `container create` refuses a workspace the host user cannot write (created by DEFAIR < 0.3.6 running as root) with the `chown` fix
- Hayabusa 4.x: `dfir-timeline` syntax, run from `/opt/hayabusa`, abbreviated levels (`crit`, `med`) mapped — critical detections now become findings
- MCP: `get_artifact`, `get_finding`, `show_rule`; `list_artifacts` gains every filter + paging

### ✅ v0.4.5 — Windows coverage completion

**Fixes first**

- MFTECmd `$J` output is normalized as `windows.usn.journal_entry` (it was a file entry without timestamp); `-m $MFT` resolves parent paths; Dissect `usnjrnl` records use the same type
- SrumECmd: one artifact type per SRUM table (app resource usage, network usage / connectivity, energy, push notifications) instead of `network_usage` for everything
- MCP `analyze_srum` forwards `registry_hive`; MFTECmd `--bdl` takes the drive letter only

**Remaining EZ Tools** (pinned by SHA-256 like the others)

- **RecentFileCacheParser** (Windows 7 program execution), **SumECmd** (User Access Logging — who reached which Windows Server role, from where), **bstrings** (pattern search in any binary; runs with a pseudo-terminal on stdin), **rla** (dirty hive replay)
- Profile steps can read another step's output: `input: step:hives_replay` (+ `input_fallback`) — rla replays the `.LOG1/.LOG2` of dirty hives into the workspace, RECmd parses the clean copies

**NTFS depth** — native parsers on `dissect.ntfs`, no mount, E01 / VMDK / VHDX / raw

- **`$I30` INDX slack** (`indx_native`, INDXRipper approach): every directory of every NTFS volume; `$FILE_NAME` remnants of deleted / renamed files with their four `$FN` times; entries still live (allocation or `$INDEX_ROOT`) are dropped
- **`$LogFile`** (`logfile_native`): file names linked / unlinked, FILE records created / freed, `$FILE_NAME` created / removed; every other operation is counted as *not decoded* in the run statistics, never guessed
- USN journal in `windows-triage`

**Extra Windows artefacts** (pure-Python parsers, Dissect plugins as fallbacks)

- **Defender MPLog** (detections, processes Defender measured, SDN file hashes, exclusions), **PowerShell `ConsoleHost_history`**, **Scheduled Task XML** (actions, triggers, principal — `defusedxml`), **WebCache** (IE / legacy Edge history incl. Explorer `file://` accesses, downloads, cookies), **RDP bitmap cache** (tiles rebuilt as PNG + a collage), **IIS W3C logs**
- Local times without a zone (task registration, some MPLog lines) are kept as text, never assumed UTC

**Typed EVTX views** — `src/defair/data/evtx_views.yaml`, on top of the EventID catalog

- `logons`, `process_creation`, `services`, `scheduled_tasks`, `rdp`, `powershell`, `account_changes`, `log_cleared`, `defender`, `network_shares`, `kerberos_ntlm` — filtered, column-projected views over the EVTX artifacts of any parser (EvtxECmd, native, Dissect); schema v4 indexes the EventID
- CLI `defair evtx views` / `defair evtx view logons --case X [--since/--until/--host/--user/--event-id]`

**Chainsaw** — second Sigma engine, pinned (2.16.5, SHA-256 = GitHub digest), on the **verified DEFAIR rule store** (never its own bundle): rule file, SHA-256, source, pinned ref resolved by Sigma id; findings like Raijin's — `defair hunt --engine chainsaw --rule-profile precise|broad`

**Host profile** — hostname, domain, OS build, architecture, timezone, install date, users, IPs, installed applications (Dissect, also on collections), registry time zone / network profiles / USB devices / services, computer names in the logs — every fact with its source, disagreements listed as conflicts, stored as one `windows.system.host_profile` artifact per evidence *(≈ Hecatrace `systeminfo.txt`)* — `defair host profile`, profile action `host_profile`

**Strings + watchlists**

- **Strings extraction** (`strings_native`): ASCII + UTF-16LE of `pagefile.sys` / `swapfile.sys`, streamed through Dissect (never copied), written as a TSV index; `hiberfil.sys` reported as skipped (compressed — v0.8), unallocated space in v0.5
- **Watchlists**: built-in (`offensive_tools`, `lolbins`, `rmm`, `exfiltration`) + per case (`/workspace/watchlists/*.yaml`), literal or regex terms; one batch search over the normalized artifacts (hits → `ART-NNN`), the strings index and the raw collection files (ASCII + UTF-16), **ripgrep**-backed (pinned) with a pure-Python fallback; JSON report + optional findings — `defair watchlist list|show|search`
- MCP: `analyze_usn`, `analyze_ual`, `hunt_chainsaw`, `list_evtx_views`, `get_evtx_view`, `get_host_profile`, `list_watchlists`, `search_watchlist`
- *Not yet:* hiberfil decompression (v0.8), JumpList pure-Python fallback

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
| **Dissect** | Image carving without mount (v0.4), plugins as parsing fallback / `engine=dissect` | `defair` | v0.2 / v0.4 | ✅ |
| **orc-decrypt** (ANSSI) | DFIR-ORC archive decryption | `defair` | v0.4 | ✅ |
| **EZ Tools** (13) | Windows artifacts (MFT, EVTX, Registry, Amcache, LNK, SRUM, ...) | `defair` | v0.2 | ✅ |
| **Hayabusa** | EVTX hunting timeline (hayabusa-rules, distinct provenance) | `defair` | v0.3 | ✅ |
| **YARA** (yara-python) | File pattern matching — replaced by Raijin in v0.3.7 | — | v0.3.5 | ⛔ |
| **Raijin** (vendored) | YARA-X + Sigma cold scanner, 13 pinned rule sources | `defair` | v0.3.7 | ✅ |
| **EZ Tools** (remaining) | RecentFileCacheParser, SumECmd, bstrings, rla | `defair` | v0.4.5 | ✅ |
| **NTFS native** (dissect.ntfs) | `$I30` slack, `$LogFile`, USN Journal | `defair` | v0.4.5 | ✅ |
| **Chainsaw** | Second Sigma engine on the pinned rule store | `defair` | v0.4.5 | ✅ |
| **ripgrep** | Watchlist / IOC batch search | `defair` | v0.4.5 | ✅ |
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
