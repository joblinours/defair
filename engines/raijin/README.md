![Raijin Logo](./images/raijin-logo.png)

# Raijin

High-performance, multi-threaded YARA, Sigma & IOC scanner in a single binary.

**Status**: Beta. Works, but still under active development.

## Features

- YARA scanning of files and process memory (yara-x)
- Sigma rule scanning of Windows EVTX / Linux log artifacts (cold/offline scan), with automatic detection of KAPE, Velociraptor, or plain-mount collection layouts
- IOC matching (MD5/SHA1/SHA256 hashes, filename patterns, C2 indicators)
- Multi-threaded scanning with configurable thread count
- Archive scanning (ZIP files)
- Interactive TUI with real-time stats and controls
- Remote logging via syslog (UDP/TCP) (SYSLOG/JSON)
- HTML report generation with detailed findings
- Configurable scoring thresholds
- Smart filtering (skips /proc, /sys, mounted drives by default)
- Magic header detection
- JSONL output for log ingestion

## macOS process scanning

Process memory scanning on macOS is best-effort and typically requires debugging entitlements or elevated privileges. Without those, Raijin will still scan files but will not be able to read most process memory. Use `--no-procs` to skip process scanning if needed.

## Linux process scanning

On Linux, Raijin skips device-backed and kernel-special process mappings before reading `/proc/<pid>/mem`. This avoids known instability with some driver-managed VMAs while preserving normal anonymous, heap/stack, and regular file-backed memory scanning. If you still hit environment-specific issues, use `--no-procs` to disable process scanning.

## Installation

Download the pre-compiled binary for your platform from the [Releases Page](https://github.com/YOUR_GITHUB_USER/Raijin/releases).

```bash
# Extract
tar -xzvf raijin-linux-*.tar.gz
cd raijin-linux-*

# Update signatures (recommended)
./raijin-util update

# Run
sudo ./raijin --help
```

Signatures ship with the release but get stale quickly. Run `raijin-util update` to fetch the latest YARA-Forge and SigmaHQ Core rules.

Raijin looks for its rules next to its own binary first (`<dir of raijin>/signatures/`), then in the directories above it (so a `cargo build` binary under `target/` finds the checkout's `signatures/` from wherever it is run), then in the working directory (`./signatures/`), and logs the absolute path it settled on and why. A deployed install and a source checkout therefore both work from any directory. To point a scan somewhere else, pass `--signatures <DIR>` or set `RAIJIN_SIGNATURES`; `raijin-util update` and `raijin-util validate` take the same flag, so the rules they install are the rules the scan loads. The optional `config/excludes.cfg` is resolved the same way.

## Signatures

`raijin-util update` (no flags) fetches rules from multiple sources unconditionally:

- **YARA**: [YARA Forge](https://yarahq.github.io/) Core, [Elastic protections-artifacts](https://github.com/elastic/protections-artifacts), [ESET malware-ioc](https://github.com/eset/malware-ioc), [ReversingLabs yara-rules](https://github.com/reversinglabs/reversinglabs-yara-rules), [Malpedia signator-rules](https://github.com/malpedia/signator-rules), [Neo23x0 signature-base](https://github.com/Neo23x0/signature-base) (the original Loki/THOR-lite ruleset), [Trellix ATR Yara-Rules](https://github.com/advanced-threat-research/Yara-Rules)
- **Sigma**: [SigmaHQ](https://github.com/SigmaHQ/sigma) Core, [mdecrevoisier SIGMA-detection-rules](https://github.com/mdecrevoisier/SIGMA-detection-rules)

None of the 7 extra sources ship a GitHub release, so each is fetched by pulling its repo archive and keeping only its rule files. Each is independently best-effort: one source being unreachable or renamed logs an error and is skipped rather than failing the whole update.

Every YARA source lands in its own subdirectory under `signatures/yara/` (`elastic/`, `eset/`, `reversinglabs/`, `malpedia/`, `neo23x0/`, `atr/`) and is compiled into its own YARA namespace, cleared and re-extracted on every update. This matters: YARA rule identifiers must be unique within a namespace, and two independently-authored sources can genuinely define a rule with the same name (real example: ESET's and Neo23x0's signature-base both ship a rule literally named `PrikormkaDropper`, copied verbatim between the two projects). Flattening every source into one shared namespace turns that single collision into a hard compile error for the *entire* YARA engine - namespacing by source avoids it, while rules within one source that reference each other by name still resolve correctly. YARA-Forge Core and any custom rules dropped directly into `signatures/yara/` keep the default namespace, unaffected.

On top of namespacing, Raijin deduplicates rules across sources so the same detection doesn't fire (and get counted) twice:

- **YARA**: first-source-wins by rule name, at individual rule granularity (not whole file - about 23% of the fetched rule files contain more than one rule). Root-level files (YARA-Forge Core, custom rules) are processed first and always win a collision; subdirectories are then processed in alphabetical order for reproducible results. A duplicate rule is logged (`Dropped N duplicate YARA rule(s)...`) rather than silently vanishing.
- **Sigma**: by `id` - the Sigma spec requires this to be a globally unique v4 UUID per rule, so two rules sharing one is treated as genuinely the same rule (e.g. mirrored verbatim between sources) and only the first-loaded copy is kept.

mdecrevoisier's Sigma rules use some syntax (multi-document YAML files, list-valued `logsource.category`, `timeframe`-based aggregation) that `sigma-rust` 0.7 (Raijin's Sigma engine) doesn't support yet - those individual files are logged and skipped rather than failing the whole load, same graceful-degradation behavior as any other unparseable Sigma file.

Raijin uses YARA Forge Core and SigmaHQ Core as its **default, always-on baseline** (high accuracy, low false positives, optimized for performance) alongside the extra sources above. If you need broader coverage still, you can swap in the Extended/Full YARA-Forge sets manually, or fetch SigmaHQ's full rule set (every status: `stable`, `test`, `experimental`, `unsupported`) with:

```bash
./raijin-util update --sigma-all
```

This trades precision for recall: SigmaHQ Core ships ~1,400 stable rules, while the full set is ~3,300 rules, most of them `test`/`experimental` status and expected to need tuning or produce more noise. Tools that bundle the entire Sigma corpus by default (e.g. Hayabusa) will surface far more hits than Raijin's Core default for this reason alone - it isn't a detection engine gap, it's a rule-set coverage choice. `--sigma-all` closes most of that gap; Hayabusa also ships its own proprietary, non-Sigma detection rules on top, which `--sigma-all` cannot replicate.

A third, additive source is [LOLRMM](https://github.com/magicsword-io/LOLRMM) - a catalogue of legitimate RMM (Remote Monitoring & Management) tools abused for initial access/C2, with a Sigma rule per tool (network/process/registry/file indicators, plus a DNS-domain rule covering the whole catalogue at once). It has no GitHub release, so it's fetched by pulling its repo archive and keeping only `detections/sigma/*.yml`:

```bash
./raijin-util update --sigma-lolrmm       # combine with SigmaHQ Core
./raijin-util update --sigma-all --sigma-lolrmm   # combine with the full SigmaHQ set
```

IOC files in `signatures/iocs/` remain supported as optional local/custom content.

## Sigma Scanning

In addition to YARA/IOC scanning of live files, Raijin can cold-scan a forensic artifact collection (Windows EVTX event logs, Linux text logs) against Sigma detection rules. This is a separate pass from the file/process scan and only looks at `.evtx` files and known Linux log names (`auth.log`, `syslog`, `audit.log`, `secure`, `messages`, `kern.log`, `daemon.log`, `user.log`).

For offline analysis of a collected artifact dump, combine this with `--lab` so live process scanning of the analysis machine itself doesn't run - see [Common Scenarios](#common-scenarios).

Point `-f`/`--folder` at the root of the collection and Raijin auto-detects the layout:

- **KAPE output** - a source drive mirrored under a single-letter directory (e.g. `<root>/C/Windows/System32/winevt/Logs/...`)
- **Velociraptor offline collection** - an extracted collection with `uploads/<accessor>/...` and a sibling `results/` folder
- **Plain mount** - any other directory (a mounted image, an extracted archive, or an arbitrary folder), also the fallback when neither of the above is detected

Findings are reported per matched event (not per file), with the original host path reconstructed for KAPE/Velociraptor collections (e.g. a Velociraptor upload path is decoded back to `C:\Windows\System32\winevt\Logs\Security.evtx`).

Custom Sigma rules go in `signatures/sigma/`, and can be organized in subdirectories, e.g. `signatures/sigma/custom/` - rule loading is recursive. `raijin-util update` / `make fetch-signatures` only clear and refresh `.yml`/`.yaml` files directly at the top level of `signatures/sigma/`, so anything placed in a subdirectory survives updates untouched.

A rule the engine cannot parse is reported and skipped rather than failing the scan. To see which rules those are without running a scan:

```bash
./raijin-util validate
```

It parses every installed Sigma and YARA rule with the same code the scanner uses and prints, per engine, how many rules load and which files are unusable with the reason. `raijin-util update` runs it automatically once the download finishes, so a broken rule surfaces then rather than as a warning buried in your next scan.

Rules are routed to events by `logsource.product` (`windows`/`linux`), then narrowed by `category`/`service` against the event's own Windows Event Log `Channel` (and, for the most common categories like `process_creation`, its EventID too - e.g. a `process_creation` rule only considers Sysmon EventID 1 or Security EventID 4688, not every event sharing that channel). A category/service this routing doesn't recognize falls back to per-product matching rather than being guessed at.

**Current scope:**
- Linux log coverage is plain-text logs only (auditd `type=... msg=audit(...):` lines map best onto public Sigma rules; raw binary systemd-journal files are not parsed)
- Compressed/rotated logs (`*.gz`, etc.) are not decompressed
- Velociraptor collections must be pre-extracted (a raw `.zip` isn't read directly)

Disable this pass with `--no-sigma`.

## Usage

```bash
# Basic scan (TUI enabled by default)
sudo ./raijin

# Scan specific folder
sudo ./raijin --folder /tmp

# Disable TUI, use standard command-line output
sudo ./raijin --no-tui
```

## Common Scenarios

```bash
# Scan a mounted image (skip process scanning, use all cores)
sudo ./raijin --no-procs --folder ~/image1 --threads 0

# Offline analysis of a collected artifact dump (KAPE/Velociraptor/mount):
# YARA scans every file under -f, Sigma cold-scans EVTX/Linux logs found under
# -f, and live process scanning of this analysis machine is skipped entirely
./raijin --lab --folder /mnt/kape-dump

# Slow and cautious scan (lower CPU limit, single thread)
sudo ./raijin --cpu-limit 60 --threads 1

# Scan and send logs to remote syslog
sudo ./raijin --remote syslog-host.internal:514 --remote-proto udp
```

### Live triage of a Windows machine

Unpack the Windows release archive anywhere - it contains `raijin.exe`, `raijin-util.exe` and the rules current when the release was built, and needs nothing installed. (If the rule download failed at build time the `signatures/` directories are empty; `raijin-util.exe update` fills them.) From an **elevated** prompt (Administrator: reading other processes' memory and `Security.evtx` both require it):

```powershell
# Processes in memory against YARA, files on C:\ against YARA/IOCs, and every
# .evtx on C:\ - which includes C:\Windows\System32\winevt\Logs - against Sigma
.\raijin.exe

# All fixed drives, not just C:\
.\raijin.exe --scan-hard-drives

# Same, without the TUI (for a scheduled task or a remote shell)
.\raijin.exe --scan-hard-drives --no-tui

# Refresh the rules first, if the machine has internet access
.\raijin-util.exe update
```

Do **not** pass `--lab` here: it exists for offline analysis of a collected artifact dump and skips the live process scan. The live event logs are read in place; the EventLog service keeps them open for writing but not exclusively, so no export is needed. Each finding names the host and the event's own time (`HOST:` / `EVENT_TIME:` on the console, `source_host` / `event_timestamp` in the JSONL), so a report can be handed over without the scanning machine's name and clock getting in the way.

## Screenshots

![Raijin Startup](./images/raijin-screen-1.png)

![Raijin Interrup Menu](./images/raijin-interrupt-menu.png)

## Command Line Options

### Scan Target
| Option | Default | Description |
|--------|---------|-------------|
| `-f, --folder <PATH>` | `/` | Folder to scan. Quote paths containing spaces, e.g. `-f "J:\SteamLibrary\steamapps\common\SpaceCraft beta"` |
| `--signatures <DIR>` | *next to the binary, then `./signatures`* | Directory holding `yara/`, `sigma/` and `iocs/`. `RAIJIN_SIGNATURES` overrides the default; the flag overrides both |

### Scan Control
| Option | Default | Description |
|--------|---------|-------------|
| `--no-procs` | `false` | Skip process memory scanning |
| `--lab` | `false` | Offline/cold artifact analysis mode: skip live process scanning of this analysis machine (same effect as `--no-procs`, named for offline workflows where `-f` points at collected artifacts, not a live system) |
| `--no-fs` | `false` | Skip filesystem scanning |
| `--no-sigma` | `false` | Skip Sigma-rule artifact scanning (EVTX / Linux logs) |
| `--no-archive` | `false` | Skip scanning inside archives (ZIP) |
| `--scan-all-drives` | `false` | Scan all drives including mounted/network/cloud |
| `--scan-all-files` | `false` | Scan all files regardless of extension/type |

### Output Options
| Option | Default | Description |
|--------|---------|-------------|
| `-l, --log <FILE>` | auto | Plain text log file |
| `--no-log` | `false` | Disable plaintext log output |
| `-j, --jsonl <FILE>` | auto | JSONL output file |
| `--no-jsonl` | `false` | Disable JSONL output |
| `--no-html` | `false` | Disable HTML report generation |
| `--no-tui` | `false` | Disable TUI, use standard command-line output |
| `-r, --remote <HOST:PORT>` | none | Remote syslog destination |
| `-p, --remote-proto <PROTO>` | `udp` | Remote protocol (udp/tcp) |
| `--remote-format <FMT>` | `syslog` | Remote format (syslog/json) |

### Tuning
| Option | Default | Description |
|--------|---------|-------------|
| `--alert-level <SCORE>` | `80` | Score threshold for ALERT |
| `--warning-level <SCORE>` | `60` | Score threshold for WARNING |
| `--notice-level <SCORE>` | `40` | Score threshold for NOTICE |
| `--max-reasons <NUM>` | `2` | Max match reasons to display per finding |
| `-m, --max-file-size <BYTES>` | `64000000` | Maximum file size to scan (64MB) |
| `--yara-timeout <SECONDS>` | `10` | Maximum YARA scan time for each file or process-memory buffer (minimum: 1 second) |
| `--sigma-max-size <BYTES>` | `2000000000` | Maximum size of a Sigma artifact (EVTX/log), independent of `--max-file-size` |
| `--sigma-max-events-per-rule <N>` | `100` | Max findings a single Sigma rule may emit per artifact; further matches are still scored and counted, then summarised in one line (0 = unlimited) |
| `-c, --cpu-limit <PERCENT>` | `100` | CPU utilization limit (1-100) |
| `--threads <NUM>` | `-2` | Number of threads (0=all, -1=all-1, -2=all-2) |

### Info & Debug
| Option | Default | Description |
|--------|---------|-------------|
| `--version` | - | Show version and exit |
| `-d, --debug` | `false` | Show debug output |
| `--trace` | `false` | Show verbose trace output |
| `--show-access-errors` | `false` | Show file/process access errors |

## Excluding Files and Folders

Raijin provides multiple mechanisms for excluding files and folders from scans.

### Built-in Automatic Exclusions

By default, Raijin automatically excludes:

**System directories (Linux/macOS):**
- `/proc`, `/dev`, `/sys/kernel/debug`, `/sys/kernel/slab`, `/sys/kernel/tracing`, `/sys/devices`
- `/run`, `/var/run`

**Cloud storage directories** (unless `--scan-all-drives` is used):
- OneDrive, Dropbox, Google Drive, iCloud, Box, Nextcloud, pCloud, MEGA, Seafile, ownCloud, and others

**Network and mounted drives** (unless `--scan-all-drives` is used):
- NFS, CIFS/SMB, SSHFS, WebDAV mounts
- External media under `/media`, `/volumes`

**Program directory:**
- Raijin automatically excludes its own directory to prevent scanning itself

### Command-Line Exclusion Options

| Option | Description |
|--------|-------------|
| `--scan-all-drives` | Include mounted drives, network drives, and cloud storage |
| `--scan-all-files` | Scan all files regardless of file type/extension (by default, only relevant file types are scanned) |
| `-m, --max-file-size <BYTES>` | Skip files larger than this size (default: 64MB) |
| `--no-procs` | Skip process memory scanning entirely |
| `--no-fs` | Skip filesystem scanning entirely |
| `--no-archive` | Skip scanning inside archive files (ZIP) |

### Hash-Based False Positive Exclusions

You can exclude known good files by their hash. This is useful for whitelisting legitimate files that trigger false positives.

**Setup:**
1. Create a file in `signatures/iocs/` with both `hash` and `falsepositive` in the filename
   Example: `hash-falsepositive-custom.txt`

2. Add hashes (MD5, SHA1, or SHA256) with optional descriptions:
```
# Format: HASH;description
d41d8cd98f00b204e9800998ecf8427e;Empty file - known good
a7f5f35426b927411fc9231b56382173;Legitimate system utility
```

Files matching these hashes will be silently skipped during scanning.

### Filename Pattern False Positive Exclusions

When adding filename IOCs to `signatures/iocs/filename-iocs.txt`, you can specify a false positive exclusion regex in the third column:

```
# Format: REGEX;SCORE;FALSE_POSITIVE_REGEX
#
# This matches all .ps1 files, but excludes those in SysInternals directories
(?i)\\procdump(64)?\.(exe|zip);50;(?i)(SysInternals\\)
```

If a file matches both the main pattern AND the false positive regex, it will not be reported.

### Configuration File Exclusions

The `config/excludes.cfg` file supports regex-based path exclusions:

```
# Exclude system directories
^/proc/.*
^/dev/.*
^/sys/.*

# Exclude temporary files
.*\.tmp$
.*\.temp$
.*\.swp$

# Exclude specific directories
.*node_modules.*
.*/\.git/.*
```

**Note:** Path exclusion patterns are matched against the full file path using regular expressions. Lines starting with `#` are comments.

### Examples

```bash
# Scan but include all drives (network, cloud, mounted)
sudo ./raijin --scan-all-drives

# Scan all file types, not just executables and scripts
sudo ./raijin --scan-all-files

# Scan only small files (under 10MB)
sudo ./raijin --max-file-size 10000000

# Skip process scanning (useful for mounted images)
sudo ./raijin --no-procs --folder /mnt/image
```

## TUI Mode

The terminal interface is enabled by default and provides real-time monitoring during scans.

```bash
sudo ./raijin --folder /path/to/scan
```

![Raijin in Action](./images/raijin-run.gif)

| Key | Action |
|-----|--------|
| `q` | Quit |
| `p` | Pause/Resume |
| `s` | Skip current items |
| `t` | Toggle thread overlay |
| `+` / `-` | Adjust CPU limit |
| Arrow keys | Scroll logs |

![Raijin TUI Screenshot](./images/raijin-tui-1.png)

## HTML Reports

Raijin automatically generates a styled HTML report after each scan. The report is created alongside the JSONL log file and provides a visual summary of all findings.

The report includes:
- Scan configuration and runtime statistics
- Color-coded findings grouped by severity (Alert, Warning, Notice)
- File metadata (hashes, timestamps, size)
- YARA rule matches with descriptions and matched strings
- IOC match details with references

![Raijin HTML Report](./images/raijin-html-report.png)

The HTML report shares the same base filename as the JSONL output (e.g., `raijin_hostname_2025-01-08.html`). To disable report generation, use `--no-html`.

### Generating HTML Reports from JSONL Files

You can generate HTML reports from existing JSONL files using `raijin-util`:

```bash
# Generate HTML report from a single JSONL file
./raijin-util html --input scan_results.jsonl --output report.html

# Generate combined HTML report from multiple JSONL files
./raijin-util html --input "*.jsonl" --combine --output combined_report.html

# Use glob patterns to match multiple files
./raijin-util html --input "/path/to/scans/*.jsonl" --combine --output combined.html
```

**Options:**
- `--input <file|glob>` - Input JSONL file or glob pattern (required)
- `--output <file.html>` - Output HTML file (optional, defaults to input filename with .html extension)
- `--combine` - Combine multiple JSONL files into one report (groups findings by hostname)
- `--title <str>` - Override report title
- `--host <str>` - Override hostname in report

The combined report mode is useful for aggregating scan results from multiple hosts or time periods into a single view, with findings grouped by source hostname.

## Building from Source

```bash
git clone https://github.com/YOUR_GITHUB_USER/Raijin.git
cd Raijin
cargo build --release
./target/release/raijin-util update
sudo ./target/release/raijin
```

Requires Rust toolchain. See [docs/BUILD.md](docs/BUILD.md) for cross-compilation.

## Documentation

- [Build Guide](docs/BUILD.md)
- [Score Calculation](docs/score_calculation.md)
- [Parity Matrix](docs/parity_matrix.md)
- [Excluding Files and Folders](#excluding-files-and-folders)

## About

Raijin is a side project. It’s a fast, single-binary scanner built for practical triage and experimentation, and it may change quickly as ideas get tried and removed.

Support is community-based and best-effort - no SLA, no guaranteed response times, and no promise that every edge case is handled perfectly. If you run it in production, do it with that in mind.

## License

GNU General Public License v3.0. See [LICENSE](LICENSE).

Raijin is a derivative work based on Loki-RS, Copyright (c) 2025 Florian Roth, licensed under GPLv3. Modifications and additions (including the Sigma scanning module) are Copyright (c) 2026 TCS-CERT, also licensed under GPLv3.
