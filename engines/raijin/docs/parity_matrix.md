# Raijin Parity Matrix

This document provides a feature-by-feature comparison between Loki v1 and Raijin, identifying gaps, bugs, and implementation plans.

**Last Updated**: 2026-01-04
**Loki v1 Version**: 0.51.1
**Raijin Version**: 2.0.1-alpha

---

## Legend

**Status:**
- ✅ **Implemented**: Feature exists and works
- ⚠️ **Partial**: Feature exists but incomplete or has issues
- ❌ **Missing**: Feature not implemented
- 🐛 **Broken**: Feature exists but has bugs
- 🔄 **Divergent**: Works differently than v1 (may be intentional)

**Priority:**
- **P0**: Release blocker - must have for v1 parity
- **P1**: High priority - important for usability
- **P2**: Medium priority - nice to have
- **P3**: Low priority - can defer
- **Skip**: Can be skipped (better alternatives or not needed)

---

## Core Scanning Features

| Feature | Loki v1 Behavior | Raijin Status | Gap / Bug Description | Priority | Plan | Test Plan |
|---------|------------------|--------------|----------------------|----------|------|-----------|
| **File System Scanning** | Recursive directory walk with `os.walk()`, `followlinks=False` | ✅ Implemented | Uses `walkdir` with `follow_links(false)` to match v1 behavior | ✅ | ✅ Complete | Test with symlink directories |
| **File Type Filtering** | Filters by extension list + file magic signatures | ⚠️ Partial | Uses `file-format` crate, different approach, missing "evil extensions" list | P1 | Add evil extensions list, consider file magic loading | Test with various file types |
| **File Size Limit** | Default 5000 KB, configurable via `-s` | ⚠️ Partial | Default 10MB (bytes), no KB option | P1 | Add `-s` flag for KB, keep bytes option | Test size limit enforcement |
| **Hash IOC Matching** | MD5/SHA1/SHA256 matching with binary search | ✅ Implemented | Binary search implemented - hashes organized by type and sorted for O(log n) lookup | ✅ | ✅ Complete | Test with large hash IOC files |
| **Hash Score Parsing** | Reads score from IOC file (3-column format) | ✅ Implemented | Supports 2-column (hash;description → score=75) and 3-column (hash;score;description) formats | ✅ | ✅ Complete | Test with IOC files containing scores |
| **False Positive Hashes** | Checks false positive hashes before matching | ✅ Implemented | Loads files with "hash" and "falsepositive" in filename, checks before hash matching, skips file if match found | ✅ | ✅ Complete | Test with false positive hash file |
| **Hash Whitelist** | Excludes empty file hashes | ❌ Missing | No whitelist | P2 | Add hash whitelist | Test with empty files |
| **Filename IOC Matching** | Regex matching on full file path | ✅ Implemented | Regex compilation and matching implemented, supports false positive regex | ✅ | ✅ Complete | Test with filename IOC patterns |
| **Filename IOC False Positives** | Optional FP regex per IOC | ✅ Implemented | Third column parsed as false positive regex | ✅ | ✅ Complete | Test with FP patterns |
| **Filename IOC Environment Vars** | Replaces `%VAR%` / `$VAR` in patterns | ❌ Missing | No replacement | P2 | Add env var replacement | Test with patterns containing vars |
| **YARA Rule Compilation** | Compiles from multiple directories | ⚠️ Partial | Only one directory, no recursive walk. ✅ Migrated to YARA-X. | P1 | Add recursive walk, multiple directories | Test with nested rule directories |
| **YARA Metadata Extraction** | Extracts score, description, reference, author | ✅ Implemented | Using YARA-X API: `matching_rule.metadata()` extracts description, author, score from rule metadata | ✅ | ✅ Complete - Migrated to YARA-X | Test with rules containing metadata |
| **YARA Matched Strings** | Shows matched string values with offsets | ✅ Implemented | Using YARA-X API: `pattern.matches()` extracts matched strings with offsets, hex-encodes non-ASCII | ✅ | ✅ Complete - Migrated to YARA-X | Test with rules that match strings, including non-ASCII |
| **YARA Memory Rules** | Checks `memory` meta field for process scanning | ❌ Missing | Scans all rules on processes | P1 | Filter rules by memory flag | Test with memory-only rules |
| **Process Memory Scanning** | YARA scan of process memory | ✅ Implemented | Works, but no working set limit | P1 | Add `--maxworkingset` flag | Test with large processes |
| **C2 IOC Matching** | Matches process network connections | ✅ Implemented | Loads C2 IOCs from files with "c2" in filename, matches against process network connections from /proc/net/tcp and /proc/net/udp | ✅ | ✅ Complete | Test with process connections |

---

## CLI Interface

| Feature | Loki v1 Behavior | Raijin Status | Gap / Bug Description | Priority | Plan | Test Plan |
|---------|------------------|--------------|----------------------|----------|------|-----------|
| **Path Selection (`-p`)** | Default `C:\` or `/`, configurable | ⚠️ Partial | Uses `--folder` instead of `-p` | P1 | Add `-p` alias, keep `--folder` | Test path selection |
| **File Size (`-s` KB)** | Size in KB, default 5000 | ❌ Missing | Only bytes option exists | P1 | Add `-s` flag for KB | Test KB vs bytes |
| **Score Thresholds (`-a/-w/-n`)** | Alert/Warning/Notice levels | ✅ Implemented | `--alert-level`, `--warning-level`, `--notice-level` flags (default: 80/60/40), `--max-reasons` flag | ✅ | ✅ Complete | Test with different thresholds |
| **Log File (`-l`)** | Custom log file path | ❌ Missing | Fixed filename only | P2 | Add `-l` flag | Test custom log paths |
| **Log Folder (`--logfolder`)** | Folder for log files | ❌ Missing | No folder option | P2 | Add `--logfolder` flag | Test log folder |
| **No Log (`--nolog`)** | Skip log file writing | ❌ Missing | Always writes log | P2 | Add `--nolog` flag | Test no log mode |
| **Syslog (`-r/-t/--syslogtcp`)** | Remote syslog logging | ❌ Missing | No syslog support | P3 | Add syslog support (low priority) | Test syslog output |
| **CSV Output (`--csv`)** | CSV format to STDOUT | ❌ Missing | No CSV mode | P2 | Add CSV output format | Test CSV parsing |
| **Only Relevant (`--onlyrelevant`)** | Filter to warnings/alerts | ❌ Missing | All messages logged | P2 | Add filtering | Test message filtering |
| **Print All (`--printall`)** | Log all scanned files | ❌ Missing | No verbose mode | P3 | Add verbose logging | Test verbose output |
| **All Reasons (`--allreasons`)** | Show all match reasons | ⚠️ Partial | Always shows all (no option to limit) | P3 | Add flag to limit reasons | Test reason display |
| **Intense Mode (`--intense`)** | Scan unknown file types | ⚠️ Partial | `--scan-all-files` similar but not identical | P2 | Align with v1 behavior | Test intense mode |
| **Force (`--force`)** | Override exclusions | ❌ Missing | No override option | P2 | Add force flag | Test exclusion override |
| **Version (`--version`)** | Show version and exit | ✅ Implemented | `--version` flag shows version and exits | ✅ | ✅ Complete | Test version display |
| **Update (`--update`)** | Update signatures | ⚠️ Partial | `raijin-util` implements update, but main binary does not have `--update` flag | P2 | Encourage `raijin-util` usage | Test signature update |
| **Help (`-h/--help`)** | Show help | ✅ Implemented | Works via rustop | ✅ | - | - |

---

## Path Exclusions and Filtering

| Feature | Loki v1 Behavior | Raijin Status | Gap / Bug Description | Priority | Plan | Test Plan |
|---------|------------------|--------------|----------------------|----------|------|-----------|
| **Linux Path Exclusions** | Excludes `/proc`, `/dev`, `/sys`, etc. | ✅ Implemented | Excludes `/proc`, `/dev`, `/sys/kernel/debug`, `/sys/kernel/slab`, `/sys/devices`, `/usr/src/linux`, `/media`, `/volumes` (unless `--scan-all-drives`) | ✅ | ✅ Complete | Test on Linux system |
| **Windows Drive Handling** | `--allhds`, `--alldrives` options | ❌ Missing | No Windows-specific drive handling | P2 | Add Windows drive enumeration | Test on Windows |
| **User Excludes Config** | `config/excludes.cfg` regex patterns | ❌ Missing | No config file support | P1 | Load and apply excludes.cfg | Test with exclude patterns |
| **Program Directory Skip** | Skips Raijin's own directory | ❌ Missing | May scan own directory | P1 | Detect and skip program directory | Test with Raijin in scan path |
| **Mounted Devices** | Excludes `/media`, `/volumes` | ✅ Implemented | Excludes `/media` and `/Volumes` | ✅ | ✅ Complete | Test with mounted drives |
| **Network Drives** | Excludes network drives (unless `--alldrives`) | ❌ Missing | No network drive detection | P2 | Detect and exclude network drives | Test with network mounts |

---

## Output and Reporting

| Feature | Loki v1 Behavior | Raijin Status | Gap / Bug Description | Priority | Plan | Test Plan |
|---------|------------------|--------------|----------------------|----------|------|-----------|
| **Console Colors** | Colorama with specific colors per level | ⚠️ Partial | Basic colors via flexi_logger | P2 | Enhance colorization to match v1 | Test color output |
| **Message Formatting** | Key-value pairs with line breaks | ⚠️ Partial | Basic formatting | P2 | Add key-value formatting | Test formatted output |
| **Result Summary** | Final counts and recommendations | ✅ Implemented | Shows files/processes scanned/matched and alert/warning/notice counts at end of scan | ✅ | ✅ Complete | Test summary output |
| **Alert/Warning/Notice Counters** | Tracks counts per level | ✅ Implemented | Counted during scan and displayed in summary | ✅ | ✅ Complete | Test counter accuracy |
| **Log File Timestamp** | `raijin_{hostname}_{timestamp}.log` | ⚠️ Partial | No timestamp in filename | P2 | Add timestamp to filename | Test log file naming |
| **Log File Removal** | Removes old log at start | ⚠️ Partial | Appends instead | P2 | Remove old log file | Test log file handling |

---

## Error Handling and Robustness

| Feature | Loki v1 Behavior | Raijin Status | Gap / Bug Description | Priority | Plan | Test Plan |
|---------|------------------|--------------|----------------------|----------|------|-----------|
| **Graceful IOC Load Errors** | Logs error, continues or exits gracefully | ✅ Implemented | Replaced `expect()` with Result handling, returns empty vectors on errors | ✅ | ✅ Complete | Test with missing IOC files |
| **Graceful YARA Errors** | Logs error, skips file | ✅ Implemented | Returns Result from compilation, handles scan errors gracefully | ✅ | ✅ Complete | Test with invalid YARA rules |
| **File Access Error Handling** | Logs and continues | ✅ Implemented | Handles errors gracefully | ✅ | ✅ Complete | - |
| **Process Scan Error Handling** | Logs and continues | ✅ Implemented | Handles errors gracefully | ✅ | ✅ Complete | - |
| **Exit Codes** | 0 for success, 1 for errors | ✅ Implemented | Exit 0 for success (no matches), exit 1 for fatal errors, exit 2 for partial success (matches found) | ✅ | ✅ Complete | Test exit code scenarios |
| **Signal Handling (CTRL+C)** | Catches SIGINT, exits gracefully | ❌ Missing | No signal handling | P1 | Add signal handler | Test CTRL+C handling |
| **Argument Validation** | Validates conflicting flags | ⚠️ Partial | Validates score thresholds (alert > warning > notice) | P1 | Add more argument validation | Test invalid flag combinations |

---

## Platform-Specific Features

| Feature | Loki v1 Behavior | Raijin Status | Gap / Bug Description | Priority | Plan | Test Plan |
|---------|------------------|--------------|----------------------|----------|------|-----------|
| **Windows Process Enumeration** | WMI for process list | ⚠️ Partial | Uses sysinfo (cross-platform) | P2 | Consider WMI for Windows | Test process enumeration |
| **PE-Sieve Integration** | Windows process analysis tool | ❌ Missing | No PE-Sieve support | Skip | Windows-only, complex dependency | - |
| **Rootkit Check** | Regin filesystem check | ❌ Missing | No rootkit check | Skip | Windows-only, specialized | - |
| **Vulnerability Checks** | Windows vulnerability scanner | ❌ Missing | No vuln checks | Skip | Windows-only, specialized | - |
| **Process Anomaly Checks** | System process validation | ❌ Missing | No anomaly checks | P3 | Low priority, Windows-focused | - |
| **DoublePulsar Check** | Backdoor detection | ❌ Missing | No DoublePulsar check | Skip | Windows-only, specialized | - |
| **Admin/Root Check** | Warns if not admin/root | ❌ Missing | No privilege check | P2 | Add privilege detection | Test privilege warnings |
| **Process Priority** | Sets nice priority | ❌ Missing | No priority setting | P3 | Low priority | - |

---

## Advanced Features

| Feature | Loki v1 Behavior | Raijin Status | Gap / Bug Description | Priority | Plan | Test Plan |
|---------|------------------|--------------|----------------------|----------|------|-----------|
| **Levenshtein Distance** | Filename similarity check | ❌ Missing | No Levenshtein check | P3 | Low priority, can be added later | - |
| **Script Analysis** | Statistical obfuscation detection | ❌ Missing | Beta feature in v1 | Skip | Beta feature, can skip | - |
| **Progress Indicator** | File count display | ❌ Missing | No progress display | P3 | Nice to have | - |
| **SWF Decompression** | Decompresses SWF files | ❌ Missing | No archive handling | Skip | Specialized, low usage | - |
| **Memory Dump Scanning** | Special handling for MDMP files | ❌ Missing | No special case | P2 | Add MDMP special handling | Test with memory dumps |

---

## Performance Optimizations

| Feature | Loki v1 Behavior | Raijin Status | Gap / Bug Description | Priority | Plan | Test Plan |
|---------|------------------|--------------|----------------------|----------|------|-----------|
| **Hash Binary Search** | Sorted lists + binary search | ✅ Implemented | Hashes are sorted by type and value, using `binary_search_by` | ✅ | ✅ Complete | Test with large hash sets |
| **File Magic Caching** | Caches max signature length | ❌ Missing | No magic file support | P2 | If adding magic file, cache length | - |
| **YARA Rule Reuse** | Compiled once, reused | ✅ Implemented | Works correctly | ✅ | - | - |

---

## Release Blockers (P0)

These features must be implemented for v1 parity:

1. **Error Handling** - Robust recovery - continue scanning even if individual checks fail (Completed)
2. **Hash Score Parsing** - Default score: 75, support 2/3 columns (Completed)
3. **Score Thresholds** - Alert/Warning/Notice configuration (Completed)
4. **Score Calculation** - Weighted score formula (Completed)
5. **Exit Codes** - Follow common standards (Completed)
6. **Linux Path Exclusions** - Exclude system directories on Linux (Completed)
7. **YARA Metadata Extraction** - Extract info from rules (Completed)

---

## High Priority (P1)

Important for usability but not blockers:

1. **User Excludes Config** - Load `config/excludes.cfg`
2. **Filename IOC Environment Vars** - Resolve `%SystemRoot%` etc.
3. **YARA Memory Rules** - Filter process scanning rules
4. **Signal Handling** - Handle CTRL+C gracefully
5. **Log File Timestamp** - Add timestamp to log filename
6. **Process Working Set Limit** - Stability for large processes

---

## Can Be Skipped or Deferred

These features can be skipped or have better alternatives:

1. **PE-Sieve Integration** - Windows-only, complex dependency, can skip
2. **Rootkit Check** - Windows-only, specialized, can skip
3. **Vulnerability Checks** - Windows-only, specialized, can skip
4. **DoublePulsar Check** - Windows-only, specialized, can skip
5. **Script Analysis** - Beta feature in v1, can skip
6. **SWF Decompression** - Specialized, low usage, can skip
7. **Levenshtein Distance** - Low priority, can defer
8. **Progress Indicator** - Nice to have, can defer
9. **Syslog Support** - Low usage, can defer to P3

