/// Cold-scan module: evaluates Sigma detection rules against Windows EVTX
/// and Linux text-log artifacts found under an auto-detected forensic
/// artifact-collection layout (KAPE / Velociraptor / plain mount).
///
/// Diverges deliberately from `filesystem_scan.rs`'s per-file aggregation:
/// a Sigma finding is about one event (one EVTX record, one log line), not
/// "this file is bad" — so `logger.file_match` is called once per matching
/// event rather than once per file. See the plan doc for the full rationale.
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Datelike, NaiveDateTime, Utc};
use evtx::{EvtxParser, ParserSettings, SerializedEvtxRecord};
use regex::Regex;
use rayon::prelude::*;
use sha1::*;
use sha2::{Digest, Sha256};
use sigma_rust::Event;
use walkdir::{DirEntry, WalkDir};

use crate::helpers::artifact_profile::{detect_artifact_profile, ArtifactProfile};
use crate::helpers::evtx_normalize::flatten_evtx_record;
use crate::helpers::interrupt::ScanState;
use crate::helpers::linux_log_parse::{parse_auditd_line, parse_syslog_line};
use crate::helpers::score::calculate_weighted_score;
use crate::helpers::sigma_rules::{level_name, LoadedSigmaRule, SigmaRuleIndex};
use crate::helpers::unified_logger::{EventOrigin, FileFinding, LogLevel, MatchReason, UnifiedLogger};
use crate::modules::{ModuleResult, ScanContext, ScanModule};
use crate::{GenMatch, ScanConfig};

#[derive(Clone, Copy)]
enum LinuxLogFormat {
    Syslog,
    Auditd,
}

const LINUX_LOG_FILENAME_PATTERNS: &[(&str, LinuxLogFormat)] = &[
    ("auth.log", LinuxLogFormat::Syslog),
    ("syslog", LinuxLogFormat::Syslog),
    ("secure", LinuxLogFormat::Syslog),
    ("messages", LinuxLogFormat::Syslog),
    ("kern.log", LinuxLogFormat::Syslog),
    ("daemon.log", LinuxLogFormat::Syslog),
    ("user.log", LinuxLogFormat::Syslog),
    ("audit.log", LinuxLogFormat::Auditd),
];

fn is_evtx_file(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case("evtx")).unwrap_or(false)
}

/// Matches a filename against the known Linux log names, allowing a
/// numeric rotation suffix (`auth.log.1`). Compressed/rotated (`*.gz`) logs
/// are explicitly out of scope for v1.
fn classify_linux_log(filename: &str) -> Option<LinuxLogFormat> {
    for (pattern, format) in LINUX_LOG_FILENAME_PATTERNS {
        if filename == *pattern {
            return Some(*format);
        }
        if let Some(rest) = filename.strip_prefix(pattern) {
            if let Some(digits) = rest.strip_prefix('.') {
                if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) {
                    return Some(*format);
                }
            }
        }
    }
    None
}

fn sum_results(a: ModuleResult, b: ModuleResult) -> ModuleResult {
    (a.0 + b.0, a.1 + b.1, a.2 + b.2, a.3 + b.3, a.4 + b.4)
}

pub struct SigmaScanModule;

impl ScanModule for SigmaScanModule {
    fn name(&self) -> &'static str {
        "SigmaScan"
    }

    fn run(&self, context: &ScanContext) -> ModuleResult {
        scan_sigma_artifacts(
            context.target_folder,
            context.sigma_rules,
            context.scan_config,
            context.exclusion_patterns,
            context.logger,
            context.scan_state.as_ref(),
        )
    }
}

fn profile_name(profile: &ArtifactProfile) -> &'static str {
    match profile {
        ArtifactProfile::Kape { .. } => "KAPE output",
        ArtifactProfile::Velociraptor { .. } => "Velociraptor collection",
        ArtifactProfile::Mount { .. } => "plain mount",
    }
}

pub fn scan_sigma_artifacts(
    target_folder: &str,
    sigma_rules: &SigmaRuleIndex,
    scan_config: &ScanConfig,
    exclusion_patterns: &Vec<Regex>,
    logger: &UnifiedLogger,
    scan_state: Option<&Arc<ScanState>>,
) -> ModuleResult {
    if sigma_rules.total_rule_count() == 0 {
        logger.debug("Sigma scan: no Sigma rules loaded, skipping");
        return (0, 0, 0, 0, 0);
    }

    let root = Path::new(target_folder);
    let profile = detect_artifact_profile(root);
    logger.info(&format!("Sigma scan: detected artifact layout: {}", profile_name(&profile)));

    profile
        .walk_roots()
        .into_iter()
        .map(|walk_root| {
            WalkDir::new(&walk_root)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
                .par_bridge()
                .map(|entry| {
                    process_artifact_entry(
                        entry,
                        &profile,
                        sigma_rules,
                        scan_config,
                        exclusion_patterns,
                        logger,
                        scan_state,
                    )
                })
                .reduce(|| (0, 0, 0, 0, 0), sum_results)
        })
        .fold((0, 0, 0, 0, 0), sum_results)
}

fn process_artifact_entry(
    entry: DirEntry,
    profile: &ArtifactProfile,
    sigma_rules: &SigmaRuleIndex,
    scan_config: &ScanConfig,
    exclusion_patterns: &Vec<Regex>,
    logger: &UnifiedLogger,
    scan_state: Option<&Arc<ScanState>>,
) -> ModuleResult {
    let path = entry.path();
    let path_str = path.to_string_lossy();

    if let Some(state) = scan_state {
        if state.should_stop() {
            return (0, 0, 0, 0, 0);
        }
        state.wait_for_resume();
        if state.should_stop() {
            return (0, 0, 0, 0, 0);
        }
        state.set_current_element(path_str.to_string());
        state.increment_files();
    }

    if entry.path_is_symlink() {
        if let Some(state) = scan_state {
            state.increment_skipped();
        }
        return (0, 0, 0, 0, 0);
    }

    if let Some(ref program_dir) = scan_config.program_dir {
        if path.starts_with(Path::new(program_dir)) {
            if let Some(state) = scan_state {
                state.increment_skipped();
            }
            return (0, 0, 0, 0, 0);
        }
    }

    for pattern in exclusion_patterns.iter() {
        if pattern.is_match(&path_str) {
            if let Some(state) = scan_state {
                state.increment_skipped();
            }
            return (0, 0, 0, 0, 0);
        }
    }

    let Some(filename) = path.file_name().and_then(|n| n.to_str()) else {
        return (0, 0, 0, 0, 0);
    };

    if is_evtx_file(path) {
        process_evtx_file(path, profile, sigma_rules, scan_config, logger, scan_state)
    } else if let Some(format) = classify_linux_log(filename) {
        process_linux_log_file(path, format, profile, sigma_rules, scan_config, logger, scan_state)
    } else {
        (0, 0, 0, 0, 0)
    }
}

/// Aggregates Sigma matches for one event into a scored finding and emits
/// it via `logger.file_match`, mirroring the aggregation pattern
/// `filesystem_scan.rs::scan_memory_buffer` uses for YARA matches.
///
/// `emit == false` scores and counts the event but writes no finding - see
/// `RuleEmissionBudget`. The returned level is the same either way, so the
/// caller's alert/warning/notice tallies stay complete.
#[allow(clippy::too_many_arguments)]
fn emit_event_finding(
    display_path: &str,
    file_type: &str,
    file_size: u64,
    md5_value: &str,
    sha1_value: &str,
    sha256_value: &str,
    origin: EventOrigin,
    sub_matches: &[GenMatch],
    emit: bool,
    scan_config: &ScanConfig,
    logger: &UnifiedLogger,
    scan_state: Option<&Arc<ScanState>>,
) -> Option<LogLevel> {
    if sub_matches.is_empty() {
        return None;
    }

    let sub_scores: Vec<i16> = sub_matches.iter().map(|m| m.score).collect();
    let total_score = calculate_weighted_score(&sub_scores).round() as i16;

    let level = if total_score as f64 >= scan_config.alert_threshold as f64 {
        if let Some(state) = scan_state {
            state.add_alerts(1);
        }
        LogLevel::Alert
    } else if total_score as f64 >= scan_config.warning_threshold as f64 {
        if let Some(state) = scan_state {
            state.add_warnings(1);
        }
        LogLevel::Warning
    } else if total_score as f64 >= scan_config.notice_threshold as f64 {
        if let Some(state) = scan_state {
            state.add_notices(1);
        }
        LogLevel::Notice
    } else {
        return None;
    };

    // Built inside the guard: cloning every reason only to drop it is the bulk
    // of the per-event cost a suppressed match is meant to avoid.
    if emit {
        let reasons_to_show = std::cmp::min(sub_matches.len(), scan_config.max_reasons);
        let shown_reasons: Vec<MatchReason> = sub_matches
            .iter()
            .take(reasons_to_show)
            .map(|m| MatchReason {
                message: m.message.clone(),
                score: m.score,
                description: m.description.clone(),
                author: m.author.clone(),
                reference: m.reference.clone(),
                matched_strings: m.matched_strings.clone(),
                rule: m.rule.clone(),
            })
            .collect();

        logger.file_match(FileFinding {
            level,
            path: display_path,
            score: total_score as f64,
            file_type,
            file_size,
            md5: md5_value,
            sha1: sha1_value,
            sha256: sha256_value,
            reasons: shown_reasons,
            // The event's own time used to be written into all three file
            // timestamp slots, so a report read "Created: <event time>" for
            // a log record. It travels as `origin.timestamp` now, and the
            // container file's dates are simply not part of the finding.
            file_created: None,
            file_modified: None,
            file_accessed: None,
            origin,
        });
    }

    Some(level)
}

fn bump_counts(result: &mut ModuleResult, level: LogLevel) {
    result.1 += 1;
    match level {
        LogLevel::Alert => result.2 += 1,
        LogLevel::Warning => result.3 += 1,
        LogLevel::Notice => result.4 += 1,
        _ => {}
    }
}

/// Records are matched in parallel batches of this size: large enough to
/// amortize rayon's per-task overhead, small enough to bound memory and keep
/// the stop/pause checks responsive.
const EVTX_BATCH_SIZE: usize = 512;

/// Maximum length of one event field value attached to a finding.
const MAX_FIELD_VALUE_LEN: usize = 400;

/// Per-artifact cap on how many findings any single Sigma rule may emit.
///
/// Emitting one finding per matching event is deliberate (see the module
/// header), but a rule that matches a recurring, benign-in-context event -
/// "Publicly Accessible RDP Service" against a busy DNS Server.evtx, say -
/// produces one near-identical finding per record: 22k findings for a single
/// 85 MB artifact, each carrying the full file metadata block. That floods
/// the log outputs and, worse, the unbounded channel feeding the TUI, which
/// drains at a bounded rate and falls arbitrarily far behind.
///
/// So the first `max_per_rule` events matching a given rule are reported in
/// full and the rest are counted, with `drain_suppressed` yielding one
/// summary line per rule at end of artifact. Stats are unaffected: suppressed
/// events are still scored and still counted as alerts/warnings/notices, so
/// the totals keep telling the truth about what matched.
struct RuleEmissionBudget {
    /// 0 means unlimited - every matching event is emitted.
    max_per_rule: usize,
    /// Keyed by the rule's Sigma `id`, falling back to its title when the
    /// rule carries no id. Locked only on the matched path, which is rare
    /// except in exactly the flood case this exists to contain.
    seen: Mutex<HashMap<String, RuleEmissionCount>>,
}

struct RuleEmissionCount {
    title: String,
    emitted: usize,
    suppressed: usize,
}

impl RuleEmissionBudget {
    fn new(max_per_rule: usize) -> Self {
        Self { max_per_rule, seen: Mutex::new(HashMap::new()) }
    }

    /// Records one match of `rule` and reports whether it is still within
    /// budget. A poisoned lock means another thread panicked mid-update; the
    /// budget is an output-volume guard, not a correctness invariant, so the
    /// match is admitted rather than propagating the panic into the scan.
    fn admit(&self, loaded: &LoadedSigmaRule) -> bool {
        if self.max_per_rule == 0 {
            return true;
        }
        let key = loaded.rule.id.as_deref().unwrap_or(&loaded.rule.title);
        let Ok(mut seen) = self.seen.lock() else { return true };
        // Looked up before `entry`, which would allocate an owned key on every
        // match - this runs once per matching event, so only the first match
        // of each rule should pay for it.
        let entry = match seen.get_mut(key) {
            Some(entry) => entry,
            None => seen.entry(key.to_string()).or_insert(RuleEmissionCount {
                title: loaded.rule.title.clone(),
                emitted: 0,
                suppressed: 0,
            }),
        };
        if entry.emitted < self.max_per_rule {
            entry.emitted += 1;
            true
        } else {
            entry.suppressed += 1;
            false
        }
    }

    /// (title, emitted, suppressed) for every rule that exceeded its budget,
    /// ordered by suppressed count so the noisiest rule reads first.
    fn drain_suppressed(&self) -> Vec<(String, usize, usize)> {
        let Ok(seen) = self.seen.lock() else { return Vec::new() };
        let mut over: Vec<(String, usize, usize)> = seen
            .values()
            .filter(|c| c.suppressed > 0)
            .map(|c| (c.title.clone(), c.emitted, c.suppressed))
            .collect();
        over.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
        over
    }
}

/// Logs one summary line per rule that hit its per-artifact emission cap.
fn report_suppressed(budget: &RuleEmissionBudget, display_path: &str, logger: &UnifiedLogger) {
    for (title, emitted, suppressed) in budget.drain_suppressed() {
        logger.warning(&format!(
            "Sigma scan: rule '{}' matched {} further event(s) in {} beyond the first {} reported \
             (raise --sigma-max-events-per-rule, or 0 for unlimited, to see them all)",
            title,
            suppressed,
            display_path,
            emitted
        ));
    }
}

/// Per-file constants shared by every record of one EVTX file.
struct EvtxFileContext<'a> {
    display_path: &'a str,
    file_size: u64,
    md5: &'a str,
    sha1: &'a str,
    sha256: &'a str,
    budget: &'a RuleEmissionBudget,
}

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max).collect();
        t.push_str("...");
        t
    }
}

/// Builds the finding reason for one matched rule, attaching the event's
/// identity (EventID/Channel/RecordID/Computer) plus the values of the
/// fields the rule's detection block references - what an analyst needs to
/// triage the hit without re-opening the EVTX.
fn build_sigma_match(
    loaded: &LoadedSigmaRule,
    event: &Event,
    event_id: Option<u32>,
    channel: Option<&str>,
    record_id: Option<u64>,
) -> GenMatch {
    let computer = event.get("Computer").map(|v| v.value_to_string()).unwrap_or_default();
    let mut header = String::new();
    if let Some(id) = event_id {
        header.push_str(&format!("EventID={} ", id));
    }
    if let Some(ch) = channel {
        header.push_str(&format!("Channel={} ", ch));
    }
    if let Some(rid) = record_id {
        header.push_str(&format!("RecordID={} ", rid));
    }
    if !computer.is_empty() {
        header.push_str(&format!("Computer={} ", computer));
    }
    header.push_str(&format!("Level={}", level_name(&loaded.rule)));
    if let Some(id) = loaded.rule.id.as_deref() {
        header.push_str(&format!(" RuleID={}", id));
    }

    let mut matched_strings = vec![header.trim().to_string()];
    for field in &loaded.fields {
        if field == "EventID" || field == "Channel" || field == "Computer" {
            continue;
        }
        if let Some(value) = event.get(field) {
            let rendered = value.value_to_string();
            if rendered.is_empty() {
                continue;
            }
            matched_strings.push(format!("{}: {}", field, truncate_chars(&rendered, MAX_FIELD_VALUE_LEN)));
        }
    }

    GenMatch {
        message: format!("Sigma rule match: {}", loaded.rule.title),
        score: loaded.score,
        description: loaded.rule.description.clone(),
        author: loaded.rule.author.clone(),
        reference: loaded.rule.references.as_ref().and_then(|r| r.first().cloned()),
        matched_strings: Some(matched_strings),
        rule: Some(crate::types::RuleRef {
            engine: "sigma".to_string(),
            name: loaded.rule.title.clone(),
            id: loaded.rule.id.clone(),
            file: loaded.source_file.clone(),
            tags: loaded.rule.tags.clone().unwrap_or_default(),
            level: Some(level_name(&loaded.rule).to_string()),
            ..Default::default()
        }),
    }
}

/// Evaluates one parsed EVTX record against the applicable Sigma rules and
/// emits a finding if anything matched. Returns the finding's level.
fn evaluate_evtx_record(
    record: &SerializedEvtxRecord<serde_json::Value>,
    ctx: &EvtxFileContext,
    sigma_rules: &SigmaRuleIndex,
    scan_config: &ScanConfig,
    logger: &UnifiedLogger,
    scan_state: Option<&Arc<ScanState>>,
) -> Option<LogLevel> {
    let flat = flatten_evtx_record(&record.data);
    let channel = flat.get("Channel").and_then(|v| v.as_str()).map(|s| s.to_string());
    // The originating machine, straight from the record. Without this a
    // finding would report the analysis workstation's hostname, which says
    // nothing about which host in the collection the event came from.
    let source_host = flat
        .get("Computer")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());
    let event_id = flat
        .get("EventID")
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok())))
        .and_then(|id| u32::try_from(id).ok());
    let event = Event::try_from(flat).ok()?;

    // An event is reported if at least one of the rules it matched is still
    // within budget; rules already over budget have this match counted
    // against them either way, so a rule that only ever co-occurs with a
    // quieter one still gets an accurate suppressed tally.
    let mut emit = false;
    let sub_matches: Vec<GenMatch> = sigma_rules
        .windows_candidates(channel.as_deref(), event_id)
        .filter(|loaded| loaded.rule.is_match(&event))
        .map(|loaded| {
            emit |= ctx.budget.admit(loaded);
            build_sigma_match(loaded, &event, event_id, channel.as_deref(), Some(record.event_record_id))
        })
        .collect();

    if sub_matches.is_empty() {
        return None;
    }

    emit_event_finding(
        ctx.display_path,
        "EVTX Record",
        ctx.file_size,
        ctx.md5,
        ctx.sha1,
        ctx.sha256,
        EventOrigin { host: source_host, timestamp: Some(record.timestamp.to_string()) },
        &sub_matches,
        emit,
        scan_config,
        logger,
        scan_state,
    )
}

/// Matches one batch of records in parallel and folds the per-level counts
/// into `result`.
fn flush_evtx_batch(
    batch: &mut Vec<SerializedEvtxRecord<serde_json::Value>>,
    ctx: &EvtxFileContext,
    sigma_rules: &SigmaRuleIndex,
    scan_config: &ScanConfig,
    logger: &UnifiedLogger,
    scan_state: Option<&Arc<ScanState>>,
    result: &mut ModuleResult,
) {
    if batch.is_empty() {
        return;
    }
    let counts = batch
        .par_iter()
        .map(|record| {
            let mut r: ModuleResult = (0, 0, 0, 0, 0);
            if let Some(level) = evaluate_evtx_record(record, ctx, sigma_rules, scan_config, logger, scan_state) {
                bump_counts(&mut r, level);
            }
            r
        })
        .reduce(|| (0, 0, 0, 0, 0), sum_results);
    result.1 += counts.1;
    result.2 += counts.2;
    result.3 += counts.3;
    result.4 += counts.4;
    if let Some(state) = scan_state {
        state.add_sigma_events(batch.len());
    }
    batch.clear();
}

/// Size of one read when hashing an artifact without holding it in memory.
const HASH_CHUNK_SIZE: usize = 1 << 20;

/// MD5/SHA1/SHA256 of a file, read in fixed-size chunks.
///
/// The obvious `fs::read` + hash costs one anonymous allocation the size of
/// the whole artifact, per file, on every thread scanning one - and Sigma
/// artifacts are walked with `par_bridge`, so that is (threads x artifact
/// size) of unreclaimable heap. A 38-thread run over a forensic collection
/// reached 118 GB of anon-rss that way and was killed by the OOM killer.
/// Hashing in chunks keeps it at `HASH_CHUNK_SIZE` per thread.
fn hash_file_streaming(path: &Path) -> std::io::Result<(String, String, String, u64)> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::with_capacity(HASH_CHUNK_SIZE, file);

    let mut md5_ctx = md5::Context::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut buf = vec![0u8; HASH_CHUNK_SIZE];
    let mut total = 0u64;

    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        md5_ctx.consume(&buf[..read]);
        sha1.update(&buf[..read]);
        sha256.update(&buf[..read]);
        total += read as u64;
    }

    Ok((
        format!("{:x}", md5_ctx.finalize()),
        hex::encode(sha1.finalize()),
        hex::encode(sha256.finalize()),
        total,
    ))
}

fn process_evtx_file(
    path: &Path,
    profile: &ArtifactProfile,
    sigma_rules: &SigmaRuleIndex,
    scan_config: &ScanConfig,
    logger: &UnifiedLogger,
    scan_state: Option<&Arc<ScanState>>,
) -> ModuleResult {
    let display_path = profile.rewrite_path(path);

    let metadata = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            logger.debug(&format!("Sigma scan: failed to stat {}: {}", path.display(), e));
            return (0, 0, 0, 0, 0);
        }
    };
    if metadata.len() > scan_config.sigma_max_artifact_size as u64 {
        logger.warning(&format!(
            "Sigma scan: skipping oversized EVTX file {} ({} bytes, limit {} bytes - raise with --sigma-max-size)",
            path.display(),
            metadata.len(),
            scan_config.sigma_max_artifact_size
        ));
        return (0, 0, 0, 0, 0);
    }

    let (md5_value, sha1_value, sha256_value, file_size) = match hash_file_streaming(path) {
        Ok(h) => h,
        Err(e) => {
            logger.debug(&format!("Sigma scan: failed to read {}: {}", path.display(), e));
            return (0, 0, 0, 0, 0);
        }
    };

    logger.debug(&format!("Sigma scan: parsing EVTX {} ({} bytes)", display_path, file_size));

    // `from_path` reads through a File handle. `from_buffer` would take an
    // owned Vec of the whole artifact, which is what pushed a 38-thread run
    // to 118 GB of anon-rss (see `hash_file_streaming`).
    //
    // One parser thread, not `scan_config.threads`: artifacts are already
    // walked with `par_bridge`, so every one of the pool's threads was
    // handing its file to a further N-thread parser. That nesting bought no
    // throughput - the pool was saturated either way - and multiplied the
    // decompression buffers held at once.
    let settings = ParserSettings::default().num_threads(1);
    let mut parser = match EvtxParser::from_path(path) {
        Ok(p) => p.with_configuration(settings),
        Err(e) => {
            logger.warning(&format!("Sigma scan: failed to open EVTX file {}: {:?}", path.display(), e));
            return (1, 0, 0, 0, 0);
        }
    };

    let budget = RuleEmissionBudget::new(scan_config.sigma_max_events_per_rule);
    let ctx = EvtxFileContext {
        display_path: &display_path,
        file_size,
        md5: &md5_value,
        sha1: &sha1_value,
        sha256: &sha256_value,
        budget: &budget,
    };

    let mut result: ModuleResult = (1, 0, 0, 0, 0);
    let mut batch: Vec<SerializedEvtxRecord<serde_json::Value>> = Vec::with_capacity(EVTX_BATCH_SIZE);
    let mut bad_records = 0usize;
    let mut total_records = 0usize;

    for record in parser.records_json_value() {
        if let Some(state) = scan_state {
            if state.should_stop() {
                break;
            }
            state.wait_for_resume();
        }
        match record {
            Ok(r) => {
                total_records += 1;
                batch.push(r);
            }
            Err(e) => {
                bad_records += 1;
                if bad_records <= 3 {
                    logger.debug(&format!("Sigma scan: bad EVTX record in {}: {:?}", path.display(), e));
                }
            }
        }
        if batch.len() >= EVTX_BATCH_SIZE {
            flush_evtx_batch(&mut batch, &ctx, sigma_rules, scan_config, logger, scan_state, &mut result);
        }
    }
    flush_evtx_batch(&mut batch, &ctx, sigma_rules, scan_config, logger, scan_state, &mut result);
    report_suppressed(&budget, &display_path, logger);

    if bad_records > 0 {
        logger.debug(&format!(
            "Sigma scan: {} unreadable record(s) skipped in {} ({} records parsed)",
            bad_records, display_path, total_records
        ));
    }
    logger.debug(&format!(
        "Sigma scan: finished {} - {} records, {} matched",
        display_path, total_records, result.1
    ));

    result
}

fn file_mtime_year(path: &Path) -> i32 {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .map(|t| {
            let dt: DateTime<Utc> = t.into();
            dt.year()
        })
        .unwrap_or_else(|| Utc::now().year())
}

fn syslog_timestamp_to_rfc3339(raw: &str, year: i32) -> Option<String> {
    let with_year = format!("{} {}", year, raw);
    NaiveDateTime::parse_from_str(&with_year, "%Y %b %e %H:%M:%S").ok().map(|dt| dt.and_utc().to_rfc3339())
}

fn auditd_epoch_to_rfc3339(epoch_str: &str) -> Option<String> {
    let epoch: f64 = epoch_str.parse().ok()?;
    let secs = epoch.trunc() as i64;
    let nanos = ((epoch.fract()) * 1_000_000_000.0).round() as u32;
    DateTime::<Utc>::from_timestamp(secs, nanos).map(|dt| dt.to_rfc3339())
}

#[allow(clippy::too_many_arguments)]
fn process_linux_log_file(
    path: &Path,
    format: LinuxLogFormat,
    profile: &ArtifactProfile,
    sigma_rules: &SigmaRuleIndex,
    scan_config: &ScanConfig,
    logger: &UnifiedLogger,
    scan_state: Option<&Arc<ScanState>>,
) -> ModuleResult {
    let display_path = profile.rewrite_path(path);

    let metadata = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            logger.debug(&format!("Sigma scan: failed to stat {}: {}", path.display(), e));
            return (0, 0, 0, 0, 0);
        }
    };
    if metadata.len() > scan_config.sigma_max_artifact_size as u64 {
        logger.warning(&format!(
            "Sigma scan: skipping oversized log file {} ({} bytes, limit {} bytes - raise with --sigma-max-size)",
            path.display(),
            metadata.len(),
            scan_config.sigma_max_artifact_size
        ));
        return (0, 0, 0, 0, 0);
    }

    let (md5_value, sha1_value, sha256_value, file_size) = match hash_file_streaming(path) {
        Ok(h) => h,
        Err(e) => {
            logger.debug(&format!("Sigma scan: failed to read {}: {}", path.display(), e));
            return (0, 0, 0, 0, 0);
        }
    };
    let mtime_year = file_mtime_year(path);

    // Read line by line rather than slurping the file: a rotated-but-not-
    // compressed auth.log can be gigabytes, and this runs on every thread at
    // once (see `hash_file_streaming`).
    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            logger.debug(&format!("Sigma scan: failed to read {}: {}", path.display(), e));
            return (0, 0, 0, 0, 0);
        }
    };
    let reader = BufReader::new(file);

    let budget = RuleEmissionBudget::new(scan_config.sigma_max_events_per_rule);
    let mut result: ModuleResult = (1, 0, 0, 0, 0);

    // Lossy, like the previous `String::from_utf8_lossy` over the whole file:
    // a log with one mis-encoded byte should not lose every line after it.
    for line in reader.split(b'\n').filter_map(Result::ok).map(|raw| {
        let text = String::from_utf8_lossy(&raw).into_owned();
        text.strip_suffix('\r').map(str::to_string).unwrap_or(text)
    }) {
        let line = line.as_str();
        let (event_value, timestamp) = match format {
            LinuxLogFormat::Syslog => {
                let Some(v) = parse_syslog_line(line) else { continue };
                let ts = v.get("timestamp").and_then(|t| t.as_str()).and_then(|t| syslog_timestamp_to_rfc3339(t, mtime_year));
                (v, ts)
            }
            LinuxLogFormat::Auditd => {
                let Some(v) = parse_auditd_line(line) else { continue };
                let ts = v.get("audit_epoch").and_then(|t| t.as_str()).and_then(auditd_epoch_to_rfc3339);
                (v, ts)
            }
        };

        // Syslog lines name the originating host; auditd lines do not.
        let source_host = event_value
            .get("hostname")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());

        let Ok(event) = Event::try_from(event_value) else { continue };
        if let Some(state) = scan_state {
            state.add_sigma_events(1);
        }

        let mut emit = false;
        let sub_matches: Vec<GenMatch> = sigma_rules
            .linux_candidates()
            .filter(|loaded| loaded.rule.is_match(&event))
            .map(|loaded| {
                emit |= budget.admit(loaded);
                let mut m = build_sigma_match(loaded, &event, None, None, None);
                if let Some(strings) = m.matched_strings.as_mut() {
                    strings.push(format!("line: {}", truncate_chars(line, MAX_FIELD_VALUE_LEN)));
                }
                m
            })
            .collect();

        if sub_matches.is_empty() {
            continue;
        }

        if let Some(level) = emit_event_finding(
            &display_path,
            "Linux Log Line",
            file_size,
            &md5_value,
            &sha1_value,
            &sha256_value,
            EventOrigin { host: source_host, timestamp },
            &sub_matches,
            emit,
            scan_config,
            logger,
            scan_state,
        ) {
            bump_counts(&mut result, level);
        }
    }

    report_suppressed(&budget, &display_path, logger);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::helpers::sigma_rules::{build_rule_index, parse_rule_file, SigmaDocument};

    /// An index holding one rule per (id, title), routed through the real
    /// parser so the budget is keyed off the same `id` the scan path uses.
    /// The index owns the rules, so tests keep it alive and borrow from it.
    fn rule_index(rules: &[(&str, &str)]) -> SigmaRuleIndex {
        let parsed = rules
            .iter()
            .map(|(id, title)| {
                let yaml = format!(
                    "title: {}\nid: {}\nlogsource:\n    product: windows\ndetection:\n    selection:\n        f: v\n    condition: selection\nlevel: high\n",
                    title, id
                );
                parse_rule_file(&yaml)
                    .into_iter()
                    .find_map(|d| match d {
                        SigmaDocument::Rule(r) => Some(r),
                        _ => None,
                    })
                    .expect("test rule should parse")
            })
            .collect();
        build_rule_index(parsed)
    }

    /// The loaded rule titled `title` in `index`.
    fn rule<'a>(index: &'a SigmaRuleIndex, title: &str) -> &'a LoadedSigmaRule {
        index
            .windows_candidates(None, None)
            .find(|loaded| loaded.rule.title == title)
            .expect("test rule should be a windows candidate")
    }

    /// The streaming hashes must equal what the previous whole-file
    /// `fs::read` + hash produced, including across a chunk boundary and for
    /// an empty file - these hashes end up in findings analysts pivot on.
    #[test]
    fn test_hash_file_streaming_matches_whole_file_hashing() {
        use std::io::Write;

        for size in [0usize, 1, HASH_CHUNK_SIZE - 1, HASH_CHUNK_SIZE, HASH_CHUNK_SIZE + 12345] {
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();

            let path = std::env::temp_dir().join(format!("raijin_hash_test_{}_{}", std::process::id(), size));
            let mut f = fs::File::create(&path).expect("temp file should be creatable");
            f.write_all(&data).expect("temp file should be writable");
            drop(f);

            let (md5_value, sha1_value, sha256_value, total) =
                hash_file_streaming(&path).expect("hashing should succeed");
            let _ = fs::remove_file(&path);

            assert_eq!(total, size as u64, "size mismatch at {} bytes", size);
            assert_eq!(md5_value, format!("{:x}", md5::compute(&data)), "md5 mismatch at {} bytes", size);
            assert_eq!(
                sha1_value,
                hex::encode(Sha1::new().chain_update(&data).finalize()),
                "sha1 mismatch at {} bytes",
                size
            );
            assert_eq!(
                sha256_value,
                hex::encode(Sha256::new().chain_update(&data).finalize()),
                "sha256 mismatch at {} bytes",
                size
            );
        }
    }

    #[test]
    fn test_budget_admits_up_to_cap_then_suppresses() {
        let index = rule_index(&[("00000000-0000-0000-0000-0000000000aa", "Noisy")]);
        let rule = rule(&index, "Noisy");
        let budget = RuleEmissionBudget::new(3);

        let admitted: Vec<bool> = (0..5).map(|_| budget.admit(rule)).collect();
        assert_eq!(admitted, vec![true, true, true, false, false]);

        let over = budget.drain_suppressed();
        assert_eq!(over, vec![("Noisy".to_string(), 3, 2)]);
    }

    #[test]
    fn test_budget_zero_means_unlimited() {
        let index = rule_index(&[("00000000-0000-0000-0000-0000000000bb", "Unbounded")]);
        let rule = rule(&index, "Unbounded");
        let budget = RuleEmissionBudget::new(0);

        assert!((0..1000).all(|_| budget.admit(rule)));
        // Nothing was suppressed, so nothing is reported at end of artifact.
        assert!(budget.drain_suppressed().is_empty());
    }

    #[test]
    fn test_budget_is_tracked_per_rule() {
        let index = rule_index(&[
            ("00000000-0000-0000-0000-0000000000cc", "Noisy"),
            ("00000000-0000-0000-0000-0000000000dd", "Quiet"),
        ]);
        let noisy = rule(&index, "Noisy");
        let quiet = rule(&index, "Quiet");
        let budget = RuleEmissionBudget::new(2);

        for _ in 0..4 {
            budget.admit(noisy);
        }
        // `quiet` has its own allowance and is untouched by `noisy` blowing past its own.
        assert!(budget.admit(quiet));
        assert!(budget.admit(quiet));
        assert!(!budget.admit(quiet));

        let over = budget.drain_suppressed();
        assert_eq!(over.len(), 2);
        // Noisiest rule first: 2 suppressed vs 1.
        assert_eq!(over[0], ("Noisy".to_string(), 2, 2));
        assert_eq!(over[1], ("Quiet".to_string(), 2, 1));
    }

    #[test]
    fn test_budget_reports_nothing_when_under_cap() {
        let index = rule_index(&[("00000000-0000-0000-0000-0000000000ee", "Rare")]);
        let rule = rule(&index, "Rare");
        let budget = RuleEmissionBudget::new(100);

        for _ in 0..7 {
            assert!(budget.admit(rule));
        }
        assert!(budget.drain_suppressed().is_empty());
    }

    #[test]
    fn test_is_evtx_file() {
        assert!(is_evtx_file(Path::new("Security.evtx")));
        assert!(is_evtx_file(Path::new("Security.EVTX")));
        assert!(!is_evtx_file(Path::new("Security.log")));
        assert!(!is_evtx_file(Path::new("Security")));
    }

    #[test]
    fn test_classify_linux_log_exact_names() {
        assert!(matches!(classify_linux_log("auth.log"), Some(LinuxLogFormat::Syslog)));
        assert!(matches!(classify_linux_log("audit.log"), Some(LinuxLogFormat::Auditd)));
        assert!(matches!(classify_linux_log("syslog"), Some(LinuxLogFormat::Syslog)));
    }

    #[test]
    fn test_classify_linux_log_rotation_suffix() {
        assert!(matches!(classify_linux_log("auth.log.1"), Some(LinuxLogFormat::Syslog)));
        assert!(matches!(classify_linux_log("audit.log.2"), Some(LinuxLogFormat::Auditd)));
    }

    #[test]
    fn test_classify_linux_log_no_match() {
        assert!(classify_linux_log("random.txt").is_none());
        assert!(classify_linux_log("auth.log.gz").is_none());
    }

    #[test]
    fn test_syslog_timestamp_to_rfc3339() {
        let ts = syslog_timestamp_to_rfc3339("Jan 15 10:23:45", 2026).unwrap();
        assert!(ts.starts_with("2026-01-15T10:23:45"));
    }

    #[test]
    fn test_auditd_epoch_to_rfc3339() {
        let ts = auditd_epoch_to_rfc3339("1700000000.500").unwrap();
        assert!(ts.starts_with("2023-11-14"));
    }
}
