//! HTML Report Generation from JSONL files for raijin-util
//! 
//! Provides functionality to generate HTML reports from single or multiple JSONL files,
//! reusing the existing HTML rendering pipeline from raijin.

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::collections::BTreeMap;
use chrono::{DateTime, Utc};
use regex::Regex;

// The scanner's own report types and parser, so a JSONL is read by the
// same code that wrote it - the copies this file used to carry drifted
// (they never learned about matched strings, or a finding's own host).
pub use raijin::helpers::html_report::{parse_jsonl, LogEvent, ReportData, RenderOptions};
use raijin::ScanConfig;

/// Metadata extracted from a JSONL file
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SourceMetadata {
    pub hostname: String,
    pub scan_start: Option<DateTime<Utc>>,
    pub scan_end: Option<DateTime<Utc>>,
    pub version: Option<String>,
    pub filename: String,
    pub os_info: Option<String>,
    pub scan_duration_seconds: Option<f64>,
}

/// Combined report data from multiple JSONL files
pub struct CombinedReportData {
    pub sources: Vec<SourceMetadata>,
    #[allow(dead_code)] // Kept for backward compatibility
    pub findings_by_source: BTreeMap<String, Vec<LogEvent>>,
    pub all_findings: Vec<LogEvent>,
    pub findings_by_hostname: BTreeMap<String, Vec<LogEvent>>,
    pub total_findings: usize,
    #[allow(dead_code)] // Kept for backward compatibility
    pub total_by_severity: BTreeMap<String, usize>,
    pub os_statistics: BTreeMap<String, usize>,
    pub version_statistics: BTreeMap<String, usize>,
    pub error_count_by_host: BTreeMap<String, usize>,
}

/// Extract metadata from a parsed ReportData
pub fn extract_metadata(data: &ReportData, filename: &str) -> SourceMetadata {
    let hostname = data.scan_start.as_ref()
        .map(|e| e.hostname.clone())
        .unwrap_or_else(|| {
            // Try to extract from filename (raijin_hostname_date.jsonl)
            Path::new(filename)
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s: &str| s.strip_prefix("raijin_"))
                .and_then(|s: &str| s.split('_').next())
                .map(|s: &str| s.to_string())
                .unwrap_or_else(|| "Unknown".to_string())
        });
    
    let scan_start = data.scan_start.as_ref().map(|e| e.timestamp);
    let scan_end = data.scan_end.as_ref().map(|e| e.timestamp);
    
    // Calculate scan duration
    let scan_duration_seconds = scan_start.and_then(|start| {
        scan_end.map(|end| {
            let duration = end.signed_duration_since(start);
            duration.num_seconds() as f64 + duration.num_milliseconds() as f64 / 1000.0
        })
    });
    
    // Extract version from scan_start message
    let version = data.scan_start.as_ref()
        .and_then(|e| {
            let re = Regex::new(r"VERSION:\s*([^\s]+)").ok()?;
            re.captures(&e.message)
                .and_then(|caps| caps.get(1))
                .map(|m| m.as_str().to_string())
        });
    
    // Extract OS information from info events
    let os_info = data.info_events.iter()
        .find(|e| e.message.contains("Operating system"))
        .map(|e| e.message.clone());
    
    SourceMetadata {
        hostname,
        scan_start,
        scan_end,
        version,
        filename: filename.to_string(),
        os_info,
        scan_duration_seconds,
    }
}

/// Synthesize a ScanConfig from extracted metadata and info events
pub fn synthesize_scan_config(data: &ReportData) -> ScanConfig {
    // Default values
    let mut alert_threshold = 80;
    let mut warning_threshold = 60;
    let mut notice_threshold = 40;
    let mut max_file_size = 64_000_000;
    let mut threads = 0;
    let mut cpu_limit = 100;
    let mut yara_rules_count = 0;
    let mut ioc_count = 0;
    
    // Try to extract from info events
    for event in &data.info_events {
        // Extract thresholds from context
        if let Some(threshold_str) = event.context.get("ALERT_THRESHOLD") {
            if let Ok(val) = threshold_str.parse::<i16>() {
                alert_threshold = val;
            }
        }
        if let Some(threshold_str) = event.context.get("WARNING_THRESHOLD") {
            if let Ok(val) = threshold_str.parse::<i16>() {
                warning_threshold = val;
            }
        }
        if let Some(threshold_str) = event.context.get("NOTICE_THRESHOLD") {
            if let Ok(val) = threshold_str.parse::<i16>() {
                notice_threshold = val;
            }
        }
        
        // Extract max_file_size from "Scan limits" message
        if event.message.contains("MAX_FILE_SIZE") {
            if let Some(size_str) = event.context.get("MAX_FILE_SIZE") {
                // Format: "64000000 bytes (64.0 MB)"
                if let Some(bytes_part) = size_str.split_whitespace().next() {
                    if let Ok(val) = bytes_part.parse::<usize>() {
                        max_file_size = val;
                    }
                }
            }
        }
        
        // Extract thread count
        if event.message.contains("Thread pool") || event.message.contains("THREADS:") {
            let re = Regex::new(r"THREADS:\s*(\d+)").ok();
            if let Some(re) = re {
                if let Some(caps) = re.captures(&event.message) {
                    if let Some(thread_str) = caps.get(1) {
                        if let Ok(val) = thread_str.as_str().parse::<usize>() {
                            threads = val;
                        }
                    }
                }
            }
        }
        
        // Extract CPU limit
        if event.message.contains("CPU") && event.message.contains("%") {
            let re = Regex::new(r"CPU[:\s]+(\d+)%").ok();
            if let Some(re) = re {
                if let Some(caps) = re.captures(&event.message) {
                    if let Some(cpu_str) = caps.get(1) {
                        if let Ok(val) = cpu_str.as_str().parse::<u8>() {
                            cpu_limit = val;
                        }
                    }
                }
            }
        }
        
        // Extract YARA rules count
        if event.message.contains("YARA rules") || event.message.contains("rules loaded") {
            let re = Regex::new(r"(\d+)\s+rules").ok();
            if let Some(re) = re {
                if let Some(caps) = re.captures(&event.message) {
                    if let Some(count_str) = caps.get(1) {
                        if let Ok(val) = count_str.as_str().parse::<usize>() {
                            yara_rules_count = val;
                        }
                    }
                }
            }
        }
        
        // Extract IOC count
        if event.message.contains("IOC") || event.message.contains("indicators loaded") {
            let re = Regex::new(r"(\d+)\s+indicators").ok();
            if let Some(re) = re {
                if let Some(caps) = re.captures(&event.message) {
                    if let Some(count_str) = caps.get(1) {
                        if let Ok(val) = count_str.as_str().parse::<usize>() {
                            ioc_count = val;
                        }
                    }
                }
            }
        }
    }
    
    // What the header can show is what the JSONL recorded; the rest are the
    // scanner's defaults, and the report does not display them.
    ScanConfig {
        max_file_size,
        sigma_max_artifact_size: 2_000_000_000,
        sigma_max_events_per_rule: 100,
        show_access_errors: false,
        scan_all_types: false,
        scan_hard_drives: false,
        scan_all_drives: false,
        scan_archives: true,
        is_elevated: false,
        alert_threshold,
        warning_threshold,
        notice_threshold,
        max_reasons: 2,
        yara_timeout: std::time::Duration::from_secs(10),
        threads,
        cpu_limit,
        exclusion_count: 0,
        yara_rules_count,
        ioc_count,
        sigma_rules_count: 0,
        program_dir: None,
    }
}

/// Parse multiple JSONL files and combine them
pub fn parse_multiple_jsonl_files(paths: &[String]) -> Result<CombinedReportData, String> {
    let mut sources = Vec::new();
    let mut findings_by_source = BTreeMap::new();
    let mut all_findings = Vec::new();
    let mut findings_by_hostname: BTreeMap<String, Vec<LogEvent>> = BTreeMap::new();
    let mut total_by_severity: BTreeMap<String, usize> = BTreeMap::new();
    let mut os_statistics: BTreeMap<String, usize> = BTreeMap::new();
    let mut version_statistics: BTreeMap<String, usize> = BTreeMap::new();
    let mut error_count_by_host: BTreeMap<String, usize> = BTreeMap::new();
    let mut total_findings = 0;
    
    for path in paths {
        let report_data = parse_jsonl(path)?;
        let metadata = extract_metadata(&report_data, path);
        
        // Count findings by severity
        for finding in &report_data.findings {
            let severity = finding.level.to_uppercase();
            *total_by_severity.entry(severity.clone()).or_insert(0) += 1;
            
            // Count errors
            if severity == "ERROR" {
                *error_count_by_host.entry(metadata.hostname.clone()).or_insert(0) += 1;
            }
        }
        
        total_findings += report_data.findings.len();
        
        // Store findings by source (use filename as key if hostname conflicts)
        let key = format!("{} ({})", metadata.hostname, metadata.filename);
        findings_by_source.insert(key.clone(), report_data.findings.clone());
        
        // Store findings by hostname for filtering
        findings_by_hostname
            .entry(metadata.hostname.clone())
            .or_insert_with(Vec::new)
            .extend(report_data.findings.clone());
        
        // Add all findings to merged list (will sort later)
        all_findings.extend(report_data.findings);
        
        // Update OS statistics
        if let Some(ref os) = metadata.os_info {
            // Extract OS name from message (e.g., "Operating system information OS: linux ARCH: x86_64")
            let os_name = if let Some(os_part) = os.split("OS:").nth(1) {
                os_part.split_whitespace().next().unwrap_or("unknown").to_string()
            } else {
                "unknown".to_string()
            };
            *os_statistics.entry(os_name).or_insert(0) += 1;
        }
        
        // Update version statistics
        if let Some(ref ver) = metadata.version {
            *version_statistics.entry(ver.clone()).or_insert(0) += 1;
        }
        
        // Update metadata with the key used
        let mut meta = metadata;
        meta.filename = key;
        sources.push(meta);
    }
    
    // Sort all findings by score descending
    all_findings.sort_by(|a, b| {
        let score_a = a.score.unwrap_or(0.0);
        let score_b = b.score.unwrap_or(0.0);
        score_b.partial_cmp(&score_a).unwrap_or(std::cmp::Ordering::Equal)
    });
    
    Ok(CombinedReportData {
        sources,
        findings_by_source,
        all_findings,
        findings_by_hostname,
        total_findings,
        total_by_severity,
        os_statistics,
        version_statistics,
        error_count_by_host,
    })
}

/// Extract version from scan_start message or use binary version
pub fn extract_version(data: &ReportData, fallback_version: &str) -> String {
    data.scan_start.as_ref()
        .and_then(|e| {
            let re = Regex::new(r"VERSION:\s*([^\s]+)").ok()?;
            re.captures(&e.message)
                .and_then(|caps| caps.get(1))
                .map(|m| m.as_str().to_string())
        })
        .unwrap_or_else(|| fallback_version.to_string())
}

/// Generate HTML report from a single JSONL file
pub fn generate_single_report(
    input_path: &str,
    output_path: Option<&str>,
    title_override: Option<&str>,
    host_override: Option<&str>,
) -> Result<String, String> {
    let report_data = parse_jsonl(input_path)?;
    let version = extract_version(&report_data, RAIJIN_UTIL_VERSION);
    let scan_config = synthesize_scan_config(&report_data);

    // Default: same as input but with .html extension
    let html_path = output_path.unwrap_or_else(|| {
        if input_path.ends_with(".jsonl") {
            &input_path[..input_path.len() - 6]
        } else {
            input_path
        }
    });
    let html_path = if html_path.ends_with(".html") {
        html_path.to_string()
    } else {
        format!("{}.html", html_path)
    };

    // The scanner's own renderer: a report regenerated from a JSONL is then
    // the report the scan would have written, matched strings, rule filters
    // and artifact host included, rather than the trimmed copy this used to
    // produce.
    let options = RenderOptions {
        title: title_override.map(str::to_string),
        hostname: host_override.map(str::to_string),
    };
    raijin::helpers::html_report::write_report(&report_data, &scan_config, &version, input_path, &html_path, &options)
}

/// Render combined HTML report from multiple sources
pub fn render_combined_html(
    data: &CombinedReportData,
    _version: &str,
    output_path: &str,
) -> Result<String, String> {
    let mut html = String::new();
    
    // Calculate scan duration range
    let scan_durations: Vec<f64> = data.sources.iter()
        .filter_map(|s| s.scan_duration_seconds)
        .collect();
    let min_duration = scan_durations.iter().fold(f64::INFINITY, |a, &b| a.min(b));
    let max_duration = scan_durations.iter().fold(0.0f64, |a, &b| a.max(b));
    let avg_duration = if !scan_durations.is_empty() {
        scan_durations.iter().sum::<f64>() / scan_durations.len() as f64
    } else {
        0.0
    };
    
    // Build OS distribution string
    let os_distribution: Vec<String> = data.os_statistics.iter()
        .map(|(os, count)| format!("{}x {}", count, os))
        .collect();
    let os_dist_str = if os_distribution.is_empty() {
        "Unknown".to_string()
    } else {
        os_distribution.join(", ")
    };
    
    // Build version distribution string
    let version_distribution: Vec<String> = data.version_statistics.iter()
        .map(|(ver, count)| format!("{}x v{}", count, ver))
        .collect();
    let version_dist_str = if version_distribution.is_empty() {
        "Unknown".to_string()
    } else {
        version_distribution.join(", ")
    };
    
    // Build statistics table data
    let mut stats_rows = Vec::new();
    for source in &data.sources {
        let findings = data.findings_by_hostname.get(&source.hostname).map(|v| v.as_slice()).unwrap_or(&[]);
        let alerts = findings.iter().filter(|f| f.level.to_uppercase() == "ALERT").count();
        let warnings = findings.iter().filter(|f| f.level.to_uppercase() == "WARNING").count();
        let notices = findings.iter().filter(|f| f.level.to_uppercase() == "NOTICE").count();
        let errors = data.error_count_by_host.get(&source.hostname).copied().unwrap_or(0);
        
        stats_rows.push((source.hostname.clone(), alerts, warnings, notices, errors));
    }
    
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("    <meta charset=\"UTF-8\">\n");
    html.push_str("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    html.push_str("    <title>Raijin Combined Scan Report</title>\n");
    html.push_str("    <style>\n");
    html.push_str(r##"        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #1f2428;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent: #3fb950;
            --alert-bg: #f85149;
            --warning-bg: #d29922;
            --notice-bg: #3fb950;
            --error-bg: #f85149;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.5;
            padding: 20px;
        }
        .header {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 20px;
        }
        .header h1 { margin-bottom: 10px; }
        .summary-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
        }
        .stat-card h3 {
            font-size: 12px;
            text-transform: uppercase;
            color: var(--text-secondary);
            margin-bottom: 8px;
        }
        .stat-card p {
            font-size: 14px;
            color: var(--text-primary);
        }
        .stats-table-container {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 20px;
        }
        .stats-table-container h2 { margin-bottom: 16px; }
        .filter-state {
            margin-bottom: 12px;
            padding: 8px 12px;
            background: var(--bg-tertiary);
            border-radius: 4px;
            font-size: 13px;
        }
        .filter-state span { color: var(--accent); font-weight: 600; }
        .clear-filters-btn {
            margin-left: 12px;
            padding: 4px 12px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            color: var(--text-primary);
            cursor: pointer;
            font-size: 12px;
        }
        .clear-filters-btn:hover { background: var(--border-color); }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        th {
            background: var(--bg-tertiary);
            font-weight: 600;
            cursor: pointer;
            user-select: none;
        }
        th:hover { background: var(--border-color); }
        .clickable-cell {
            cursor: pointer;
            transition: background 0.2s;
        }
        .clickable-cell:hover {
            background: var(--bg-tertiary);
        }
        .active-filter {
            background: var(--accent) !important;
            color: #fff !important;
        }
        .findings-section {
            margin-top: 20px;
        }
        .findings-section h2 { margin-bottom: 16px; }
        .finding-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 16px;
            transition: opacity 0.2s;
        }
        .finding-card.hidden {
            display: none;
        }
        .finding-card.alert { border-left: 4px solid var(--alert-bg); }
        .finding-card.warning { border-left: 4px solid var(--warning-bg); }
        .finding-card.notice { border-left: 4px solid var(--notice-bg); }
        .finding-card.error { border-left: 4px solid var(--error-bg); }
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }
        .finding-title {
            font-size: 16px;
            font-weight: 600;
        }
        .finding-score {
            font-size: 18px;
            font-weight: 700;
            padding: 4px 12px;
            background: var(--bg-tertiary);
            border-radius: 4px;
        }
        .hostname-badge {
            display: inline-block;
            padding: 2px 8px;
            background: var(--bg-tertiary);
            border-radius: 4px;
            font-size: 11px;
            color: var(--text-secondary);
            margin-left: 8px;
        }
        .finding-path {
            font-family: monospace;
            font-size: 13px;
            color: var(--text-secondary);
            margin-bottom: 12px;
            word-break: break-all;
        }
        .detail-item {
            margin: 8px 0;
            font-size: 13px;
        }
        .detail-label {
            color: var(--text-secondary);
            font-weight: 600;
        }
        .detail-value {
            color: var(--text-primary);
        }
        .reasons-section {
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid var(--border-color);
        }
        .reason-item {
            background: var(--bg-tertiary);
            padding: 8px 12px;
            border-radius: 4px;
            margin: 8px 0;
        }
        .no-findings {
            text-align: center;
            padding: 40px;
            color: var(--text-secondary);
        }
        .filter-panel {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        .filter-panel-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px 16px;
            background: var(--bg-tertiary);
            cursor: pointer;
            user-select: none;
        }
        .filter-panel-header h3 {
            font-size: 13px;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin: 0;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .filter-count {
            background: var(--accent);
            color: #fff;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
        }
        .filter-panel-actions {
            display: flex;
            gap: 8px;
        }
        .filter-panel-btn {
            padding: 4px 10px;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            cursor: pointer;
            font-size: 12px;
            transition: all 0.2s;
        }
        .filter-panel-btn:hover {
            color: var(--accent);
            border-color: var(--accent);
        }
        .filter-panel-btn.danger:hover {
            color: var(--alert-bg);
            border-color: var(--alert-bg);
        }
        .filter-panel-content {
            padding: 16px;
            display: none;
        }
        .filter-panel.open .filter-panel-content {
            display: block;
        }
        .filter-list {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }
        .filter-chip {
            display: flex;
            align-items: center;
            gap: 6px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 4px 8px 4px 12px;
            font-size: 12px;
            font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
        }
        .filter-chip-text {
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .filter-chip-remove {
            width: 18px;
            height: 18px;
            border: none;
            background: var(--bg-primary);
            color: var(--text-secondary);
            border-radius: 50%;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
        }
        .filter-chip-remove:hover {
            background: var(--alert-bg);
            color: #fff;
        }
        .filter-empty {
            color: var(--text-secondary);
            font-size: 13px;
            font-style: italic;
        }
        .filter-icon-hint {
            display: inline-block;
            color: #ff6b6b;
            font-style: normal;
            font-weight: bold;
        }
        .hidden-input {
            display: none;
        }
        .context-menu {
            position: fixed;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 4px;
            z-index: 10000;
            display: none;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }
        .context-menu.visible {
            display: block;
        }
        .context-menu-item {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 12px;
            cursor: pointer;
            font-size: 13px;
            border-radius: 4px;
        }
        .context-menu-item:hover {
            background: var(--bg-tertiary);
        }
        .context-menu-item .icon {
            font-size: 14px;
        }
        .filter-btn-inline {
            display: inline-block;
            margin-left: 8px;
            padding: 2px 6px;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            color: var(--text-secondary);
            cursor: pointer;
            font-size: 11px;
            transition: all 0.2s;
        }
        .filter-btn-inline:hover {
            background: var(--alert-bg);
            color: #fff;
            border-color: var(--alert-bg);
        }
    "##);
    html.push_str("    </style>\n");
    html.push_str("</head>\n<body>\n");
    
    // Header
    html.push_str("    <div class=\"header\">\n");
    html.push_str("        <h1>Raijin Combined Scan Report</h1>\n");
    html.push_str(&format!("        <p>Generated: {} | Total Hosts: {} | Total Findings: {}</p>\n",
        Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
        data.sources.len(),
        data.total_findings
    ));
    html.push_str("    </div>\n");
    
    // Summary statistics
    html.push_str("    <div class=\"summary-stats\">\n");
    html.push_str("        <div class=\"stat-card\">\n");
    html.push_str("            <h3>Operating Systems</h3>\n");
    html.push_str(&format!("            <p>{}</p>\n", html_escape(&os_dist_str)));
    html.push_str("        </div>\n");
    html.push_str("        <div class=\"stat-card\">\n");
    html.push_str("            <h3>Raijin Versions</h3>\n");
    html.push_str(&format!("            <p>{}</p>\n", html_escape(&version_dist_str)));
    html.push_str("        </div>\n");
    html.push_str("        <div class=\"stat-card\">\n");
    html.push_str("            <h3>Scan Duration</h3>\n");
    if min_duration != f64::INFINITY {
        html.push_str(&format!("            <p>Range: {:.1}s - {:.1}s<br>Avg: {:.1}s</p>\n",
            min_duration, max_duration, avg_duration));
    } else {
        html.push_str("            <p>N/A</p>\n");
    }
    html.push_str("        </div>\n");
    html.push_str("    </div>\n");
    
    // Filter Panel
    html.push_str("    <div class=\"filter-panel\" id=\"filterPanel\">\n");
    html.push_str("        <div class=\"filter-panel-header\" onclick=\"toggleFilterPanel()\">\n");
    html.push_str("            <h3>\n");
    html.push_str("                <span>🔍 Active Filters</span>\n");
    html.push_str("                <span class=\"filter-count\" id=\"filterCount\">0</span>\n");
    html.push_str("            </h3>\n");
    html.push_str("            <div class=\"filter-panel-actions\">\n");
    html.push_str("                <button class=\"filter-panel-btn\" onclick=\"event.stopPropagation(); exportFilters()\">Export</button>\n");
    html.push_str("                <button class=\"filter-panel-btn\" onclick=\"event.stopPropagation(); document.getElementById('importInput').click()\">Import</button>\n");
    html.push_str("                <button class=\"filter-panel-btn danger\" onclick=\"event.stopPropagation(); clearAllFilters()\">Clear All</button>\n");
    html.push_str("            </div>\n");
    html.push_str("        </div>\n");
    html.push_str("        <div class=\"filter-panel-content\">\n");
    html.push_str("            <div class=\"filter-list\" id=\"filterList\">\n");
    html.push_str("                <span class=\"filter-empty\">Click the <span class=\"filter-icon-hint\">✖</span> next to any field value or select text and use the right-click context menu to add filters.</span>\n");
    html.push_str("            </div>\n");
    html.push_str("        </div>\n");
    html.push_str("    </div>\n");
    html.push_str("    <input type=\"file\" id=\"importInput\" class=\"hidden-input\" accept=\".json\" onchange=\"importFilters(event)\">\n");
    
    // Interactive statistics table
    html.push_str("    <div class=\"stats-table-container\">\n");
    html.push_str("        <h2>Host Statistics</h2>\n");
    html.push_str("        <div class=\"filter-state\" id=\"filterState\">\n");
    html.push_str("            <span>Showing:</span> All findings\n");
    html.push_str("            <button class=\"clear-filters-btn\" onclick=\"clearHostnameSeverityFilters()\" style=\"display:none;\" id=\"clearFiltersBtn\">Clear Host/Severity Filters</button>\n");
    html.push_str("        </div>\n");
    html.push_str("        <table id=\"statsTable\">\n");
    html.push_str("            <thead>\n");
    html.push_str("                <tr>\n");
    html.push_str("                    <th onclick=\"filterBySeverity('')\">Hostname</th>\n");
    html.push_str("                    <th class=\"clickable-cell\" onclick=\"filterBySeverity('ALERT')\" data-severity=\"ALERT\">Alerts</th>\n");
    html.push_str("                    <th class=\"clickable-cell\" onclick=\"filterBySeverity('WARNING')\" data-severity=\"WARNING\">Warnings</th>\n");
    html.push_str("                    <th class=\"clickable-cell\" onclick=\"filterBySeverity('NOTICE')\" data-severity=\"NOTICE\">Notices</th>\n");
    html.push_str("                    <th class=\"clickable-cell\" onclick=\"filterBySeverity('ERROR')\" data-severity=\"ERROR\">Errors</th>\n");
    html.push_str("                </tr>\n");
    html.push_str("            </thead>\n");
    html.push_str("            <tbody>\n");
    
    for (hostname, alerts, warnings, notices, errors) in &stats_rows {
        let hostname_escaped = html_escape(hostname);
        html.push_str(&format!(
            "                <tr>\n                    <td class=\"clickable-cell\" onclick=\"filterByHostname('{}')\" data-hostname=\"{}\">{}</td>\n                    <td class=\"clickable-cell\" onclick=\"filterByHostnameAndSeverity('{}', 'ALERT')\" data-hostname=\"{}\" data-severity=\"ALERT\">{}</td>\n                    <td class=\"clickable-cell\" onclick=\"filterByHostnameAndSeverity('{}', 'WARNING')\" data-hostname=\"{}\" data-severity=\"WARNING\">{}</td>\n                    <td class=\"clickable-cell\" onclick=\"filterByHostnameAndSeverity('{}', 'NOTICE')\" data-hostname=\"{}\" data-severity=\"NOTICE\">{}</td>\n                    <td class=\"clickable-cell\" onclick=\"filterByHostnameAndSeverity('{}', 'ERROR')\" data-hostname=\"{}\" data-severity=\"ERROR\">{}</td>\n                </tr>\n",
            hostname_escaped, hostname_escaped, hostname_escaped,
            hostname_escaped, hostname_escaped, alerts,
            hostname_escaped, hostname_escaped, warnings,
            hostname_escaped, hostname_escaped, notices,
            hostname_escaped, hostname_escaped, errors
        ));
    }
    
    html.push_str("            </tbody>\n");
    html.push_str("        </table>\n");
    html.push_str("    </div>\n");
    
    // Merged findings list
    html.push_str("    <div class=\"findings-section\">\n");
    html.push_str("        <h2>All Findings (Sorted by Score)</h2>\n");
    
    if data.all_findings.is_empty() {
        html.push_str("        <div class=\"no-findings\">\n");
        html.push_str("            <h3>✓ No Findings</h3>\n");
        html.push_str("            <p>The combined scan completed without detecting any threats above the configured thresholds.</p>\n");
        html.push_str("        </div>\n");
    } else {
        for finding in &data.all_findings {
            html.push_str(&render_finding_with_hostname(finding));
        }
    }
    
    html.push_str("    </div>\n");
    
    // Context Menu
    html.push_str("    <!-- Context Menu -->\n");
    html.push_str("    <div class=\"context-menu\" id=\"contextMenu\">\n");
    html.push_str("        <div class=\"context-menu-item\" onclick=\"filterOutSelection()\">\n");
    html.push_str("            <span class=\"icon\">✖</span>\n");
    html.push_str("            <span>Filter out</span>\n");
    html.push_str("        </div>\n");
    html.push_str("        <div class=\"context-menu-item\" onclick=\"searchOnGoogle()\">\n");
    html.push_str("            <span class=\"icon\">🔍</span>\n");
    html.push_str("            <span>Search on Google</span>\n");
    html.push_str("        </div>\n");
    html.push_str("    </div>\n");
    
    // JavaScript for filtering
    html.push_str("    <script>\n");
    html.push_str(r##"        // =====================================================
        // FILTER STATE MANAGEMENT (Exclusion Filters)
        // =====================================================
        const STORAGE_KEY = 'raijin_combined_filters_' + new Date().toISOString().slice(0, 10).replace(/-/g, '_');
        let filterList = [];
        let selectedText = '';
        
        // Pre-cached card data for fast filtering
        let cardCache = null;
        
        // Initialize card cache on first use
        function initCardCache() {
            if (cardCache) return;
            const cards = document.querySelectorAll('.finding-card');
            cardCache = Array.from(cards).map(card => ({
                element: card,
                hostname: card.dataset.hostname,
                severity: card.dataset.severity,
                text: card.textContent
            }));
        }
        
        // Load filters from localStorage on page load
        function loadFilters() {
            try {
                const stored = localStorage.getItem(STORAGE_KEY);
                if (stored) {
                    const data = JSON.parse(stored);
                    filterList = data.filters || [];
                }
            } catch (e) {
                console.warn('Failed to load filters:', e);
                filterList = [];
            }
            initCardCache();
            updateFilterUI();
            applyAllFilters();
        }
        
        // Save filters to localStorage
        function saveFilters() {
            try {
                const data = {
                    filters: filterList,
                    savedAt: new Date().toISOString()
                };
                localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
            } catch (e) {
                console.warn('Failed to save filters:', e);
            }
        }
        
        // =====================================================
        // FILTER UI
        // =====================================================
        function updateFilterUI() {
            const list = document.getElementById('filterList');
            const count = document.getElementById('filterCount');
            
            count.textContent = filterList.length;
            
            if (filterList.length === 0) {
                list.innerHTML = '<span class="filter-empty">Click the <span class="filter-icon-hint">✖</span> next to any field value or select text and use the right-click context menu to add filters.</span>';
            } else {
                list.innerHTML = filterList.map((f, i) => `
                    <div class="filter-chip">
                        <span class="filter-chip-text" title="${escapeHtml(f)}">${escapeHtml(truncateText(f, 40))}</span>
                        <button class="filter-chip-remove" onclick="removeFilter(${i})" title="Remove filter">×</button>
                    </div>
                `).join('');
            }
        }
        
        function toggleFilterPanel() {
            const panel = document.getElementById('filterPanel');
            panel.classList.toggle('open');
        }
        
        function addFilter(text) {
            if (!text || filterList.includes(text)) return;
            filterList.push(text);
            saveFilters();
            updateFilterUI();
            applyAllFilters();
        }
        
        function removeFilter(index) {
            filterList.splice(index, 1);
            saveFilters();
            updateFilterUI();
            applyAllFilters();
        }
        
        function clearAllFilters() {
            if (filterList.length === 0) return;
            if (!confirm('Clear all ' + filterList.length + ' exclusion filters?')) return;
            filterList = [];
            saveFilters();
            updateFilterUI();
            applyAllFilters();
        }
        
        // =====================================================
        // EXPORT / IMPORT
        // =====================================================
        function exportFilters() {
            if (filterList.length === 0) {
                alert('No filters to export');
                return;
            }
            const data = {
                filters: filterList,
                exportedAt: new Date().toISOString(),
                source: document.title
            };
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'raijin-combined-filters-' + new Date().toISOString().slice(0, 10) + '.json';
            a.click();
            URL.revokeObjectURL(url);
        }
        
        function importFilters(event) {
            const file = event.target.files[0];
            if (!file) return;
            
            const reader = new FileReader();
            reader.onload = function(e) {
                try {
                    const data = JSON.parse(e.target.result);
                    if (Array.isArray(data.filters)) {
                        const newFilters = data.filters.filter(f => typeof f === 'string' && !filterList.includes(f));
                        filterList = filterList.concat(newFilters);
                        saveFilters();
                        updateFilterUI();
                        applyAllFilters();
                        alert('Imported ' + newFilters.length + ' new filters');
                    } else {
                        alert('Invalid filter file format');
                    }
                } catch (err) {
                    alert('Failed to parse filter file: ' + err.message);
                }
            };
            reader.readAsText(file);
            event.target.value = '';
        }
        
        // =====================================================
        // CONTEXT MENU
        // =====================================================
        const contextMenu = document.getElementById('contextMenu');
        
        document.addEventListener('contextmenu', function(e) {
            const selection = window.getSelection().toString().trim();
            if (selection) {
                e.preventDefault();
                selectedText = selection;
                contextMenu.style.left = e.clientX + 'px';
                contextMenu.style.top = e.clientY + 'px';
                contextMenu.classList.add('visible');
            }
        });
        
        document.addEventListener('click', function(e) {
            if (!contextMenu.contains(e.target)) {
                contextMenu.classList.remove('visible');
            }
        });
        
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                contextMenu.classList.remove('visible');
            }
        });
        
        function filterOutSelection() {
            if (selectedText) {
                addFilter(selectedText);
                contextMenu.classList.remove('visible');
                window.getSelection().removeAllRanges();
            }
        }
        
        function searchOnGoogle() {
            if (selectedText) {
                window.open('https://www.google.com/search?q=' + encodeURIComponent(selectedText), '_blank');
                contextMenu.classList.remove('visible');
            }
        }
        
        // Inline filter button handler
        function filterValue(text, event) {
            if (event) {
                event.stopPropagation();
                event.preventDefault();
            }
            if (text) {
                addFilter(text.trim());
            }
        }
        
        // =====================================================
        // HOSTNAME/SEVERITY FILTERING
        // =====================================================
        let activeHostname = null;
        let activeSeverity = null;
        
        function updateFilterState() {
            const stateEl = document.getElementById('filterState');
            const clearBtn = document.getElementById('clearFiltersBtn');
            let stateText = '<span>Showing:</span> ';
            
            if (activeHostname && activeSeverity) {
                stateText += `${activeHostname} - ${activeSeverity}`;
            } else if (activeHostname) {
                stateText += activeHostname;
            } else if (activeSeverity) {
                stateText += activeSeverity;
            } else {
                stateText += 'All findings';
            }
            
            stateEl.innerHTML = stateText;
            if (activeHostname || activeSeverity) {
                clearBtn.style.display = 'inline-block';
            } else {
                clearBtn.style.display = 'none';
            }
            
            // Update active filter indicators in table
            document.querySelectorAll('#statsTable th, #statsTable td').forEach(cell => {
                cell.classList.remove('active-filter');
            });
            
            if (activeHostname) {
                document.querySelectorAll(`[data-hostname="${activeHostname}"]`).forEach(cell => {
                    if (!activeSeverity || cell.dataset.severity === activeSeverity) {
                        cell.classList.add('active-filter');
                    }
                });
            }
            
            if (activeSeverity) {
                document.querySelectorAll(`[data-severity="${activeSeverity}"]`).forEach(cell => {
                    if (!activeHostname || cell.dataset.hostname === activeHostname) {
                        cell.classList.add('active-filter');
                    }
                });
            }
        }
        
        function filterByHostname(hostname) {
            if (activeHostname === hostname) {
                activeHostname = null;
            } else {
                activeHostname = hostname;
            }
            activeSeverity = null; // Clear severity filter when selecting host
            applyFilters();
            updateFilterState();
        }
        
        function filterBySeverity(severity) {
            if (!severity) {
                activeSeverity = null;
            } else if (activeSeverity === severity) {
                activeSeverity = null;
            } else {
                activeSeverity = severity;
            }
            activeHostname = null; // Clear hostname filter when selecting severity
            applyFilters();
            updateFilterState();
        }
        
        function filterByHostnameAndSeverity(hostname, severity) {
            if (activeHostname === hostname && activeSeverity === severity) {
                activeHostname = null;
                activeSeverity = null;
            } else {
                activeHostname = hostname;
                activeSeverity = severity;
            }
            applyFilters();
            updateFilterState();
        }
        
        function clearHostnameSeverityFilters() {
            activeHostname = null;
            activeSeverity = null;
            applyAllFilters();
            updateFilterState();
        }
        
        function applyFilters() {
            applyAllFilters();
        }
        
        function applyAllFilters() {
            initCardCache();
            
            const hasExclusions = filterList.length > 0;
            
            // Use requestAnimationFrame for smoother UI updates
            requestAnimationFrame(() => {
                const len = cardCache.length;
                for (let i = 0; i < len; i++) {
                    const cached = cardCache[i];
                    
                    // Check hostname filter
                    if (activeHostname && cached.hostname !== activeHostname) {
                        cached.element.classList.add('hidden');
                        continue;
                    }
                    
                    // Check severity filter
                    if (activeSeverity && cached.severity !== activeSeverity) {
                        cached.element.classList.add('hidden');
                        continue;
                    }
                    
                    // Check exclusion filters (exact match)
                    if (hasExclusions) {
                        let excluded = false;
                        for (let j = 0; j < filterList.length; j++) {
                            if (cached.text.includes(filterList[j])) {
                                excluded = true;
                                break;
                            }
                        }
                        if (excluded) {
                            cached.element.classList.add('hidden');
                            continue;
                        }
                    }
                    
                    cached.element.classList.remove('hidden');
                }
            });
        }
        
        // =====================================================
        // UTILITY FUNCTIONS
        // =====================================================
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        function truncateText(text, maxLen) {
            if (text.length <= maxLen) return text;
            return text.substring(0, maxLen) + '...';
        }
        
        // Initialize
        loadFilters();
        updateFilterState();
    "##);
    html.push_str("    </script>\n");
    html.push_str("</body>\n</html>\n");
    
    // Write HTML file
    let mut file = File::create(output_path)
        .map_err(|e| format!("Failed to create HTML file: {}", e))?;
    file.write_all(html.as_bytes())
        .map_err(|e| format!("Failed to write HTML file: {}", e))?;
    
    Ok(output_path.to_string())
}

/// Render finding with hostname and data attributes for filtering
fn render_finding_with_hostname(finding: &LogEvent) -> String {
    let level = finding.level.to_uppercase();
    let level_class = match level.as_str() {
        "ALERT" => "alert",
        "WARNING" => "warning",
        "ERROR" => "error",
        _ => "notice",
    };
    
    let hostname = &finding.hostname;
    let hostname_escaped = html_escape(hostname);
    let score = finding.score.unwrap_or(0.0).round() as i16;
    let path_or_name = finding.file_path.as_deref()
        .or(finding.process_name.as_deref())
        .unwrap_or("Unknown");
    let path_escaped = html_escape(path_or_name);
    
    // Escape hostname for JavaScript
    let hostname_js = hostname.replace('\\', "\\\\").replace('\'', "\\'");
    
    let mut details_html = String::new();
    
    if let Some(size) = finding.file_size {
        details_html.push_str(&format!(
            r#"<div class="detail-item"><span class="detail-label">Size:</span> <span class="detail-value">{}</span></div>"#,
            format_size(size as usize)
        ));
    }
    
    if let Some(ref md5) = finding.md5 {
        let md5_js = md5.replace('\\', "\\\\").replace('\'', "\\'");
        details_html.push_str(&format!(
            r#"<div class="detail-item"><span class="detail-label">MD5:</span> <span class="detail-value">{}<button class="filter-btn-inline" onclick="filterValue('{}', event)" title="Filter out this hash">✖</button></span></div>"#,
            html_escape(md5), md5_js
        ));
    }
    
    if let Some(ref sha1) = finding.sha1 {
        let sha1_js = sha1.replace('\\', "\\\\").replace('\'', "\\'");
        details_html.push_str(&format!(
            r#"<div class="detail-item"><span class="detail-label">SHA1:</span> <span class="detail-value">{}<button class="filter-btn-inline" onclick="filterValue('{}', event)" title="Filter out this hash">✖</button></span></div>"#,
            html_escape(sha1), sha1_js
        ));
    }
    
    if let Some(ref sha256) = finding.sha256 {
        let sha256_js = sha256.replace('\\', "\\\\").replace('\'', "\\'");
        details_html.push_str(&format!(
            r#"<div class="detail-item"><span class="detail-label">SHA256:</span> <span class="detail-value">{}<button class="filter-btn-inline" onclick="filterValue('{}', event)" title="Filter out this hash">✖</button></span></div>"#,
            html_escape(sha256), sha256_js
        ));
    }
    
    let reasons_html = if let Some(ref reasons) = finding.reasons {
        let mut reasons_str = String::from(r#"<div class="reasons-section"><h4>Match Reasons</h4>"#);
        for reason in reasons {
            // Extract rule name if it's a YARA match
            let rule_name = if reason.message.starts_with("YARA match with rule ") || reason.message.starts_with("YARA-X match with rule ") {
                reason.message.split(" rule ").nth(1).map(|s| s.to_string())
            } else {
                None
            };
            
            let filter_btn = if let Some(ref rn) = rule_name {
                let rule_js = rn.replace('\\', "\\\\").replace('\'', "\\'");
                format!(r#"<button class="filter-btn-inline" onclick="filterValue('{}', event)" title="Filter out this rule">✖</button>"#, rule_js)
            } else {
                String::new()
            };
            
            reasons_str.push_str(&format!(
                r#"<div class="reason-item"><strong>{}:</strong> {} (Score: {}){}</div>"#,
                html_escape(&reason.message),
                reason.description.as_ref().map(|d| html_escape(d)).unwrap_or_default(),
                reason.score,
                filter_btn
            ));
        }
        reasons_str.push_str("</div>");
        reasons_str
    } else {
        String::new()
    };
    
    // Escape path for JavaScript
    let path_js = path_or_name.replace('\\', "\\\\").replace('\'', "\\'");
    
    format!(
        r#"        <div class="finding-card {}" data-hostname="{}" data-severity="{}" data-score="{}">
            <div class="finding-header">
                <div class="finding-title">
                    {}<span class="hostname-badge">{}</span>
                </div>
                <div class="finding-score">Score: {}</div>
            </div>
            <div class="finding-path">{}<button class="filter-btn-inline" onclick="filterValue('{}', event)" title="Filter out this path">✖</button></div>
            {}
            {}
        </div>
"#,
        level_class,
        hostname_js,
        level,
        score,
        html_escape(&level),
        hostname_escaped,
        score,
        path_escaped,
        path_js,
        details_html,
        reasons_html
    )
}

const RAIJIN_UTIL_VERSION: &str = env!("CARGO_PKG_VERSION");

// Helper functions for HTML rendering (copied from helpers/html_report.rs to maintain consistency)
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn format_size(bytes: usize) -> String {
    const KB: usize = 1_000;
    const MB: usize = KB * 1_000;
    const GB: usize = MB * 1_000;
    
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

// Helper functions kept for potential future use
#[allow(dead_code)]
fn truncate_string(s: &str, max_len: usize) -> String {
    let char_count = s.chars().count();
    if char_count <= max_len {
        s.to_string()
    } else {
        format!("{}...", s.chars().take(max_len).collect::<String>())
    }
}

#[allow(dead_code)]
fn format_rfc3339_to_datetime(rfc3339: &str) -> String {
    // Simple formatter - just return as-is for now, or parse if needed
    rfc3339.to_string()
}
