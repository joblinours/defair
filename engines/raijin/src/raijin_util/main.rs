mod html_report;


use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use raijin::paths::{self, Located};
use std::process::{Command, Stdio};
use serde_json::Value;
use colored::*;
use dialoguer::{Select, theme::ColorfulTheme};
use glob::glob;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const YARA_FORGE_URL: &str = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip";
// SigmaHQ publishes four release bundles, selected with
// `raijin-util update --sigma-set <core|core+|core++|all>`:
//   core   - level high/critical only (default: precise, low noise)
//   core+  - core + level medium (what most triage tools alert on)
//   core++ - core+ + level low
//   all    - every rule regardless of level/status (includes deprecated and
//            unsupported rules - highest recall, noisiest)
// `--sigma-all` is kept as an alias for `--sigma-set all`.
const SIGMA_CORE_URL: &str = "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_core.zip";
const SIGMA_CORE_PLUS_URL: &str = "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_core+.zip";
const SIGMA_CORE_PLUS_PLUS_URL: &str = "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_core++.zip";
const SIGMA_ALL_URL: &str = "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_all_rules.zip";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SigmaSet {
    Core,
    CorePlus,
    CorePlusPlus,
    All,
}

impl SigmaSet {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "core" => Some(Self::Core),
            "core+" | "coreplus" | "core-plus" => Some(Self::CorePlus),
            "core++" | "coreplusplus" | "core-plus-plus" => Some(Self::CorePlusPlus),
            "all" | "all_rules" | "all-rules" => Some(Self::All),
            _ => None,
        }
    }

    fn url(self) -> &'static str {
        match self {
            Self::Core => SIGMA_CORE_URL,
            Self::CorePlus => SIGMA_CORE_PLUS_URL,
            Self::CorePlusPlus => SIGMA_CORE_PLUS_PLUS_URL,
            Self::All => SIGMA_ALL_URL,
        }
    }

    fn zip_name(self) -> &'static str {
        match self {
            Self::Core => "sigma_core.zip",
            Self::CorePlus => "sigma_core_plus.zip",
            Self::CorePlusPlus => "sigma_core_plus_plus.zip",
            Self::All => "sigma_all_rules.zip",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Core => "Core - high/critical level rules only",
            Self::CorePlus => "Core+ - high/critical + medium level rules",
            Self::CorePlusPlus => "Core++ - high/critical + medium + low level rules",
            Self::All => "All rules - every level and status (noisiest)",
        }
    }
}
// LOLRMM (https://github.com/magicsword-io/LOLRMM) catalogues legitimate RMM
// tools abused for initial access/C2 and ships Sigma rules for each
// (network/process/registry/file indicators). It has no GitHub releases, so
// this pulls the whole repo archive and keeps only detections/sigma/*.yml.
// Opt-in via `raijin-util update --sigma-lolrmm` (additive - combines with
// either Core or --sigma-all).
const SIGMA_LOLRMM_URL: &str = "https://github.com/magicsword-io/LOLRMM/archive/refs/heads/main.zip";

// Additional always-on rule sources (none of these have GitHub releases, so
// each is a whole-repo branch archive filtered down to its rule files - same
// approach as LOLRMM above). Unlike --sigma-all/--sigma-lolrmm, these are
// fetched unconditionally by plain `update`, same as YARA-Forge/SigmaHQ Core.
const ELASTIC_YARA_URL: &str = "https://github.com/elastic/protections-artifacts/archive/refs/heads/main.zip";
const ESET_IOC_URL: &str = "https://github.com/eset/malware-ioc/archive/refs/heads/master.zip";
const REVERSINGLABS_YARA_URL: &str =
    "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/refs/heads/develop.zip";
const MALPEDIA_SIGNATOR_URL: &str = "https://github.com/malpedia/signator-rules/archive/refs/heads/main.zip";
const NEO23X0_SIGBASE_URL: &str = "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip";
const MDECREVOISIER_SIGMA_URL: &str =
    "https://github.com/mdecrevoisier/SIGMA-detection-rules/archive/refs/heads/main.zip";
const ATR_YARA_URL: &str = "https://github.com/advanced-threat-research/Yara-Rules/archive/refs/heads/master.zip";
const RAIJIN_RELEASES_URL: &str = "https://api.github.com/repos/YOUR_GITHUB_USER/Raijin/releases";
/// Where this run reads and writes rules. Set once from the command line
/// before any command runs, so every helper below agrees; resolved next to
/// the binary by default (see `raijin::paths`).
static SIGNATURES: OnceLock<Located> = OnceLock::new();

fn signatures_location() -> &'static Located {
    SIGNATURES.get_or_init(|| paths::resolve_signatures(None))
}

fn signatures_dir() -> &'static Path {
    signatures_location().path.as_path()
}

/// Downloads and extractions go through the system temp directory, not a
/// `./tmp` in whatever directory the user ran from - which on a deployed
/// install may be read-only, and on a source checkout is just litter.
fn temp_dir() -> PathBuf {
    std::env::temp_dir().join("raijin-update")
}

/// Pulls `--signatures <DIR>` / `--signatures=<DIR>` out of the arguments,
/// wherever it sits, so each command's own parser never sees it.
fn take_signatures_flag(args: Vec<String>) -> (Vec<String>, Option<PathBuf>) {
    let mut kept = Vec::with_capacity(args.len());
    let mut flag = None;
    let mut i = 0;
    while i < args.len() {
        if let Some(value) = args[i].strip_prefix("--signatures=") {
            flag = Some(PathBuf::from(value));
        } else if args[i] == "--signatures" {
            match args.get(i + 1) {
                Some(value) => {
                    flag = Some(PathBuf::from(value));
                    i += 1;
                }
                None => {
                    log_error("--signatures requires a directory");
                    std::process::exit(1);
                }
            }
        } else {
            kept.push(args[i].clone());
        }
        i += 1;
    }
    (kept, flag)
}

// Enable ANSI escape code support on Windows
#[cfg(windows)]
fn enable_ansi_support() {
    use windows::Win32::System::Console::{
        GetStdHandle, SetConsoleMode, GetConsoleMode,
        STD_OUTPUT_HANDLE, STD_ERROR_HANDLE, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
    };
    
    unsafe {
        // Enable for stdout
        if let Ok(handle) = GetStdHandle(STD_OUTPUT_HANDLE) {
            let mut mode = std::mem::zeroed();
            if GetConsoleMode(handle, &mut mode).is_ok() {
                let _ = SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
        // Enable for stderr
        if let Ok(handle) = GetStdHandle(STD_ERROR_HANDLE) {
            let mut mode = std::mem::zeroed();
            if GetConsoleMode(handle, &mut mode).is_ok() {
                let _ = SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
    }
}

#[cfg(not(windows))]
fn enable_ansi_support() {
    // ANSI codes work natively on Unix-like systems
}

fn main() {
    // Enable ANSI color support on Windows
    enable_ansi_support();
    
    print_banner();
    
    // The rules directory is decided before anything else runs, so `update`,
    // `validate` and interactive mode all read and write the same place,
    // and `raijin-util --signatures <dir>` on its own still lands in the
    // interactive menu with that directory in force.
    let (args, signatures_flag) = take_signatures_flag(std::env::args().collect());
    let _ = SIGNATURES.set(paths::resolve_signatures(signatures_flag.as_deref()));

    if args.len() < 2 {
        // Check if running in a TTY (interactive terminal)
        // If not, print usage instead of trying interactive mode
        if atty::is(atty::Stream::Stdin) {
            if let Err(e) = interactive_mode() {
                log_error(&format!("Interactive mode error: {}", e));
                std::process::exit(1);
            }
        } else {
            // Not running in a TTY (e.g., CI/CD, pipes, etc.)
            // Print usage information instead
            print_usage();
        }
        return;
    }

    let command = &args[1];
    match command.as_str() {
        "update" => {
            let sigma_lolrmm = args[2..].iter().any(|a| a == "--sigma-lolrmm");
            let mut sigma_set = SigmaSet::Core;
            let mut i = 2;
            while i < args.len() {
                let arg = args[i].as_str();
                if arg == "--sigma-all" {
                    sigma_set = SigmaSet::All;
                } else if let Some(value) = arg.strip_prefix("--sigma-set=") {
                    sigma_set = parse_sigma_set_or_exit(value);
                } else if arg == "--sigma-set" {
                    let Some(value) = args.get(i + 1) else {
                        log_error("--sigma-set requires a value: core, core+, core++ or all");
                        std::process::exit(1);
                    };
                    sigma_set = parse_sigma_set_or_exit(value);
                    i += 1;
                }
                i += 1;
            }
            log_step("Starting signature update...");
            if let Err(e) = update_signatures(sigma_set, sigma_lolrmm) {
                log_error(&format!("Error updating signatures: {}", e));
                std::process::exit(1);
            }
            log_success("Signatures updated successfully!");
        }
        "validate" => {
            validate_signatures();
        }
        "upgrade" => {
            log_step("Starting Raijin upgrade...");
            if let Err(e) = upgrade_raijin() {
                log_error(&format!("Error upgrading Raijin: {}", e));
                std::process::exit(1);
            }
            log_success("Raijin upgraded successfully!");
        }
        "html" => {
            if let Err(e) = handle_html_command(&args[2..]) {
                log_error(&format!("Error generating HTML report: {}", e));
                std::process::exit(1);
            }
        }
        "--help" | "-h" => {
            print_usage();
        }
        _ => {
            log_error(&format!("Unknown command: {}", command));
            print_usage();
            std::process::exit(1);
        }
    }
}

fn print_banner() {
    println!("{}", "------------------------------------------------------------------------".bright_green());
    println!("{}", "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣄⣀⠀⠀⠀⠀⠀⠀⠀".bright_green());
    println!("{}", "⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⡶⢿⣟⡛⣿⢉⣿⠛⢿⣯⡈⠙⣿⣦⡀⠀⠀⠀⠀  __________        .__     __.__        ".bright_green());
    println!("{}", "⠀⠀⠀⠀⠀⠀⣠⡾⠻⣧⣬⣿⣿⣿⣿⣿⡟⠉⣠⣾⣿⠿⠿⠿⢿⣿⣦⠀⠀⠀  \\______   \\_____  |__|   |__|__| ____  ".bright_green());
    println!("{}", "⠀⠀⠀⠀⣠⣾⡋⣻⣾⣿⣿⣿⠿⠟⠛⠛⠛⠀⢻⣿⡇⢀⣴⡶⡄⠈⠛⠀⠀⠀   |       _/\\__  \\ |  |   |  |  |/    \\ ".bright_green());
    println!("{}", "⠀⠀⠀⣸⣿⣉⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠈⢿⣇⠈⢿⣤⡿⣦⠀⠀⠀⠀   |    |   \\ / __ \\|  |   |  |  |   |  \\".bright_green());
    println!("{}", "⠀⠀⢰⣿⣉⣿⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠦⠀⢻⣦⠾⣆⠀⠀⠀   |____|_  /(____  /__/\\__|  |__|___|  /".bright_green());
    println!("{}", "⠀⠀⣾⣏⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⡶⢾⡀⠀⠀          \\/      \\/   \\______|       \\/ ".bright_green());
    println!("{}", "⠀⠀⣿⠉⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣧⣼⡇⠀⠀  High-Performance YARA, Sigma & IOC Scanner".bright_green());
    println!("⠀⠀⣿⡛⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣧⣼⡇⠀⠀  Version {} (Rust)", VERSION);
    println!("{}", "⠀⠀⠸⡿⢻⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⣿⣥⣽⠁⠀⠀  TCS-CERT 2026".bright_green());
    println!("{}", "⠀⠀⠀⢻⡟⢙⣿⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣧⣸⡏⠀⠀⠀".bright_green());
    println!("{}", "⠀⠀⠀⠀⠻⣿⡋⣻⣿⣿⣿⣦⣤⣀⣀⣀⣀⣀⣠⣴⣿⣿⢿⣥⣼⠟⠀⠀⠀⠀".bright_green());
    println!("{}", "⠀⠀⠀⠀⠀⠈⠻⣯⣤⣿⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⠛⣷⣴⡿⠋⠀⠀⠀⠀⠀".bright_green());
    println!("{}", "⠀⠀⠀⠀⠀⠀⠀⠈⠙⠛⠾⣧⣼⣟⣉⣿⣉⣻⣧⡿⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀".bright_green());
    println!("{}", "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀".bright_green());
    println!("{}", "------------------------------------------------------------------------".bright_green());
    println!();
}

fn print_usage() {
    println!("Usage: raijin-util <command>");
    println!();
    println!("Commands:");
    println!(
        "  {}   - Update YARA (YARA-Forge Core, Elastic, ESET, ReversingLabs, Malpedia, Neo23x0) and Sigma (SigmaHQ Core, mdecrevoisier) rules",
        "update".green()
    );
    println!(
        "    {} - Which SigmaHQ bundle to fetch: core (high/critical only, default), core+ (adds medium), core++ (adds low), all",
        "--sigma-set <set>".green()
    );
    println!("    {}          - Alias for --sigma-set all", "--sigma-all".green());
    println!(
        "    {}       - Also fetch LOLRMM Sigma rules (RMM tool abuse detection, additive)",
        "--sigma-lolrmm".green()
    );
    println!("  {}  - Update Raijin program and signatures", "upgrade".green());
    println!("  {} - Parse the installed rules and report the ones the scanner cannot use", "validate".green());
    println!("             --signatures <dir> - Rules directory for update/validate (default: next to this binary, then ./signatures)");
    println!("             (runs automatically at the end of `update`)");
    println!("  {}    - Generate HTML report from JSONL file(s)", "html".green());
    println!();
    println!("HTML Report Generation:");
    println!("  raijin-util html --input <file.jsonl> --output <report.html>");
    println!("  raijin-util html --input \"*.jsonl\" --combine --output combined.html");
    println!();
    println!("Options:");
    println!("  --input <file|glob>  - Input JSONL file or glob pattern");
    println!("  --output <file.html> - Output HTML file (optional, defaults to input.html)");
    println!("  --combine            - Combine multiple JSONL files into one report");
    println!("  --title <str>       - Override report title");
    println!("  --host <str>         - Override hostname");
    println!();
}

fn log_info(msg: &str) {
    println!(" {} {}", "[*]".blue(), msg);
}

fn log_success(msg: &str) {
    println!(" {} {}", "[+]".green(), msg);
}

fn log_error(msg: &str) {
    eprintln!(" {} {}", "[!]".red(), msg);
}

fn log_warn(msg: &str) {
    println!(" {} {}", "[!]".yellow(), msg);
}

fn log_step(msg: &str) {
    println!(" {} {}", "[>]".cyan(), msg);
}

fn interactive_mode() -> Result<(), Box<dyn std::error::Error>> {
    let options = vec![
        "Update signatures",
        "Upgrade Raijin",
        "Exit"
    ];

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("What would you like to do?")
        .default(0)
        .items(&options)
        .interact()?;

    match selection {
        0 => {
            let sigma_sets = [SigmaSet::Core, SigmaSet::CorePlus, SigmaSet::CorePlusPlus, SigmaSet::All];
            let sigma_options: Vec<&str> = sigma_sets.iter().map(|s| s.label()).collect();
            let sigma_selection = Select::with_theme(&ColorfulTheme::default())
                .with_prompt("Which SigmaHQ rule set?")
                .default(0)
                .items(&sigma_options)
                .interact()?;
            let sigma_set = sigma_sets[sigma_selection];

            let lolrmm_options = vec!["No", "Yes - fetch RMM-tool detection rules (network/process/registry/file)"];
            let lolrmm_selection = Select::with_theme(&ColorfulTheme::default())
                .with_prompt("Also fetch LOLRMM Sigma rules (RMM tool abuse detection)?")
                .default(0)
                .items(&lolrmm_options)
                .interact()?;
            let sigma_lolrmm = lolrmm_selection == 1;

            log_step("Starting signature update...");
            update_signatures(sigma_set, sigma_lolrmm)?;
            log_success("Signatures updated successfully!");
        }
        1 => {
            log_step("Starting Raijin upgrade...");
            upgrade_raijin()?;
            log_success("Raijin upgraded successfully!");
        }
        _ => {
            println!("Exiting...");
        }
    }
    
    Ok(())
}

fn parse_sigma_set_or_exit(value: &str) -> SigmaSet {
    match SigmaSet::parse(value) {
        Some(set) => set,
        None => {
            log_error(&format!("Unknown Sigma set '{}'. Expected one of: core, core+, core++, all", value));
            std::process::exit(1);
        }
    }
}

fn update_signatures(sigma_set: SigmaSet, sigma_lolrmm: bool) -> Result<(), Box<dyn std::error::Error>> {
    // DEFAIR: signatures come from `defair rules sync`, pinned by tag/commit in
    // rules/rules.lock and verified file by file. This path fetches `latest`
    // with no checksum and flattens files by basename, so it is disabled
    // unless explicitly re-enabled for standalone use.
    if std::env::var_os("RAIJIN_ALLOW_UNPINNED_UPDATE").is_none() {
        return Err("signature updates are managed by DEFAIR: run `defair rules sync` \
                    (pinned sources, verified hashes). Set RAIJIN_ALLOW_UNPINNED_UPDATE=1 \
                    to use the unpinned upstream updater anyway."
            .into());
    }
    log_info(&format!("Signatures directory: {}", signatures_location().describe()));
    // Create signatures directory if it doesn't exist
    fs::create_dir_all(signatures_dir().join("yara"))?;
    fs::create_dir_all(signatures_dir().join("sigma"))?;
    fs::create_dir_all(signatures_dir().join("iocs"))?;

    // Create temp directory
    fs::create_dir_all(temp_dir())?;

    // Remove existing YARA rules before installing the current Core bundle.
    // This prevents legacy packaged rules from accumulating across updates.
    clear_existing_yara_rules()?;

    // Download and extract YARA rules from yara-forge
    log_info("Downloading YARA rules from yara-forge...");
    download_and_extract_yara_rules()?;

    // Same for Sigma rules: clear the previous SigmaHQ Core bundle before
    // installing the current one.
    clear_existing_sigma_rules()?;

    log_info(&format!("Downloading Sigma rules from SigmaHQ ({})...", sigma_set.label()));
    download_and_extract_sigma_rules(sigma_set)?;

    if sigma_lolrmm {
        log_info("Downloading LOLRMM Sigma rules (RMM tool abuse detection)...");
        download_and_extract_lolrmm_rules()?;
    }

    // Extra always-on sources: Elastic, ESET, ReversingLabs, Malpedia,
    // Neo23x0 (YARA) and mdecrevoisier (Sigma). Each is independently
    // best-effort (see `download_extra_sources`) so one unreachable repo
    // doesn't fail the whole update.
    download_extra_sources();

    // Keep IOC files optional, but ensure default placeholder files exist to
    // maintain compatibility with IOC loading paths.
    ensure_default_ioc_files()?;

    // Report anything the scanner will not be able to load, now rather than
    // as a warning buried in the next scan's output.
    validate_signatures();

    // Clean up temp directory
    fs::remove_dir_all(temp_dir())?;

    Ok(())
}

/// Parses every downloaded rule and reports the unusable ones.
///
/// This is for visibility, not safety: the scanner already skips a rule it
/// cannot parse, and the bound in `sigma_rules::parse_rule_file` is what
/// actually protects it from a pathological file. What this adds is knowing
/// at update time which rules are not contributing any detection coverage.
fn validate_signatures() {
    let location = signatures_location();
    log_info(&format!("Signatures directory: {}", location.describe()));
    if !location.exists() {
        log_warn("Nothing to validate: no signatures directory. Pass --signatures <dir> or run 'raijin-util update' first.");
        return;
    }
    log_step("Validating downloaded rules...");
    validate_sigma_rules();
    validate_yara_rules();
}

/// Lists up to three offending files, then a count of the rest.
fn report_broken(engine: &str, ok: usize, broken: &[(String, String)]) {
    if broken.is_empty() {
        log_success(&format!("{}: {} rule(s) OK, none unusable", engine, ok));
        return;
    }
    log_warn(&format!(
        "{}: {} rule(s) OK, {} file(s) unusable and skipped by the scanner",
        engine,
        ok,
        broken.len()
    ));
    for (name, reason) in broken.iter().take(3) {
        println!("      {}: {}", name, reason);
    }
    if broken.len() > 3 {
        println!("      ... and {} more", broken.len() - 3);
    }
}

fn rule_file_name(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| path.display().to_string())
}

fn validate_sigma_rules() {
    use raijin::helpers::sigma_rules::{parse_rule_file, SigmaDocument};

    let pattern = format!("{}/sigma/**/*.y*ml", signatures_dir().display());
    let mut ok = 0usize;
    let mut broken: Vec<(String, String)> = Vec::new();

    let Ok(paths) = glob(&pattern) else {
        log_warn("Sigma: could not enumerate rule files, skipping validation");
        return;
    };

    for path in paths.filter_map(Result::ok) {
        let Ok(content) = fs::read_to_string(&path) else {
            broken.push((rule_file_name(&path), "unreadable".to_string()));
            continue;
        };
        for document in parse_rule_file(&content) {
            match document {
                SigmaDocument::Rule(_) => ok += 1,
                SigmaDocument::Error(e) => broken.push((rule_file_name(&path), e)),
                SigmaDocument::Skipped(_) => {}
            }
        }
    }

    report_broken("Sigma", ok, &broken);
}

fn validate_yara_rules() {
    let pattern = format!("{}/yara/**/*.yar*", signatures_dir().display());
    let mut ok = 0usize;
    let mut broken: Vec<(String, String)> = Vec::new();

    let Ok(paths) = glob(&pattern) else {
        log_warn("YARA: could not enumerate rule files, skipping validation");
        return;
    };

    for path in paths.filter_map(Result::ok) {
        let Ok(source) = fs::read_to_string(&path) else {
            broken.push((rule_file_name(&path), "unreadable".to_string()));
            continue;
        };
        // A fresh compiler per file: rule identifiers must be unique within a
        // namespace, so reusing one would report a valid rule as a duplicate
        // just because another file already defined that name.
        let mut compiler = yara_x::Compiler::new();
        for global in ["filename", "filepath", "extension", "filetype", "owner"] {
            let _ = compiler.define_global(global, "");
        }
        match compiler.add_source(source.as_str()) {
            Ok(_) => ok += source.lines().filter(|l| l.trim_start().starts_with("rule ")).count(),
            Err(e) => broken.push((rule_file_name(&path), e.to_string().lines().next().unwrap_or("compile error").to_string())),
        }
    }

    report_broken("YARA", ok, &broken);
}

fn download_file(url: &str, output_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let resp = ureq::get(url)
        .header("User-Agent", "raijin-util")
        .call()?;
    
    let mut reader = resp.into_body().into_reader();
    let mut file = fs::File::create(output_path)?;
    io::copy(&mut reader, &mut file)?;
    
    Ok(())
}

fn fetch_url_content(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut resp = ureq::get(url)
        .header("User-Agent", "raijin-util")
        .call()?;
    let body = resp.body_mut().read_to_string()?;
    Ok(body)
}

fn download_and_extract_yara_rules() -> Result<(), Box<dyn std::error::Error>> {
    let zip_path = temp_dir().join("yara-forge-rules-core.zip");
    download_file(YARA_FORGE_URL, &zip_path)?;
    
    // Extract ZIP file
    let file = fs::File::open(&zip_path)?;
    let mut archive = zip::ZipArchive::new(std::io::BufReader::new(file))?;
    
    let yara_dest = signatures_dir().join("yara");
    fs::create_dir_all(&yara_dest)?;
    
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        
        // Skip directories
        if file.name().ends_with('/') {
            continue;
        }
        
        // Only extract .yar files
        if !file.name().ends_with(".yar") {
            continue;
        }
        
        // Get the filename from the path
        let file_path = Path::new(file.name());
        let filename = file_path.file_name()
            .and_then(|n| n.to_str())
            .ok_or("Invalid filename")?;
        
        // Create destination path
        let dest_path = yara_dest.join(filename);
        
        // Extract file directly to signatures/yara
        let mut outfile = fs::File::create(&dest_path)?;
        io::copy(&mut file, &mut outfile)?;
    }
    
    log_success("YARA rules updated from yara-forge");
    
    Ok(())
}

// Subdirectory names raijin-util fully owns under signatures/yara/ - one per
// external source that doesn't ship via yara-forge, each compiled by Raijin
// into its own YARA namespace (see `add_yara_dir`/`initialize_yara_rules` in
// main.rs) so a rule name reused across two sources can't collide. Cleared
// and re-extracted on every `update`; any *other* subdirectory (e.g. a
// user's own custom folder) is left untouched, same as root-level files.
const MANAGED_YARA_SUBDIRS: &[&str] = &["elastic", "eset", "reversinglabs", "malpedia", "neo23x0", "atr"];

fn clear_existing_yara_rules() -> Result<(), Box<dyn std::error::Error>> {
    let yara_dir = signatures_dir().join("yara");
    if !yara_dir.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(&yara_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext.eq_ignore_ascii_case("yar") || ext.eq_ignore_ascii_case("yara") {
            fs::remove_file(path)?;
        }
    }

    for subdir in MANAGED_YARA_SUBDIRS {
        let dir = yara_dir.join(subdir);
        if dir.is_dir() {
            fs::remove_dir_all(&dir)?;
        }
    }

    Ok(())
}

// SigmaHQ's release ships rules nested under category subdirectories
// (rules/windows/..., rules/linux/..., rules/web/...) rather than flat like
// YARA-Forge's bundle, but extraction still flattens by filename into
// signatures/sigma/ - same approach as download_and_extract_yara_rules,
// which already only looks at each zip entry's basename.
fn download_and_extract_sigma_rules(sigma_set: SigmaSet) -> Result<(), Box<dyn std::error::Error>> {
    let zip_path = temp_dir().join(sigma_set.zip_name());
    download_file(sigma_set.url(), &zip_path)?;

    let file = fs::File::open(&zip_path)?;
    let mut archive = zip::ZipArchive::new(std::io::BufReader::new(file))?;

    let sigma_dest = signatures_dir().join("sigma");
    fs::create_dir_all(&sigma_dest)?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;

        if file.name().ends_with('/') {
            continue;
        }

        let is_yml = file.name().ends_with(".yml") || file.name().ends_with(".yaml");
        if !is_yml {
            continue;
        }

        let file_path = Path::new(file.name());
        let filename = file_path.file_name()
            .and_then(|n| n.to_str())
            .ok_or("Invalid filename")?;

        let dest_path = sigma_dest.join(filename);

        let mut outfile = fs::File::create(&dest_path)?;
        io::copy(&mut file, &mut outfile)?;
    }

    log_success(&format!("Sigma rules updated from SigmaHQ ({})", sigma_set.label()));

    Ok(())
}

// Generic "no GitHub release" source: downloads a repo's whole branch
// archive and keeps only the files under `path_filter` (a substring that
// must appear in the zip entry's path - pass "" to match anywhere in the
// repo) whose name ends with one of `extensions`, flattened by basename into
// `dest_dir`. Same approach for every source below that doesn't ship a
// release asset. Returns the number of files extracted.
//
// Note: flattening by basename means a filename collision between two
// sources (or within one source's own directory tree) silently overwrites -
// same tradeoff already accepted by the YARA-Forge/SigmaHQ extraction above.
fn download_and_extract_from_repo_archive(
    url: &str,
    temp_zip_name: &str,
    path_filter: &str,
    extensions: &[&str],
    dest_dir: &Path,
) -> Result<usize, Box<dyn std::error::Error>> {
    let zip_path = temp_dir().join(temp_zip_name);
    download_file(url, &zip_path)?;

    let file = fs::File::open(&zip_path)?;
    let mut archive = zip::ZipArchive::new(std::io::BufReader::new(file))?;

    fs::create_dir_all(dest_dir)?;

    let mut extracted = 0usize;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;

        if file.name().ends_with('/') {
            continue;
        }

        let matches_ext = extensions.iter().any(|ext| file.name().ends_with(ext));
        if !matches_ext {
            continue;
        }
        if !path_filter.is_empty() && !file.name().contains(path_filter) {
            continue;
        }

        let file_path = Path::new(file.name());
        let Some(filename) = file_path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        let dest_path = dest_dir.join(filename);

        let mut outfile = fs::File::create(&dest_path)?;
        io::copy(&mut file, &mut outfile)?;
        extracted += 1;
    }

    Ok(extracted)
}

// LOLRMM has no GitHub release, so this pulls the full repo archive (whole
// source tree, not just the rules) and keeps only the .yml files under
// detections/sigma/, flattened by basename into signatures/sigma/.
fn download_and_extract_lolrmm_rules() -> Result<(), Box<dyn std::error::Error>> {
    let sigma_dest = signatures_dir().join("sigma");
    let extracted = download_and_extract_from_repo_archive(
        SIGMA_LOLRMM_URL,
        "lolrmm_main.zip",
        "/detections/sigma/",
        &[".yml", ".yaml"],
        &sigma_dest,
    )?;

    log_success(&format!("LOLRMM Sigma rules updated ({} rules)", extracted));

    Ok(())
}

// The 7 "always-on" extra sources (see const doc comments above). Each
// failure is logged and skipped rather than aborting the whole `update` -
// with this many independent external sources, one flaky/renamed/moved repo
// shouldn't block YARA-Forge/SigmaHQ from updating.
fn download_extra_sources() {
    let yara_dest = signatures_dir().join("yara");
    let sigma_dest = signatures_dir().join("sigma");

    // (url, temp zip name, path filter, display label, managed subdir - see
    // MANAGED_YARA_SUBDIRS/`add_yara_dir` in main.rs for why each source
    // gets its own namespace-backing subdirectory instead of being
    // flattened into signatures/yara/ directly).
    let yara_sources: &[(&str, &str, &str, &str, &str)] = &[
        (ELASTIC_YARA_URL, "elastic_protections.zip", "/yara/rules/", "Elastic protections-artifacts", "elastic"),
        (ESET_IOC_URL, "eset_malware_ioc.zip", "", "ESET malware-ioc", "eset"),
        (REVERSINGLABS_YARA_URL, "reversinglabs_yara.zip", "/yara/", "ReversingLabs yara-rules", "reversinglabs"),
        (MALPEDIA_SIGNATOR_URL, "malpedia_signator.zip", "/rules/", "Malpedia signator-rules", "malpedia"),
        (NEO23X0_SIGBASE_URL, "neo23x0_sigbase.zip", "/yara/", "Neo23x0 signature-base", "neo23x0"),
        (ATR_YARA_URL, "atr_yara.zip", "", "Trellix ATR Yara-Rules", "atr"),
    ];

    for (url, temp_name, path_filter, label, subdir) in yara_sources {
        log_info(&format!("Downloading YARA rules from {}...", label));
        let dest = yara_dest.join(subdir);
        match download_and_extract_from_repo_archive(url, temp_name, path_filter, &[".yar", ".yara"], &dest) {
            Ok(count) => log_success(&format!("{} YARA rules updated ({} rules)", label, count)),
            Err(e) => log_error(&format!("Failed to fetch {} YARA rules: {}", label, e)),
        }
    }

    log_info("Downloading Sigma rules from mdecrevoisier SIGMA-detection-rules...");
    match download_and_extract_from_repo_archive(
        MDECREVOISIER_SIGMA_URL,
        "mdecrevoisier_sigma.zip",
        "",
        &[".yml", ".yaml"],
        &sigma_dest,
    ) {
        Ok(count) => log_success(&format!("mdecrevoisier SIGMA-detection-rules updated ({} rules)", count)),
        Err(e) => log_error(&format!("Failed to fetch mdecrevoisier SIGMA-detection-rules: {}", e)),
    }
}

fn clear_existing_sigma_rules() -> Result<(), Box<dyn std::error::Error>> {
    let sigma_dir = signatures_dir().join("sigma");
    if !sigma_dir.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(&sigma_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml") {
            fs::remove_file(path)?;
        }
    }

    Ok(())
}

fn ensure_default_ioc_files() -> Result<(), Box<dyn std::error::Error>> {
    let iocs_dir = signatures_dir().join("iocs");
    fs::create_dir_all(&iocs_dir)?;

    let defaults = [
        ("hash-iocs.txt", "# Optional custom hash IOCs\n"),
        ("filename-iocs.txt", "# Optional custom filename IOCs\n"),
        ("c2-iocs.txt", "# Optional custom C2 IOCs\n"),
        ("keywords.txt", "# Optional custom keyword IOCs\n"),
    ];

    for (name, content) in defaults {
        let path = iocs_dir.join(name);
        if !path.exists() {
            fs::write(path, content)?;
        }
    }

    Ok(())
}

fn get_platform_string() -> String {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    
    // Match the naming convention used in releases
    // e.g. raijin-windows-x86_64.zip, raijin-linux-x86_64.tar.gz
    
    let os_str = match os {
        "windows" => "windows",
        "linux" => "linux",
        "macos" => "macos",
        _ => return "unknown".to_string(),
    };
    
    let arch_str = match arch {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64", // macOS M1/M2
        _ => return "unknown".to_string(),
    };
    
    format!("raijin-{}-{}", os_str, arch_str)
}

fn extract_zip(zip_path: &Path, dest_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let file = fs::File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(std::io::BufReader::new(file))?;
    
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = dest_dir.join(file.mangled_name());

        if (&*file.name()).ends_with('/') {
            fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    fs::create_dir_all(&p)?;
                }
            }
            let mut outfile = fs::File::create(&outpath)?;
            io::copy(&mut file, &mut outfile)?;
        }
    }
    Ok(())
}

fn extract_tar_gz(tar_path: &Path, dest_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("tar")
        .arg("-xzf")
        .arg(tar_path)
        .arg("-C")
        .arg(dest_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    
    if !status.success() {
        return Err("Failed to extract tar.gz archive".into());
    }
    Ok(())
}

fn install_updates(source_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Find executables in source_dir (could be nested in a folder)
    let mut root_dir = source_dir.to_path_buf();
    
    // Check if there is a single directory inside
    let entries: Vec<_> = fs::read_dir(source_dir)?.collect::<Result<_, _>>()?;
    if entries.len() == 1 && entries[0].path().is_dir() {
        root_dir = entries[0].path();
    }
    
    let current_exe = std::env::current_exe()?;
    let current_dir = current_exe.parent().ok_or("Cannot get current directory")?;
    
    // Files to update
    let targets = if cfg!(windows) {
        vec!["raijin.exe", "raijin-util.exe"]
    } else {
        vec!["raijin", "raijin-util"]
    };
    
    for target in targets {
        let src = root_dir.join(target);
        if src.exists() {
            let dst = current_dir.join(target);
            
            // On Windows, we can't overwrite running executable. Rename it first.
            if dst.exists() {
                let backup = current_dir.join(format!("{}.old", target));
                // Remove old backup if exists
                if backup.exists() {
                    let _ = fs::remove_file(&backup);
                }
                
                // Rename current to backup
                match fs::rename(&dst, &backup) {
                    Ok(_) => log_info(&format!("Backup created: {}", backup.display())),
                    Err(e) => log_warn(&format!("Failed to rename {} to backup: {} (might be acceptable if we can overwrite)", target, e)),
                }
            }
            
            // Copy new file
            fs::copy(&src, &dst)?;
            log_success(&format!("Updated: {}", target));
            
            // Set executable permissions on Unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&dst)?.permissions();
                perms.set_mode(0o755);
                fs::set_permissions(&dst, perms)?;
            }
        }
    }
    
    Ok(())
}

fn upgrade_raijin_binary() -> Result<(), Box<dyn std::error::Error>> {
    let platform = get_platform_string();
    if platform == "unknown" {
        return Err("Could not determine platform (OS/Arch) for automatic update.".into());
    }
    
    log_info(&format!("Detected platform: {}", platform));
    
    // 1. Get latest release info
    log_info("Checking for updates from GitHub...");
    let json_content = fetch_latest_release_info()?;
    let releases: Value = serde_json::from_str(&json_content)?;
    
    // Get the first release from the list (latest)
    let latest_release = if releases.is_array() {
        releases.get(0).ok_or("No releases found")?
    } else if releases.is_object() && releases.get("tag_name").is_some() {
        &releases
    } else {
        return Err("Invalid response from GitHub API".into());
    };
    
    let tag_name = latest_release["tag_name"].as_str().ok_or("No tag_name in release info")?;
    log_info(&format!("Latest version available: {}", tag_name));
    
    // 2. Find matching asset
    let assets = latest_release["assets"].as_array().ok_or("No assets in release info")?;
    let mut download_url = None;
    let mut asset_name = "";
    
    for asset in assets {
        let name = asset["name"].as_str().unwrap_or("");
        if name.contains(&platform) && (name.ends_with(".zip") || name.ends_with(".tar.gz")) {
            download_url = asset["browser_download_url"].as_str();
            asset_name = name;
            break;
        }
    }
    
    let download_url = download_url.ok_or(format!("No matching release found for platform: {}", platform))?;
    log_info(&format!("Found matching release: {}", asset_name));
    
    // Create temp directory
    fs::create_dir_all(temp_dir())?;

    // 3. Download
    let archive_path = temp_dir().join(asset_name);
    log_info("Downloading release...");
    download_file(download_url, &archive_path)?;
    
    // 4. Extract
    log_info("Extracting update...");
    let extract_dir = temp_dir().join("update_extracted");
    fs::create_dir_all(&extract_dir)?;
    
    if asset_name.ends_with(".zip") {
        extract_zip(&archive_path, &extract_dir)?;
    } else { // tar.gz
        extract_tar_gz(&archive_path, &extract_dir)?;
    }
    
    // 5. Replace files
    install_updates(&extract_dir)?;
    
    // Clean up
    let _ = fs::remove_file(&archive_path);
    let _ = fs::remove_dir_all(&extract_dir);
    
    Ok(())
}

fn fetch_latest_release_info() -> Result<String, Box<dyn std::error::Error>> {
    fetch_url_content(RAIJIN_RELEASES_URL)
}

fn upgrade_raijin() -> Result<(), Box<dyn std::error::Error>> {
    // DEFAIR: Raijin is vendored and built from source in CI; self-upgrade
    // from a release feed would bypass that.
    if std::env::var_os("RAIJIN_ALLOW_SELF_UPGRADE").is_none() {
        return Err("Raijin is vendored in DEFAIR (engines/raijin) and built in CI; \
                    self-upgrade is disabled."
            .into());
    }
    log_info("Upgrading Raijin via GitHub Releases...");

    // Attempt binary upgrade
    if let Err(e) = upgrade_raijin_binary() {
         log_error(&format!("Automatic binary upgrade failed: {}", e));
         log_error("Please update Raijin manually.");
         return Err(e);
    }
    
    // Update signatures (Core rule set - `update --sigma-set` is the
    // explicit opt-in path for the broader SigmaHQ bundles)
    update_signatures(SigmaSet::Core, false)?;

    Ok(())
}

fn handle_html_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut input: Option<String> = None;
    let mut output: Option<String> = None;
    let mut combine = false;
    let mut title: Option<String> = None;
    let mut host: Option<String> = None;
    
    // Parse arguments
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--input" | "-i" => {
                if i + 1 < args.len() {
                    input = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    return Err("--input requires a value".into());
                }
            }
            "--output" | "-o" => {
                if i + 1 < args.len() {
                    output = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    return Err("--output requires a value".into());
                }
            }
            "--combine" | "-c" => {
                combine = true;
                i += 1;
            }
            "--title" | "-t" => {
                if i + 1 < args.len() {
                    title = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    return Err("--title requires a value".into());
                }
            }
            "--host" | "-h" => {
                if i + 1 < args.len() {
                    host = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    return Err("--host requires a value".into());
                }
            }
            "--help" => {
                print_usage();
                return Ok(());
            }
            _ => {
                return Err(format!("Unknown argument: {}", args[i]).into());
            }
        }
    }
    
    let input_path = input.ok_or("--input is required")?;
    
    // Expand glob pattern if needed
    let input_files = expand_inputs(&input_path)?;
    
    if input_files.is_empty() {
        return Err(format!("No files found matching: {}", input_path).into());
    }
    
    log_step(&format!("Found {} JSONL file(s) to process", input_files.len()));
    
    if combine || input_files.len() > 1 {
        // Combined report mode
        log_step("Generating combined HTML report...");
        let combined_data = html_report::parse_multiple_jsonl_files(&input_files)?;
        
        let output_path = output.unwrap_or_else(|| "combined_report.html".to_string());
        let version = combined_data.sources.first()
            .and_then(|s| s.version.as_ref())
            .map(|v| v.clone())
            .unwrap_or_else(|| VERSION.to_string());
        
        html_report::render_combined_html(&combined_data, &version, &output_path)?;
        log_success(&format!("Combined HTML report written to: {}", output_path));
    } else {
        // Single file mode
        log_step("Generating HTML report...");
        let output_path = html_report::generate_single_report(
            &input_files[0],
            output.as_deref(),
            title.as_deref(),
            host.as_deref(),
        )?;
        log_success(&format!("HTML report written to: {}", output_path));
    }
    
    Ok(())
}

fn expand_inputs(pattern: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    
    // Check if pattern contains glob characters
    if pattern.contains('*') || pattern.contains('?') || pattern.contains('[') {
        // Use glob pattern matching
        let matches = glob(pattern)?;
        for entry in matches {
            match entry {
                Ok(path) => {
                    if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("jsonl") {
                        files.push(path.to_string_lossy().to_string());
                    }
                }
                Err(e) => {
                    log_warn(&format!("Error matching glob pattern: {}", e));
                }
            }
        }
    } else {
        // Single file path
        let path = Path::new(pattern);
        if !path.exists() {
            return Err(format!("File not found: {}", pattern).into());
        }
        if !path.is_file() {
            return Err(format!("Path is not a file: {}", pattern).into());
        }
        files.push(pattern.to_string());
    }
    
    // Sort for consistent ordering
    files.sort();
    
    Ok(files)
}
