//! Where Raijin looks for its signatures and configuration.
//!
//! Both were once `./signatures` and `./config/...` - relative to whatever
//! directory the user happened to run from. That made two installs with two
//! rule sets indistinguishable in the logs and cost a full day of debugging
//! the wrong one. Resolution now goes, in order:
//!
//! 1. an explicit path (`--signatures`),
//! 2. the `RAIJIN_SIGNATURES` environment variable,
//! 3. `signatures/` next to the running binary - a deployed install,
//! 4. `signatures/` in a parent of the binary's directory, up to four
//!    levels - a source checkout, whose `cargo build` output sits at
//!    `target/release/` or `target/<triple>/release/` below the rules,
//! 5. `signatures/` in the working directory.
//!
//! Whatever wins, the caller logs the absolute path and how it was chosen,
//! so the question "which rules did this scan actually use?" is answered
//! by the log rather than by reconstructing the working directory later.

use std::env;
use std::path::{Path, PathBuf};

/// Environment variable overriding the default signatures directory.
pub const SIGNATURES_ENV: &str = "RAIJIN_SIGNATURES";
/// Directory name probed next to the binary and in the working directory.
pub const SIGNATURES_DIR_NAME: &str = "signatures";
/// Optional exclusion patterns, relative to the same roots.
pub const EXCLUDES_FILE: &str = "config/excludes.cfg";
/// How far above the binary's directory to look. Four reaches the root of
/// a checkout from `target/<triple>/release/` with one to spare, without
/// wandering up to `/`.
pub const MAX_ANCESTOR_LEVELS: usize = 4;

/// How a path was chosen, for the log line that reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Flag,
    EnvVar,
    ExeDir,
    /// A parent of the binary's directory: the checkout a `target/` build
    /// sits in.
    ExeAncestor,
    Cwd,
    /// Nothing exists at any candidate; `path` is where it would be
    /// created (next to the binary when that is known).
    Default,
}

#[derive(Debug, Clone)]
pub struct Located {
    pub path: PathBuf,
    pub origin: Origin,
}

impl Located {
    /// `path (how it was chosen)`, for logs.
    pub fn describe(&self) -> String {
        let how = match self.origin {
            Origin::Flag => "from --signatures".to_string(),
            Origin::EnvVar => format!("from {}", SIGNATURES_ENV),
            Origin::ExeDir => "next to the binary".to_string(),
            Origin::ExeAncestor => "above the binary, in the build directory".to_string(),
            Origin::Cwd => "in the working directory".to_string(),
            Origin::Default => "not found next to or above the binary, nor in the working directory".to_string(),
        };
        format!("{} ({})", self.path.display(), how)
    }

    pub fn exists(&self) -> bool {
        self.origin != Origin::Default
    }
}

/// Directory holding the running executable.
pub fn exe_dir() -> Option<PathBuf> {
    env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf))
}

/// The signatures directory, resolved in the order documented above.
pub fn resolve_signatures(explicit: Option<&Path>) -> Located {
    let env_value = env::var_os(SIGNATURES_ENV).map(PathBuf::from);
    resolve(
        explicit,
        env_value.as_deref(),
        exe_dir().as_deref(),
        env::current_dir().ok().as_deref(),
        SIGNATURES_DIR_NAME,
    )
}

/// A config file such as `config/excludes.cfg`: next to the binary, then in
/// the working directory. No flag or variable - exclusions are an install
/// setting, not a per-scan one.
pub fn resolve_config_file(relative: &str) -> Located {
    resolve(None, None, exe_dir().as_deref(), env::current_dir().ok().as_deref(), relative)
}

/// The resolution itself, over caller-supplied roots so it can be tested
/// without touching the process environment.
pub fn resolve(
    explicit: Option<&Path>,
    env_value: Option<&Path>,
    exe_dir: Option<&Path>,
    cwd: Option<&Path>,
    relative: &str,
) -> Located {
    if let Some(p) = explicit {
        return Located { path: absolute(p, cwd), origin: Origin::Flag };
    }
    if let Some(p) = env_value {
        return Located { path: absolute(p, cwd), origin: Origin::EnvVar };
    }
    if let Some(dir) = exe_dir {
        let candidate = dir.join(relative);
        if candidate.exists() {
            return Located { path: candidate, origin: Origin::ExeDir };
        }
        // `cargo build` leaves the binary under target/, two or three
        // levels below the checkout that holds the rules.
        for ancestor in dir.ancestors().skip(1).take(MAX_ANCESTOR_LEVELS) {
            let candidate = ancestor.join(relative);
            if candidate.exists() {
                return Located { path: candidate, origin: Origin::ExeAncestor };
            }
        }
    }
    if let Some(dir) = cwd {
        let candidate = dir.join(relative);
        if candidate.exists() {
            return Located { path: candidate, origin: Origin::Cwd };
        }
    }
    let base = exe_dir.or(cwd).map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
    Located { path: base.join(relative), origin: Origin::Default }
}

/// A relative path given by the user, made absolute against the working
/// directory so the log names one unambiguous location.
fn absolute(p: &Path, cwd: Option<&Path>) -> PathBuf {
    if p.is_absolute() {
        return p.to_path_buf();
    }
    match cwd {
        Some(dir) => dir.join(p),
        None => p.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A fresh directory per test, so tests can run in parallel.
    fn scratch(name: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("raijin_paths_{}_{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn explicit_path_wins_over_everything() {
        let exe = scratch("flag_exe");
        let cwd = scratch("flag_cwd");
        fs::create_dir_all(exe.join("signatures")).unwrap();
        fs::create_dir_all(cwd.join("signatures")).unwrap();
        let wanted = scratch("flag_wanted");

        let got = resolve(Some(&wanted), Some(&exe), Some(&exe), Some(&cwd), "signatures");
        assert_eq!(got.origin, Origin::Flag);
        assert_eq!(got.path, wanted);
    }

    #[test]
    fn relative_explicit_path_is_anchored_to_the_working_directory() {
        let cwd = scratch("rel_cwd");
        let got = resolve(Some(Path::new("rules")), None, None, Some(&cwd), "signatures");
        assert_eq!(got.origin, Origin::Flag);
        assert_eq!(got.path, cwd.join("rules"), "the log must name one unambiguous location");
    }

    #[test]
    fn env_var_beats_both_directories() {
        let exe = scratch("env_exe");
        let cwd = scratch("env_cwd");
        fs::create_dir_all(exe.join("signatures")).unwrap();
        fs::create_dir_all(cwd.join("signatures")).unwrap();
        let from_env = scratch("env_value");

        let got = resolve(None, Some(&from_env), Some(&exe), Some(&cwd), "signatures");
        assert_eq!(got.origin, Origin::EnvVar);
        assert_eq!(got.path, from_env);
    }

    #[test]
    fn next_to_the_binary_beats_the_working_directory() {
        let exe = scratch("exe_first_exe");
        let cwd = scratch("exe_first_cwd");
        fs::create_dir_all(exe.join("signatures")).unwrap();
        fs::create_dir_all(cwd.join("signatures")).unwrap();

        let got = resolve(None, None, Some(&exe), Some(&cwd), "signatures");
        assert_eq!(got.origin, Origin::ExeDir);
        assert_eq!(got.path, exe.join("signatures"));
    }

    #[test]
    fn a_cargo_build_binary_finds_the_checkout_above_it() {
        // target/release/raijin, run from anywhere: the rules are two levels up.
        let root = scratch("ancestor_root");
        let exe = root.join("target").join("release");
        fs::create_dir_all(&exe).unwrap();
        fs::create_dir_all(root.join("signatures")).unwrap();
        let elsewhere = scratch("ancestor_cwd");

        let got = resolve(None, None, Some(&exe), Some(&elsewhere), "signatures");
        assert_eq!(got.origin, Origin::ExeAncestor);
        assert_eq!(got.path, root.join("signatures"));
    }

    #[test]
    fn a_cross_target_build_is_still_within_reach() {
        // target/x86_64-pc-windows-msvc/release/: three levels.
        let root = scratch("triple_root");
        let exe = root.join("target").join("x86_64-pc-windows-msvc").join("release");
        fs::create_dir_all(&exe).unwrap();
        fs::create_dir_all(root.join("signatures")).unwrap();

        let got = resolve(None, None, Some(&exe), None, "signatures");
        assert_eq!(got.origin, Origin::ExeAncestor);
        assert_eq!(got.path, root.join("signatures"));
    }

    #[test]
    fn the_ancestor_walk_is_bounded() {
        // Rules five levels above the binary are not "the build directory".
        let root = scratch("bounded_root");
        let exe = root.join("a").join("b").join("c").join("d").join("e");
        fs::create_dir_all(&exe).unwrap();
        fs::create_dir_all(root.join("signatures")).unwrap();

        let got = resolve(None, None, Some(&exe), None, "signatures");
        assert_eq!(got.origin, Origin::Default, "{:?}", got.path);
    }

    #[test]
    fn working_directory_is_the_fallback_when_nothing_is_near_the_binary() {
        let exe = scratch("cwd_fallback_exe");
        let cwd = scratch("cwd_fallback_cwd");
        fs::create_dir_all(cwd.join("signatures")).unwrap();

        let got = resolve(None, None, Some(&exe), Some(&cwd), "signatures");
        assert_eq!(got.origin, Origin::Cwd);
        assert_eq!(got.path, cwd.join("signatures"));
    }

    #[test]
    fn nothing_found_defaults_next_to_the_binary_and_says_so() {
        let exe = scratch("default_exe");
        let cwd = scratch("default_cwd");

        let got = resolve(None, None, Some(&exe), Some(&cwd), "signatures");
        assert_eq!(got.origin, Origin::Default);
        assert_eq!(got.path, exe.join("signatures"), "an update should create it where a deployed install keeps it");
        assert!(!got.exists());
        assert!(got.describe().contains("not found"), "{}", got.describe());
    }

    #[test]
    fn config_files_resolve_through_the_same_roots() {
        let exe = scratch("cfg_exe");
        let cwd = scratch("cfg_cwd");
        fs::create_dir_all(cwd.join("config")).unwrap();
        fs::write(cwd.join("config/excludes.cfg"), "").unwrap();

        let got = resolve(None, None, Some(&exe), Some(&cwd), EXCLUDES_FILE);
        assert_eq!(got.origin, Origin::Cwd);
        assert_eq!(got.path, cwd.join("config").join("excludes.cfg"));
    }
}
