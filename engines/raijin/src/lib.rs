//! Raijin's scanning engine: YARA over files and process memory, Sigma over
//! EVTX and Linux logs, IOC matching, and the logging/report machinery.
//!
//! The `raijin` binary is the CLI around this; `raijin-util` reuses the rule
//! parser and the report renderer. Anything both need lives here.

pub mod helpers;
pub mod modules;
pub mod paths;
mod types;

pub use types::*;
