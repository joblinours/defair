//! Types and lookups shared by the scan modules and both binaries.
//!
//! Moved out of `main.rs` when the engine became a library: the modules
//! reach these through `crate::` and `raijin-util` needs `ScanConfig` for
//! report rendering, neither of which a binary crate can offer.

use regex::Regex;

#[derive(Debug, Default)]
pub struct GenMatch {
    pub message: String,
    pub score: i16,
    pub description: Option<String>,
    pub author: Option<String>,
    pub reference: Option<String>,
    pub matched_strings: Option<Vec<String>>,
    /// Structured rule identity (DEFAIR): lets consumers trace a finding
    /// back to the exact rule and source without parsing `message`.
    pub rule: Option<RuleRef>,
}

/// Which rule produced a match, as emitted in the JSONL `reasons[].rule`.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct RuleRef {
    /// "yara" or "sigma"
    pub engine: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// YARA namespace = rule source directory (one per source)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Rule file on disk (Sigma; YARA rules are resolved from the namespace)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
}

pub struct YaraMatch {
    pub rulename: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub score: i16,
    pub description: String,
    pub author: String,
    pub reference: String,
    pub matched_strings: Vec<String>,  // Format: "identifier: 'value' @ offset"
}

#[derive(Clone)]
pub struct ScanConfig {
    pub max_file_size: usize,
    pub sigma_max_artifact_size: usize,
    pub sigma_max_events_per_rule: usize,
    pub show_access_errors: bool,
    pub scan_all_types: bool,
    pub scan_hard_drives: bool,
    pub scan_all_drives: bool,
    pub scan_archives: bool,
    pub is_elevated: bool,
    pub alert_threshold: i16,
    pub warning_threshold: i16,
    pub notice_threshold: i16,
    pub max_reasons: usize,
    pub yara_timeout: std::time::Duration,
    pub threads: usize,
    pub cpu_limit: u8,
    pub exclusion_count: usize,
    pub yara_rules_count: usize,
    pub ioc_count: usize,
    pub sigma_rules_count: usize,
    pub program_dir: Option<String>,
}

#[derive(Debug)]
pub struct ExtVars {
    pub filename: String,
    pub filepath: String,
    pub filetype: String,
    pub extension: String,
    pub owner: String,
}

#[derive(Debug)]
pub struct HashIOC {
    pub hash_type: HashType,
    pub hash_value: String,
    pub description: String,
    pub score: i16,
}

// Sorted hash collections for binary search
pub struct HashIOCCollections {
    pub md5_iocs: Vec<HashIOC>,
    pub sha1_iocs: Vec<HashIOC>,
    pub sha256_iocs: Vec<HashIOC>,
}

// False positive hash collections (same structure)
pub type FalsePositiveHashCollections = HashIOCCollections;

#[derive(Debug)]
pub enum HashType {
    Md5,
    Sha1,
    Sha256,
    Unknown
}

#[derive(Debug)]
pub struct FilenameIOC {
    pub pattern: String, 
    pub regex: Regex,
    pub regex_fp: Option<Regex>,  // False positive regex (optional)
    pub description: String, 
    pub score: i16,
}

#[derive(Debug)]
pub struct C2IOC {
    pub server: String,  // Lowercased C2 server (IP or domain)
    pub description: String,
    pub score: i16,
}

#[derive(Debug)]
pub enum FilenameIOCType {
    String,
    Regex
}

// Binary search for hash in sorted collection
pub fn find_hash_ioc<'a>(hash_value: &str, iocs: &'a [HashIOC]) -> Option<&'a HashIOC> {
    iocs.binary_search_by(|ioc| ioc.hash_value.as_str().cmp(hash_value))
        .ok()
        .map(|idx| &iocs[idx])
}

// Get the hash type
pub fn get_hash_type(hash_value: &str) -> HashType {
    let hash_value_length = hash_value.len();
    match hash_value_length {
        32 => HashType::Md5,
        40 => HashType::Sha1,
        64 => HashType::Sha256,
        _ => HashType::Unknown,
    }
}

// Check if a remote address matches any C2 IOC
// Supports IP exact match, CIDR match, and domain substring match
pub fn check_c2_match<'a>(remote_addr: &str, c2_iocs: &'a [C2IOC]) -> Option<&'a C2IOC> {
    let remote_lower = remote_addr.to_lowercase();
    
    for c2_ioc in c2_iocs {
        // For IP addresses: exact match or CIDR match
        if is_ip_address(&remote_lower) {
            // Exact match
            if c2_ioc.server == remote_lower {
                return Some(c2_ioc);
            }
            // TODO: CIDR match (would need ipnet crate)
            // For now, we'll do exact match only
        } else {
            // For domains: check if remote ends with the IOC domain
            // e.g., "dga1.evildomain.com" matches IOC "evildomain.com"
            if remote_lower.ends_with(&c2_ioc.server) || remote_lower == c2_ioc.server {
                return Some(c2_ioc);
            }
        }
    }
    
    None
}

// Simple IP address check (IPv4)
pub fn is_ip_address(addr: &str) -> bool {
    let parts: Vec<&str> = addr.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    for part in parts {
        match part.parse::<u8>() {
            Ok(_) => continue,
            Err(_) => return false,
        }
    }
    true
}
