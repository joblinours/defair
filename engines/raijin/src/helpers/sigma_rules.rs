/// Sigma rule loading, scoring, and logsource-based routing.
///
/// Loading goes through `parse_rule_file`, which handles the cases the raw
/// `sigma_rust::rule_from_yaml` entry point rejects but that real-world rule
/// packs (SigmaHQ, mdecrevoisier, LOLRMM, ...) contain:
/// - multi-document YAML files (`---` separated), one rule per document
/// - list-valued `logsource.category` / `logsource.service`
/// - correlation / collection documents, which are skipped (not errors)
///
/// While the YAML is in hand, the detection block is also analyzed to
/// pre-compute two things sigma-rust doesn't expose: the set of `EventID`
/// values a rule can possibly match (used to index rules per EventID so a
/// single EVTX record is only evaluated against a handful of rules instead
/// of ~1500), and the list of event field names the rule references (used
/// to attach the relevant event fields to a finding).
use std::collections::{BTreeSet, HashMap};

use serde_norway::{Mapping, Value};
use sigma_rust::Rule;

/// A loaded Sigma rule paired with everything Raijin pre-computes about it.
pub struct LoadedSigmaRule {
    pub rule: Rule,
    pub score: i16,
    /// File the rule was loaded from (DEFAIR provenance).
    pub source_file: Option<String>,
    /// EventIDs this rule can match (`None` = not derivable from the
    /// detection block, so the rule is a candidate for every EventID).
    pub event_ids: Option<Vec<u32>>,
    /// Event field names referenced by the detection block, in rule order.
    pub fields: Vec<String>,
    /// `logsource.category` value(s), lowercased and split on `,`.
    categories: Vec<String>,
    /// `logsource.service` value(s), lowercased and split on `,`.
    services: Vec<String>,
}

/// A rule freshly parsed from YAML, before scoring/indexing.
pub struct ParsedSigmaRule {
    pub rule: Rule,
    pub event_ids: Option<Vec<u32>>,
    pub fields: Vec<String>,
    /// File the rule was read from, set by the loader.
    pub source_file: Option<String>,
}

/// Outcome of parsing one YAML document inside a rule file.
pub enum SigmaDocument {
    Rule(ParsedSigmaRule),
    /// Not a detection rule (correlation, collection header, empty
    /// document, ...). Carries a short reason for debug logging.
    Skipped(String),
    /// A detection rule sigma-rust could not parse. Carries the error.
    Error(String),
}

/// Rules indexed by `logsource.product`, then narrowed at match time by
/// EventID (when derivable from the rule) and by `logsource.category` /
/// `service` against the event's own `Channel` (see `rule_is_applicable`).
#[derive(Default)]
pub struct SigmaRuleIndex {
    windows_rules: Vec<LoadedSigmaRule>,
    /// Indexes into `windows_rules` keyed by the EventIDs each rule can
    /// match (rules with a derivable EventID set only).
    windows_by_event_id: HashMap<u32, Vec<usize>>,
    /// Indexes into `windows_rules` for rules whose EventID set couldn't be
    /// derived - always candidates.
    windows_unbucketed: Vec<usize>,
    linux_rules: Vec<LoadedSigmaRule>,
    // Truly product-agnostic rules only: `product: any` or no `product` at
    // all. Evaluated against both Windows and Linux events.
    other_rules: Vec<LoadedSigmaRule>,
    // Rules with an explicit, *specific* product Raijin has no ingestion
    // path for (`zeek`, `aws`, `gcp`, `azure`, `m365`, `okta`, ...). Counted
    // for `total_rule_count()`/load-summary purposes but never evaluated
    // (a `product: zeek` rule's `not <field>` condition matched every single
    // Windows EVTX record once it was wrongly treated as product-agnostic).
    unsupported_product_rules: Vec<LoadedSigmaRule>,
}

/// One acceptable (Channel, EventIDs) combination for a Sigma category.
/// An empty `event_ids` means "any event on this channel".
struct ChannelSpec {
    channel: &'static str,
    event_ids: &'static [u32],
}

macro_rules! spec {
    ($channel:expr) => {
        ChannelSpec { channel: $channel, event_ids: &[] }
    };
    ($channel:expr, $ids:expr) => {
        ChannelSpec { channel: $channel, event_ids: $ids }
    };
}

const SYSMON: &str = "Microsoft-Windows-Sysmon/Operational";
const PS_OPERATIONAL: &str = "Microsoft-Windows-PowerShell/Operational";
const PS_CORE: &str = "PowerShellCore/Operational";
const PS_CLASSIC: &str = "Windows PowerShell";

/// Known Sigma `category` -> acceptable (Channel, EventID) combinations.
/// Mostly Sysmon-backed, using Sysmon's own stable EventID schema. A
/// category not listed here is left unfiltered (permissive per-product
/// routing, further narrowed by the EventID pre-filter) rather than guessed
/// at - no false negatives, just less narrowing for that category.
const CATEGORY_CHANNELS: &[(&str, &[ChannelSpec])] = &[
    ("process_creation", &[spec!(SYSMON, &[1]), spec!("Security", &[4688])]),
    ("process_termination", &[spec!(SYSMON, &[5]), spec!("Security", &[4689])]),
    ("network_connection", &[spec!(SYSMON, &[3])]),
    ("image_load", &[spec!(SYSMON, &[7])]),
    ("file_event", &[spec!(SYSMON, &[11])]),
    ("file_change", &[spec!(SYSMON, &[2])]),
    ("file_delete", &[spec!(SYSMON, &[23, 26])]),
    ("file_delete_detected", &[spec!(SYSMON, &[26])]),
    ("file_block_executable", &[spec!(SYSMON, &[27])]),
    ("file_block_shredding", &[spec!(SYSMON, &[28])]),
    ("file_executable_detected", &[spec!(SYSMON, &[29])]),
    ("file_rename", &[spec!(SYSMON)]),
    ("registry_add", &[spec!(SYSMON, &[12])]),
    ("registry_delete", &[spec!(SYSMON, &[12])]),
    ("registry_event", &[spec!(SYSMON, &[12, 13, 14])]),
    ("registry_set", &[spec!(SYSMON, &[13])]),
    ("registry_rename", &[spec!(SYSMON, &[14])]),
    ("create_remote_thread", &[spec!(SYSMON, &[8])]),
    ("raw_access_thread", &[spec!(SYSMON, &[9])]),
    ("process_access", &[spec!(SYSMON, &[10])]),
    ("process_tampering", &[spec!(SYSMON, &[25])]),
    ("create_stream_hash", &[spec!(SYSMON, &[15])]),
    ("pipe_created", &[spec!(SYSMON, &[17, 18])]),
    ("wmi_event", &[spec!(SYSMON, &[19, 20, 21])]),
    ("dns_query", &[spec!(SYSMON, &[22])]),
    ("driver_load", &[spec!(SYSMON, &[6])]),
    ("sysmon_status", &[spec!(SYSMON, &[4, 16])]),
    ("sysmon_error", &[spec!(SYSMON, &[255])]),
    ("clipboard_capture", &[spec!(SYSMON, &[24])]),
    ("ps_script", &[spec!(PS_OPERATIONAL, &[4104]), spec!(PS_CORE, &[4104])]),
    ("ps_module", &[spec!(PS_OPERATIONAL, &[4103]), spec!(PS_CORE, &[4103])]),
    ("ps_classic_start", &[spec!(PS_CLASSIC, &[400])]),
    ("ps_classic_provider_start", &[spec!(PS_CLASSIC, &[600])]),
    ("ps_classic_script", &[spec!(PS_CLASSIC, &[800])]),
];

/// Known Sigma `service` -> Windows channel(s), following SigmaHQ's own
/// `windows-services` mapping. Checked when the rule has no recognized
/// category. EventIDs are left unrestricted here (a "service" is a whole
/// channel, not one event type); the EventID pre-filter narrows further.
/// A service not listed here falls back to a normalized substring match
/// against the channel name (see `service_matches_channel`).
const SERVICE_CHANNELS: &[(&str, &[&str])] = &[
    ("security", &["Security"]),
    ("system", &["System"]),
    ("application", &["Application"]),
    ("setup", &["Setup"]),
    ("sysmon", &[SYSMON]),
    ("powershell", &[PS_OPERATIONAL, PS_CORE, PS_CLASSIC]),
    ("powershell-classic", &[PS_CLASSIC]),
    ("taskscheduler", &["Microsoft-Windows-TaskScheduler/Operational"]),
    ("wmi", &["Microsoft-Windows-WMI-Activity/Operational"]),
    ("applocker", &[
        "Microsoft-Windows-AppLocker/EXE and DLL",
        "Microsoft-Windows-AppLocker/MSI and Script",
        "Microsoft-Windows-AppLocker/Packaged app-Deployment",
        "Microsoft-Windows-AppLocker/Packaged app-Execution",
    ]),
    ("appmodel-runtime", &["Microsoft-Windows-AppModel-Runtime/Admin"]),
    ("appxdeployment-server", &["Microsoft-Windows-AppXDeploymentServer/Operational"]),
    ("appxpackaging-om", &["Microsoft-Windows-AppxPackaging/Operational"]),
    ("bitlocker", &["Microsoft-Windows-BitLocker/BitLocker Management"]),
    ("bits-client", &["Microsoft-Windows-Bits-Client/Operational"]),
    ("capi2", &["Microsoft-Windows-CAPI2/Operational"]),
    ("certificateservicesclient-lifecycle-system", &["Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational"]),
    ("codeintegrity-operational", &["Microsoft-Windows-CodeIntegrity/Operational"]),
    ("dhcp", &["Microsoft-Windows-DHCP-Server/Operational"]),
    ("diagnosis-scripted", &["Microsoft-Windows-Diagnosis-Scripted/Operational"]),
    ("dns-client", &["Microsoft-Windows-DNS-Client/Operational", "Microsoft-Windows-DNS Client Events/Operational"]),
    ("dns-server", &["DNS Server"]),
    ("dns-server-analytic", &["Microsoft-Windows-DNS-Server/Analytical"]),
    ("dns-server-audit", &["Microsoft-Windows-DNS-Server/Audit"]),
    ("driver-framework", &["Microsoft-Windows-DriverFrameworks-UserMode/Operational"]),
    ("firewall-as", &["Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"]),
    ("hyper-v-worker", &["Microsoft-Windows-Hyper-V-Worker"]),
    ("iis-configuration", &["Microsoft-IIS-Configuration/Operational"]),
    ("kernel-event-tracing", &["Microsoft-Windows-Kernel-EventTracing/Admin"]),
    ("kernel-shimengine", &["Microsoft-Windows-Kernel-ShimEngine/Operational"]),
    ("ldap", &["Microsoft-Windows-LDAP-Client/Debug"]),
    ("ldap_debug", &["Microsoft-Windows-LDAP-Client/Debug"]),
    ("lsa-server", &["Microsoft-Windows-LSA/Operational"]),
    ("microsoft-servicebus-client", &["Microsoft-ServiceBus-Client"]),
    ("msexchange-management", &["MSExchange Management"]),
    ("ntlm", &["Microsoft-Windows-NTLM/Operational"]),
    ("openssh", &["OpenSSH/Operational"]),
    ("printservice", &["Microsoft-Windows-PrintService/Admin", "Microsoft-Windows-PrintService/Operational"]),
    ("printservice-admin", &["Microsoft-Windows-PrintService/Admin"]),
    ("printservice-operational", &["Microsoft-Windows-PrintService/Operational"]),
    ("security-mitigations", &["Microsoft-Windows-Security-Mitigations/KernelMode", "Microsoft-Windows-Security-Mitigations/UserMode"]),
    ("sense", &["Microsoft-Windows-SENSE/Operational"]),
    ("shell-core", &["Microsoft-Windows-Shell-Core/Operational"]),
    ("smbclient-connectivity", &["Microsoft-Windows-SmbClient/Connectivity"]),
    ("smbclient-security", &["Microsoft-Windows-SmbClient/Security"]),
    ("terminalservices-localsessionmanager", &["Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"]),
    ("terminalservices-remoteconnectionmanager", &["Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"]),
    ("terminalservices", &[
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    ]),
    ("vhdmp", &["Microsoft-Windows-VHDMP/Operational"]),
    ("windefend", &["Microsoft-Windows-Windows Defender/Operational"]),
    ("winrm", &["Microsoft-Windows-WinRM/Operational"]),
    ("wmi-activity", &["Microsoft-Windows-WMI-Activity/Operational"]),
];

/// Lowercase alphanumerics only, so `dns-server` and `DNS Server` (or
/// `appxdeployment-server` and `Microsoft-Windows-AppXDeploymentServer/
/// Operational`) compare equal / as substrings.
fn normalize_for_match(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric()).flat_map(|c| c.to_lowercase()).collect()
}

/// Whether Sigma `service` applies to an event from `channel`: the explicit
/// `SERVICE_CHANNELS` table first, then - for a service the table doesn't
/// know - a normalized substring match of the service name inside the
/// channel name. An unknown service that matches no channel this way is
/// treated as not applicable (there's simply no data for it) rather than
/// permissively evaluated against every channel, which is exactly how a
/// `service: security, system` rule keyed on EventID 104 ended up flagging
/// every EventID 104 in an unrelated DFS Replication log.
fn service_matches_channel(service: &str, channel: &str) -> bool {
    if let Some((_, channels)) = SERVICE_CHANNELS.iter().find(|(s, _)| *s == service) {
        return channels.iter().any(|c| c.eq_ignore_ascii_case(channel));
    }
    let needle = normalize_for_match(service);
    if needle.is_empty() {
        return false;
    }
    normalize_for_match(channel).contains(&needle)
}

fn category_specs(category: &str) -> Option<&'static [ChannelSpec]> {
    CATEGORY_CHANNELS.iter().find(|(c, _)| *c == category).map(|(_, specs)| *specs)
}

/// Whether `rule` should even be evaluated against an event from `channel`
/// (and, where the category's mapping is EventID-specific, `event_id`).
/// No channel available at all means "don't filter".
fn rule_is_applicable(loaded: &LoadedSigmaRule, channel: Option<&str>, event_id: Option<u32>) -> bool {
    let Some(channel) = channel else { return true };

    if !loaded.categories.is_empty() {
        let mut any_known = false;
        for category in &loaded.categories {
            if let Some(specs) = category_specs(category) {
                any_known = true;
                let hit = specs.iter().any(|s| {
                    s.channel.eq_ignore_ascii_case(channel)
                        && (s.event_ids.is_empty() || event_id.is_some_and(|id| s.event_ids.contains(&id)))
                });
                if hit {
                    return true;
                }
            }
        }
        if any_known {
            return false;
        }
        // Unknown category: fall through to the service (if any), else
        // permissive.
    }

    if !loaded.services.is_empty() {
        return loaded.services.iter().any(|service| service_matches_channel(service, channel));
    }

    true
}

/// Maps a Sigma rule's `level` to a score on Raijin's 0-100 scale, chosen
/// for consistency with the default thresholds (alert=80, warning=60,
/// notice=40) and YARA's own unscored-rule default of 75.
///
/// `sigma_rust::Level` is not re-exported from the crate root, so it can't
/// be matched on directly; its `Debug` output is stable enough to use.
pub fn level_to_score(rule: &Rule) -> i16 {
    match format!("{:?}", rule.level).as_str() {
        "Some(Critical)" => 100,
        "Some(High)" => 85,
        "Some(Medium)" => 65,
        "Some(Low)" => 40,
        "Some(Informational)" => 20,
        _ => 60,
    }
}

/// Human-readable Sigma level (`critical`, `high`, ...) for finding output.
pub fn level_name(rule: &Rule) -> &'static str {
    match format!("{:?}", rule.level).as_str() {
        "Some(Critical)" => "critical",
        "Some(High)" => "high",
        "Some(Medium)" => "medium",
        "Some(Low)" => "low",
        "Some(Informational)" => "informational",
        _ => "unspecified",
    }
}

fn split_logsource_values(value: Option<&str>) -> Vec<String> {
    value
        .map(|v| {
            v.split(',').map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty() && s != "-").collect()
        })
        .unwrap_or_default()
}

pub fn build_rule_index(rules: Vec<ParsedSigmaRule>) -> SigmaRuleIndex {
    let mut index = SigmaRuleIndex::default();
    for parsed in rules {
        let score = level_to_score(&parsed.rule);
        let categories = split_logsource_values(parsed.rule.logsource.category.as_deref());
        let services = split_logsource_values(parsed.rule.logsource.service.as_deref());
        let loaded = LoadedSigmaRule {
            rule: parsed.rule,
            score,
            source_file: parsed.source_file,
            event_ids: parsed.event_ids,
            fields: parsed.fields,
            categories,
            services,
        };
        match loaded.rule.logsource.product.as_deref().map(|p| p.trim().to_ascii_lowercase()).as_deref() {
            Some("windows") => {
                let idx = index.windows_rules.len();
                match &loaded.event_ids {
                    Some(ids) => {
                        for id in ids {
                            index.windows_by_event_id.entry(*id).or_default().push(idx);
                        }
                    }
                    None => index.windows_unbucketed.push(idx),
                }
                index.windows_rules.push(loaded);
            }
            Some("linux") => index.linux_rules.push(loaded),
            None | Some("any") | Some("") => index.other_rules.push(loaded),
            Some(_) => index.unsupported_product_rules.push(loaded),
        }
    }
    index
}

impl SigmaRuleIndex {
    /// Windows-product rules (plus product-agnostic rules) applicable to an
    /// event from `channel` with `event_id`. Rules with a derivable EventID
    /// set are only returned for their own EventIDs; pass `None` for either
    /// argument when unknown to disable that narrowing.
    pub fn windows_candidates<'a>(
        &'a self,
        channel: Option<&'a str>,
        event_id: Option<u32>,
    ) -> impl Iterator<Item = &'a LoadedSigmaRule> + 'a {
        let bucketed: Box<dyn Iterator<Item = &'a LoadedSigmaRule> + 'a> = match event_id {
            Some(id) => {
                let by_id = self.windows_by_event_id.get(&id).map(|v| v.as_slice()).unwrap_or(&[]);
                Box::new(
                    by_id
                        .iter()
                        .chain(self.windows_unbucketed.iter())
                        .map(move |i| &self.windows_rules[*i]),
                )
            }
            None => Box::new(self.windows_rules.iter()),
        };
        bucketed
            .chain(self.other_rules.iter())
            .filter(move |loaded| rule_is_applicable(loaded, channel, event_id))
    }

    /// All Linux-product rules, plus product-agnostic rules.
    pub fn linux_candidates(&self) -> impl Iterator<Item = &LoadedSigmaRule> {
        self.linux_rules.iter().chain(self.other_rules.iter())
    }

    pub fn total_rule_count(&self) -> usize {
        self.windows_rules.len()
            + self.linux_rules.len()
            + self.other_rules.len()
            + self.unsupported_product_rules.len()
    }

    /// Rules with a specific, non-Windows/Linux/agnostic product (`zeek`,
    /// `aws`, ...) that are loaded but never evaluated.
    pub fn unsupported_product_rule_count(&self) -> usize {
        self.unsupported_product_rules.len()
    }

    /// Windows rules whose EventID set could be derived (and are therefore
    /// only evaluated against records with one of those EventIDs).
    pub fn windows_event_id_indexed_count(&self) -> usize {
        self.windows_rules.len() - self.windows_unbucketed.len()
    }
}

// ---------------------------------------------------------------------------
// YAML loading
// ---------------------------------------------------------------------------

/// Parses every YAML document in a rule file. Never fails as a whole: each
/// document independently becomes a `Rule`, a `Skipped` (with reason) or an
/// `Error` (with the parser message), so a broken document can't take a
/// valid sibling down with it.
/// Upper bound on documents read from a single rule file, as a backstop
/// against a YAML stream that never ends. See `parse_rule_file`.
const MAX_DOCUMENTS_PER_RULE_FILE: usize = 512;

pub fn parse_rule_file(yaml: &str) -> Vec<SigmaDocument> {
    let mut out = Vec::new();
    for document in serde_norway::Deserializer::from_str(yaml) {
        match <Value as serde::Deserialize>::deserialize(document) {
            Ok(value) => out.push(parse_document(value)),
            // Stop at the first failure rather than carrying on through the
            // stream. Once the YAML scanner has lost its place it cannot
            // reliably find the next document boundary, and `serde_norway`
            // can then yield failing documents forever: a real rule in the
            // mdecrevoisier set (`win-os-MinPlasma_CVE-2020-17103 (Reg via
            // Sysmon).yaml`, whose `selection2` key is indented one space
            // instead of two) spun here until a 5 GiB Vec allocation got
            // the process OOM-killed. Anything after a syntax error in the
            // same file was never going to parse into a usable rule anyway.
            Err(e) => {
                out.push(SigmaDocument::Error(e.to_string()));
                break;
            }
        }
        if out.len() >= MAX_DOCUMENTS_PER_RULE_FILE {
            out.push(SigmaDocument::Error(format!(
                "stopped after {} documents - the YAML stream does not terminate",
                MAX_DOCUMENTS_PER_RULE_FILE
            )));
            break;
        }
    }
    if out.is_empty() {
        out.push(SigmaDocument::Skipped("empty file".to_string()));
    }
    out
}

/// Convenience for tests and single-rule callers: the first rule document
/// of `yaml`, or the first error.
#[cfg_attr(not(test), allow(dead_code))]
pub fn parse_rule_yaml(yaml: &str) -> Result<ParsedSigmaRule, String> {
    let mut first_skip = None;
    for doc in parse_rule_file(yaml) {
        match doc {
            SigmaDocument::Rule(r) => return Ok(r),
            SigmaDocument::Error(e) => return Err(e),
            SigmaDocument::Skipped(reason) => first_skip.get_or_insert(reason),
        };
    }
    Err(first_skip.unwrap_or_else(|| "no rule document".to_string()))
}

fn parse_document(mut value: Value) -> SigmaDocument {
    let Value::Mapping(map) = &mut value else {
        return SigmaDocument::Skipped(if value.is_null() { "empty document".into() } else { "not a mapping".into() });
    };
    if map.contains_key("correlation") {
        return SigmaDocument::Skipped("correlation rules are not supported".to_string());
    }
    if map.contains_key("action") && !map.contains_key("detection") {
        return SigmaDocument::Skipped("rule collection header (action) without detection".to_string());
    }
    if !map.contains_key("detection") {
        return SigmaDocument::Skipped("no detection section".to_string());
    }

    if let Some(Value::Mapping(logsource)) = map.get_mut("logsource") {
        normalize_logsource(logsource);
    }

    let (event_ids, fields) = match map.get("detection") {
        Some(detection) => analyze_detection(detection),
        None => (None, Vec::new()),
    };

    match serde_norway::from_value::<Rule>(value) {
        Ok(rule) => SigmaDocument::Rule(ParsedSigmaRule { rule, event_ids, fields, source_file: None }),
        Err(e) => SigmaDocument::Error(e.to_string()),
    }
}

/// `category: [a, b]` -> `category: "a, b"` so sigma-rust (which expects a
/// string) accepts the rule; `split_logsource_values` splits it back.
fn normalize_logsource(logsource: &mut Mapping) {
    for key in ["category", "service", "product"] {
        let Some(current) = logsource.get(key) else { continue };
        let replacement = match current {
            Value::Sequence(items) => {
                let joined: Vec<String> = items.iter().filter_map(scalar_to_string).collect();
                Some(Value::String(joined.join(", ")))
            }
            Value::Null => Some(Value::String(String::new())),
            _ => None,
        };
        if let Some(v) = replacement {
            logsource.insert(Value::String(key.to_string()), v);
        }
    }
}

fn scalar_to_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn value_to_event_ids(v: &Value) -> Vec<u32> {
    fn one(v: &Value) -> Option<u32> {
        match v {
            Value::Number(n) => n.as_u64().and_then(|n| u32::try_from(n).ok()),
            Value::String(s) => s.trim().parse::<u32>().ok(),
            _ => None,
        }
    }
    match v {
        Value::Sequence(items) => items.iter().filter_map(one).collect(),
        other => one(other).into_iter().collect(),
    }
}

/// Per-selection analysis: `Some(ids)` if every field group of the
/// selection constrains `EventID` (without modifiers), else `None`.
struct SelectionInfo {
    event_ids: Option<Vec<u32>>,
}

fn analyze_field_group(
    group: &Mapping,
    fields: &mut Vec<String>,
    seen_fields: &mut BTreeSet<String>,
) -> Option<Vec<u32>> {
    let mut group_ids: Option<Vec<u32>> = None;
    for (key, value) in group {
        let Value::String(key) = key else { continue };
        let mut parts = key.split('|');
        let name = parts.next().unwrap_or("").trim();
        let has_modifiers = parts.next().is_some();
        if !name.is_empty() && seen_fields.insert(name.to_string()) {
            fields.push(name.to_string());
        }
        if name == "EventID" && !has_modifiers {
            let ids = value_to_event_ids(value);
            if !ids.is_empty() {
                group_ids = Some(ids);
            }
        }
    }
    group_ids
}

fn analyze_selection(selection: &Value, fields: &mut Vec<String>, seen_fields: &mut BTreeSet<String>) -> SelectionInfo {
    match selection {
        Value::Mapping(group) => SelectionInfo { event_ids: analyze_field_group(group, fields, seen_fields) },
        Value::Sequence(items) => {
            let mut union: Vec<u32> = Vec::new();
            let mut all_constrained = !items.is_empty();
            for item in items {
                match item {
                    Value::Mapping(group) => match analyze_field_group(group, fields, seen_fields) {
                        Some(ids) => union.extend(ids),
                        None => all_constrained = false,
                    },
                    // keyword list: no field constraint
                    _ => all_constrained = false,
                }
            }
            SelectionInfo { event_ids: if all_constrained { Some(union) } else { None } }
        }
        _ => SelectionInfo { event_ids: None },
    }
}

/// Extracts (possible EventIDs, referenced field names) from a `detection`
/// block. The EventID set is sound (a superset of what can match) or `None`
/// when the condition's shape makes that impossible to guarantee.
fn analyze_detection(detection: &Value) -> (Option<Vec<u32>>, Vec<String>) {
    let Value::Mapping(map) = detection else { return (None, Vec::new()) };

    let mut fields = Vec::new();
    let mut seen_fields = BTreeSet::new();
    let mut selections: HashMap<String, SelectionInfo> = HashMap::new();
    let mut conditions: Vec<String> = Vec::new();

    for (key, value) in map {
        let Value::String(key) = key else { continue };
        match key.as_str() {
            "condition" => match value {
                Value::String(s) => conditions.push(s.clone()),
                Value::Sequence(items) => conditions.extend(items.iter().filter_map(scalar_to_string)),
                _ => {}
            },
            "timeframe" => {}
            _ => {
                selections.insert(key.clone(), analyze_selection(value, &mut fields, &mut seen_fields));
            }
        }
    }

    if conditions.is_empty() {
        return (None, fields);
    }

    let names: Vec<String> = selections.keys().cloned().collect();
    let mut union: BTreeSet<u32> = BTreeSet::new();
    for condition in &conditions {
        let Some(positives) = positive_selection_names(condition, &names) else {
            return (None, fields);
        };
        for name in positives {
            match selections.get(&name).and_then(|info| info.event_ids.as_ref()) {
                Some(ids) => union.extend(ids.iter().copied()),
                None => return (None, fields),
            }
        }
    }

    if union.is_empty() {
        (None, fields)
    } else {
        (Some(union.into_iter().collect()), fields)
    }
}

fn glob_matches(pattern: &str, name: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == name;
    }
    let mut remaining = name;
    let parts: Vec<&str> = pattern.split('*').collect();
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if !remaining.starts_with(part) {
                return false;
            }
            remaining = &remaining[part.len()..];
        } else if i == parts.len() - 1 {
            return remaining.ends_with(part);
        } else {
            match remaining.find(part) {
                Some(pos) => remaining = &remaining[pos + part.len()..],
                None => return false,
            }
        }
    }
    true
}

/// Selection names that must hold for `condition` to be true, or `None`
/// when that can't be determined soundly. Supports the boolean subset of
/// the Sigma condition grammar (`and`, `or`, `not`, parentheses, `1 of
/// X*`, `all of X*`, `... of them`). `not` is only accepted directly after
/// `and` (the ubiquitous `selection and not filter` shape); `X or not Y`
/// and aggregations (`| count()`, `near`) are not derivable.
fn positive_selection_names(condition: &str, names: &[String]) -> Option<Vec<String>> {
    if condition.contains('|') {
        return None;
    }
    let spaced = condition.replace('(', " ").replace(')', " ");
    let tokens: Vec<&str> = spaced.split_whitespace().collect();
    if tokens.is_empty() {
        return None;
    }

    let mut positives: Vec<String> = Vec::new();
    let mut negate = false;
    let mut prev: Option<&str> = None;
    let mut i = 0;
    while i < tokens.len() {
        let tok = tokens[i];
        let lower = tok.to_ascii_lowercase();
        match lower.as_str() {
            "and" | "or" => {
                negate = false;
            }
            "not" => {
                if !matches!(prev.map(|p| p.to_ascii_lowercase()).as_deref(), Some("and")) {
                    return None;
                }
                negate = true;
            }
            "near" => return None,
            "1" | "all" | "any" if i + 2 < tokens.len() && tokens[i + 1].eq_ignore_ascii_case("of") => {
                let target = tokens[i + 2];
                if !negate {
                    if target.eq_ignore_ascii_case("them") {
                        positives.extend(names.iter().cloned());
                    } else {
                        let matched: Vec<String> = names.iter().filter(|n| glob_matches(target, n)).cloned().collect();
                        if matched.is_empty() {
                            return None;
                        }
                        positives.extend(matched);
                    }
                }
                negate = false;
                prev = Some(target);
                i += 3;
                continue;
            }
            _ => {
                if !negate {
                    positives.push(tok.to_string());
                }
                negate = false;
            }
        }
        prev = Some(tok);
        i += 1;
    }

    if positives.is_empty() {
        None
    } else {
        Some(positives)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A YAML scanner error must not leave `parse_rule_file` iterating
    /// forever. This exact shape - a `detection` key indented one space
    /// where its siblings use two - ships in the mdecrevoisier rule set and
    /// grew the result Vec until a 5 GiB allocation OOM-killed the scan.
    #[test]
    fn test_malformed_indentation_does_not_loop_forever() {
        let yaml = concat!(
            "title: Broken Indentation\n",
            "logsource:\n",
            "  product: windows\n",
            "  category: registry_event\n",
            "detection:\n",
            "  selection1:\n",
            "    TargetObject|startswith: x\n",
            " selection2:\n",
            "    TargetObject|contains: y\n",
            "  condition: selection1 or selection2\n",
            "level: high\n",
        );

        let docs = parse_rule_file(yaml);

        // Bounded is the point: without the fix this never returns at all.
        assert!(
            docs.len() <= MAX_DOCUMENTS_PER_RULE_FILE,
            "expected a bounded result, got {} documents",
            docs.len()
        );
        assert!(
            docs.iter().any(|d| matches!(d, SigmaDocument::Error(_))),
            "the malformed document should be reported as an error"
        );
        assert!(
            !docs.iter().any(|d| matches!(d, SigmaDocument::Rule(_))),
            "nothing usable should be salvaged from a file the scanner choked on"
        );
    }

    /// The same rule, correctly indented, still loads - the fix must not
    /// reject valid multi-selection rules.
    #[test]
    fn test_same_rule_correctly_indented_still_parses() {
        let yaml = concat!(
            "title: Fixed Indentation\n",
            "logsource:\n",
            "  product: windows\n",
            "  category: registry_event\n",
            "detection:\n",
            "  selection1:\n",
            "    TargetObject|startswith: x\n",
            "  selection2:\n",
            "    TargetObject|contains: y\n",
            "  condition: selection1 or selection2\n",
            "level: high\n",
        );

        let docs = parse_rule_file(yaml);
        assert_eq!(docs.len(), 1);
        assert!(
            matches!(docs[0], SigmaDocument::Rule(_)),
            "the same rule, correctly indented, must still load - the fix must not \
             reject valid multi-selection rules"
        );
    }

    fn rule_with_level(level: &str) -> Rule {
        let yaml = format!(
            "title: T\nlogsource:\n    product: windows\ndetection:\n    selection:\n        f: v\n    condition: selection\nlevel: {}\n",
            level
        );
        parse_rule_yaml(&yaml).unwrap().rule
    }

    fn load(yaml: &str) -> LoadedSigmaRule {
        let mut index = build_rule_index(vec![parse_rule_yaml(yaml).unwrap()]);
        index
            .windows_rules
            .pop()
            .or_else(|| index.linux_rules.pop())
            .or_else(|| index.other_rules.pop())
            .or_else(|| index.unsupported_product_rules.pop())
            .unwrap()
    }

    #[test]
    fn test_level_to_score_all_variants() {
        assert_eq!(level_to_score(&rule_with_level("critical")), 100);
        assert_eq!(level_to_score(&rule_with_level("high")), 85);
        assert_eq!(level_to_score(&rule_with_level("medium")), 65);
        assert_eq!(level_to_score(&rule_with_level("low")), 40);
        assert_eq!(level_to_score(&rule_with_level("informational")), 20);
        assert_eq!(level_name(&rule_with_level("high")), "high");
    }

    #[test]
    fn test_level_to_score_missing_defaults_to_60() {
        let yaml = "title: T\nlogsource:\n    product: windows\ndetection:\n    selection:\n        f: v\n    condition: selection\n";
        assert_eq!(level_to_score(&parse_rule_yaml(yaml).unwrap().rule), 60);
    }

    const WINDOWS_RULE_YAML: &str = r#"
title: Test Windows Rule
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\cmd.exe'
    condition: selection
level: high
"#;

    const LINUX_RULE_YAML: &str = r#"
title: Test Linux Rule
logsource:
    product: linux
    service: auth
detection:
    selection:
        message|contains: 'Failed password'
    condition: selection
level: medium
"#;

    const UNSCOPED_RULE_YAML: &str = r#"
title: Test Unscoped Rule
logsource:
    category: dns
detection:
    selection:
        query|contains: 'evil.example'
    condition: selection
level: low
"#;

    #[test]
    fn test_build_rule_index_routes_by_product() {
        let rules = vec![
            parse_rule_yaml(WINDOWS_RULE_YAML).unwrap(),
            parse_rule_yaml(LINUX_RULE_YAML).unwrap(),
            parse_rule_yaml(UNSCOPED_RULE_YAML).unwrap(),
        ];
        let index = build_rule_index(rules);
        assert_eq!(index.total_rule_count(), 3);

        let windows: Vec<&LoadedSigmaRule> = index.windows_candidates(None, None).collect();
        assert_eq!(windows.len(), 2);
        assert!(windows.iter().any(|r| r.rule.title == "Test Windows Rule" && r.score == 85));
        assert!(windows.iter().any(|r| r.rule.title == "Test Unscoped Rule"));

        let linux: Vec<&LoadedSigmaRule> = index.linux_candidates().collect();
        assert_eq!(linux.len(), 2);
        assert!(linux.iter().any(|r| r.rule.title == "Test Linux Rule" && r.score == 65));
    }

    const ZEEK_RULE_YAML: &str = r#"
title: Test Zeek Rule
logsource:
    product: zeek
    service: rdp
detection:
    selection:
        id.orig_h|cidr:
            - '10.0.0.0/8'
    condition: not selection
"#;

    #[test]
    fn test_specific_non_windows_linux_product_is_never_evaluated() {
        let index = build_rule_index(vec![parse_rule_yaml(ZEEK_RULE_YAML).unwrap()]);
        assert_eq!(index.total_rule_count(), 1);
        assert_eq!(index.unsupported_product_rule_count(), 1);
        assert!(index.windows_candidates(None, None).next().is_none());
        assert!(index.linux_candidates().next().is_none());
    }

    #[test]
    fn test_parse_rule_yaml_error_is_readable() {
        let err = match parse_rule_yaml("title: broken\nlogsource:\n    product: windows\ndetection:\n    condition: nope\n") {
            Ok(_) => panic!("expected a parse error"),
            Err(e) => e,
        };
        assert!(!err.is_empty());
    }

    #[test]
    fn test_category_rule_only_applies_to_its_channel_and_event_id() {
        let r = load(WINDOWS_RULE_YAML);
        assert!(rule_is_applicable(&r, Some(SYSMON), Some(1)));
        assert!(!rule_is_applicable(&r, Some(SYSMON), Some(3)));
        assert!(rule_is_applicable(&r, Some("Security"), Some(4688)));
        assert!(!rule_is_applicable(&r, Some("Security"), Some(4624)));
        assert!(!rule_is_applicable(&r, Some("System"), Some(1)));
        assert!(rule_is_applicable(&r, None, None));
    }

    #[test]
    fn test_multi_value_service_is_split_and_unknown_service_is_not_permissive() {
        let yaml = r#"
title: Event log cleared
logsource:
    product: windows
    service: security, system
detection:
    selection:
        EventID:
            - 1102
            - 104
    condition: selection
level: high
"#;
        let r = load(yaml);
        assert_eq!(r.services, vec!["security", "system"]);
        assert!(rule_is_applicable(&r, Some("Security"), Some(1102)));
        assert!(rule_is_applicable(&r, Some("System"), Some(104)));
        // The real false-positive flood: EventID 104 in DFS Replication.
        assert!(!rule_is_applicable(&r, Some("DFS Replication"), Some(104)));
        assert_eq!(r.event_ids, Some(vec![104, 1102]));

        let unknown = r#"
title: Unknown service
logsource:
    product: windows
    service: proxy_configuration
detection:
    selection:
        EventID: 5
    condition: selection
"#;
        let u = load(unknown);
        assert!(!rule_is_applicable(&u, Some("Security"), Some(5)));
        assert!(!rule_is_applicable(&u, Some("System"), Some(5)));
    }

    #[test]
    fn test_unknown_service_falls_back_to_normalized_channel_match() {
        let yaml = r#"
title: DNS server
logsource:
    product: windows
    service: dns-server-audit
detection:
    selection:
        EventID: 541
    condition: selection
"#;
        let r = load(yaml);
        assert!(rule_is_applicable(&r, Some("Microsoft-Windows-DNS-Server/Audit"), Some(541)));
        assert!(!rule_is_applicable(&r, Some("Security"), Some(541)));

        let yaml2 = r#"
title: Exchange
logsource:
    product: windows
    service: msexchange-management
detection:
    selection:
        EventID: 1
    condition: selection
"#;
        let r2 = load(yaml2);
        assert!(rule_is_applicable(&r2, Some("MSExchange Management"), Some(1)));
    }

    #[test]
    fn test_list_valued_logsource_category_is_accepted() {
        let yaml = r#"
title: List category
logsource:
    product: windows
    category:
        - process_creation
        - ps_script
detection:
    selection:
        CommandLine|contains: evil
    condition: selection
"#;
        let r = load(yaml);
        assert_eq!(r.categories, vec!["process_creation", "ps_script"]);
        assert!(rule_is_applicable(&r, Some(SYSMON), Some(1)));
        assert!(rule_is_applicable(&r, Some(PS_OPERATIONAL), Some(4104)));
        assert!(!rule_is_applicable(&r, Some("Security"), Some(4624)));
    }

    #[test]
    fn test_multi_document_file_yields_each_rule() {
        let yaml = r#"
title: First
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
    condition: selection
---
title: Second
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
---
title: Correlation
correlation:
    type: event_count
    rules:
        - First
"#;
        let docs = parse_rule_file(yaml);
        assert_eq!(docs.len(), 3);
        assert!(matches!(&docs[0], SigmaDocument::Rule(r) if r.rule.title == "First"));
        assert!(matches!(&docs[1], SigmaDocument::Rule(r) if r.rule.title == "Second"));
        assert!(matches!(&docs[2], SigmaDocument::Skipped(_)));
    }

    #[test]
    fn test_event_id_extraction_shapes() {
        let simple = parse_rule_yaml(
            "title: T\nlogsource:\n    product: windows\n    service: system\ndetection:\n    selection:\n        EventID: 7045\n        ServiceName|contains: x\n    filter:\n        ImagePath|contains: y\n    condition: selection and not filter\n",
        )
        .unwrap();
        assert_eq!(simple.event_ids, Some(vec![7045]));
        assert_eq!(simple.fields, vec!["EventID", "ServiceName", "ImagePath"]);

        let one_of = parse_rule_yaml(
            "title: T\nlogsource:\n    product: windows\n    service: security\ndetection:\n    sel_a:\n        EventID: 4624\n    sel_b:\n        EventID: '4625'\n    condition: 1 of sel_*\n",
        )
        .unwrap();
        assert_eq!(one_of.event_ids, Some(vec![4624, 4625]));

        let or_not = parse_rule_yaml(
            "title: T\nlogsource:\n    product: windows\n    service: security\ndetection:\n    selection:\n        EventID: 4624\n    other:\n        EventID: 4625\n    condition: selection or not other\n",
        )
        .unwrap();
        assert_eq!(or_not.event_ids, None);

        let missing = parse_rule_yaml(
            "title: T\nlogsource:\n    product: windows\n    service: security\ndetection:\n    selection:\n        EventID: 4624\n    other:\n        TargetUserName: bob\n    condition: selection or other\n",
        )
        .unwrap();
        assert_eq!(missing.event_ids, None);

        let list_of_maps = parse_rule_yaml(
            "title: T\nlogsource:\n    product: windows\n    service: security\ndetection:\n    selection:\n        - EventID: 4720\n          TargetUserName: a\n        - EventID: 4722\n    condition: selection\n",
        )
        .unwrap();
        assert_eq!(list_of_maps.event_ids, Some(vec![4720, 4722]));

        let aggregation = parse_rule_yaml(
            "title: T\nlogsource:\n    product: windows\n    service: security\ndetection:\n    selection:\n        EventID: 4625\n    timeframe: 5m\n    condition: selection | count() > 10\n",
        );
        // sigma-rust may or may not accept aggregations; if it does, no
        // EventID narrowing must be derived from a `|` condition.
        if let Ok(r) = aggregation {
            assert_eq!(r.event_ids, None);
        }
    }

    #[test]
    fn test_event_id_index_narrows_candidates() {
        let a = parse_rule_yaml(
            "title: A\nlogsource:\n    product: windows\n    service: system\ndetection:\n    selection:\n        EventID: 7045\n    condition: selection\n",
        )
        .unwrap();
        let b = parse_rule_yaml(
            "title: B\nlogsource:\n    product: windows\n    service: system\ndetection:\n    selection:\n        EventID: 104\n    condition: selection\n",
        )
        .unwrap();
        let c = parse_rule_yaml(
            "title: C\nlogsource:\n    product: windows\n    service: system\ndetection:\n    selection:\n        Provider_Name: LsaSrv\n    condition: selection\n",
        )
        .unwrap();
        let index = build_rule_index(vec![a, b, c]);
        assert_eq!(index.windows_event_id_indexed_count(), 2);

        let titles = |ch: Option<&str>, id: Option<u32>| -> Vec<String> {
            let mut t: Vec<String> = index.windows_candidates(ch, id).map(|r| r.rule.title.clone()).collect();
            t.sort();
            t
        };
        assert_eq!(titles(Some("System"), Some(7045)), vec!["A", "C"]);
        assert_eq!(titles(Some("System"), Some(104)), vec!["B", "C"]);
        assert_eq!(titles(Some("System"), Some(1)), vec!["C"]);
        assert_eq!(titles(Some("System"), None), vec!["A", "B", "C"]);
        assert!(titles(Some("Security"), Some(7045)).is_empty());
    }

    #[test]
    fn test_glob_matches() {
        assert!(glob_matches("filter_*", "filter_main"));
        assert!(glob_matches("selection", "selection"));
        assert!(!glob_matches("filter_*", "selection"));
        assert!(glob_matches("*_main", "filter_main"));
        assert!(glob_matches("sel*ion", "selection"));
    }
}
