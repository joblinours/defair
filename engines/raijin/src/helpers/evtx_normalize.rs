/// Flattens the raw JSON produced by `evtx::EvtxParser::records_json_value()`
/// into a flat top-level object matching the bare field names public
/// SigmaHQ Windows rules reference (`EventID`, `Channel`, `Image`,
/// `CommandLine`, ...), the same way Hayabusa/Chainsaw present a record to
/// a Sigma rule.
///
/// What this resolves:
/// - `System.*` XML-attribute wrapping (`#attributes` / `#text`), e.g.
///   `EventID: {"#attributes": {"Qualifiers": 16384}, "#text": 7045}`
///   (classic providers such as Service Control Manager) -> `EventID: 7045`
/// - `EventData` / `UserData` merged to the top level, one wrapper level
///   deep (`UserData.EventXML.{fields}` as used by TerminalServices,
///   Firewall, etc. becomes bare `{fields}`)
/// - arrays of scalars joined into a single newline-separated string, so
///   `Data|contains: HostApplication=` works on classic PowerShell EventID
///   400/403/600 records (`sigma-rust` never matches against sequences)
/// - Security EventID 4688 (process creation) gets Sysmon-style aliases
///   (`Image`, `ParentImage`, `ProcessId`, `ParentProcessId`, `User`, ...)
///   so `category: process_creation` rules written for Sysmon EventID 1
///   also apply to native Windows process auditing
use serde_json::{Map, Value};

/// If `v` is an `{"#text": ...}` wrapper, returns the inner value;
/// otherwise returns `v` unchanged.
fn plain_value(v: &Value) -> Value {
    if let Some(text) = v.get("#text") {
        text.clone()
    } else {
        v.clone()
    }
}

/// Reads `obj["#attributes"][key]`, if present, keeping the original JSON
/// type (string or number).
fn attr_value(obj: &Value, key: &str) -> Option<Value> {
    obj.get("#attributes")?.get(key).cloned()
}

fn insert_if_present(out: &mut Map<String, Value>, key: &str, value: Option<Value>) {
    if let Some(v) = value {
        out.insert(key.to_string(), v);
    }
}

/// Joins an array of scalars into one string ("\n"-separated). Arrays
/// containing non-scalars are left untouched.
fn scalar_array_to_string(items: &[Value]) -> Option<Value> {
    let mut parts: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        match plain_value(item) {
            Value::String(s) => parts.push(s),
            Value::Number(n) => parts.push(n.to_string()),
            Value::Bool(b) => parts.push(b.to_string()),
            Value::Null => parts.push(String::new()),
            _ => return None,
        }
    }
    Some(Value::String(parts.join("\n")))
}

/// Merges the entries of a data object into `out`, resolving `#text`
/// wrappers, flattening arrays of scalars and descending one level into
/// nested wrapper objects (`UserData.EventXML`).
fn merge_data_object(out: &mut Map<String, Value>, data: &Map<String, Value>, depth: u8) {
    for (k, v) in data {
        if k == "#attributes" {
            continue;
        }
        match v {
            Value::Object(inner) => {
                if let Some(text) = inner.get("#text") {
                    out.insert(k.clone(), text.clone());
                } else if depth < 2 {
                    merge_data_object(out, inner, depth + 1);
                } else {
                    out.insert(k.clone(), v.clone());
                }
            }
            Value::Array(items) => match scalar_array_to_string(items) {
                Some(joined) => {
                    out.insert(k.clone(), joined);
                }
                None => {
                    out.insert(k.clone(), v.clone());
                }
            },
            _ => {
                out.insert(k.clone(), v.clone());
            }
        }
    }
}

fn alias(out: &mut Map<String, Value>, from: &str, to: &str) {
    if out.contains_key(to) {
        return;
    }
    if let Some(v) = out.get(from).cloned() {
        out.insert(to.to_string(), v);
    }
}

/// Sysmon-style field aliases for Security 4688 so `process_creation`
/// rules apply to native process-creation auditing as well.
fn add_security_4688_aliases(out: &mut Map<String, Value>) {
    // 4688's own `ProcessId` is the *parent* PID; `NewProcessId` is the
    // created process. Resolve the parent first so the alias below doesn't
    // read an already-overwritten value.
    let parent_pid = out.get("ProcessId").cloned();
    alias(out, "NewProcessName", "Image");
    alias(out, "ParentProcessName", "ParentImage");
    alias(out, "SubjectLogonId", "LogonId");
    alias(out, "MandatoryLabel", "IntegrityLevel");
    if !out.contains_key("ParentProcessId") {
        if let Some(pid) = parent_pid {
            out.insert("ParentProcessId".to_string(), pid);
        }
    }
    if let Some(new_pid) = out.get("NewProcessId").cloned() {
        out.insert("ProcessId".to_string(), new_pid);
    }
    if !out.contains_key("User") {
        let domain = out.get("SubjectDomainName").and_then(|v| v.as_str()).unwrap_or("");
        let user = out.get("SubjectUserName").and_then(|v| v.as_str()).unwrap_or("");
        if !user.is_empty() {
            let value = if domain.is_empty() { user.to_string() } else { format!("{}\\{}", domain, user) };
            out.insert("User".to_string(), Value::String(value));
        }
    }
}

/// Flattens one EVTX record (the full `Event` JSON value) into a flat
/// top-level object. Never fails: unrecognized shapes just pass through
/// best-effort rather than dropping the record.
pub fn flatten_evtx_record(value: &Value) -> Value {
    let Some(event) = value.get("Event") else {
        return value.clone();
    };
    let Some(system) = event.get("System") else {
        return value.clone();
    };

    let mut out = Map::new();

    if let Some(provider) = system.get("Provider") {
        insert_if_present(&mut out, "Provider_Name", attr_value(provider, "Name"));
        insert_if_present(&mut out, "Provider_Guid", attr_value(provider, "Guid"));
        insert_if_present(&mut out, "EventSourceName", attr_value(provider, "EventSourceName"));
    }
    for key in ["EventID", "Version", "Level", "Task", "Opcode", "Keywords", "Channel", "Computer", "EventRecordID"] {
        if let Some(v) = system.get(key) {
            out.insert(key.to_string(), plain_value(v));
        }
    }
    if let Some(time_created) = system.get("TimeCreated") {
        insert_if_present(&mut out, "TimeCreated", attr_value(time_created, "SystemTime"));
    }
    if let Some(execution) = system.get("Execution") {
        insert_if_present(&mut out, "ExecutionProcessID", attr_value(execution, "ProcessID"));
        insert_if_present(&mut out, "ExecutionThreadID", attr_value(execution, "ThreadID"));
    }
    if let Some(correlation) = system.get("Correlation") {
        insert_if_present(&mut out, "ActivityID", attr_value(correlation, "ActivityID"));
        insert_if_present(&mut out, "RelatedActivityID", attr_value(correlation, "RelatedActivityID"));
    }
    if let Some(security) = system.get("Security") {
        insert_if_present(&mut out, "UserID", attr_value(security, "UserID"));
    }

    // EventData/UserData take priority over any same-named System field.
    for data_key in ["EventData", "UserData"] {
        if let Some(Value::Object(data)) = event.get(data_key) {
            merge_data_object(&mut out, data, 0);
        }
    }

    let is_security = out.get("Channel").and_then(|c| c.as_str()).is_some_and(|c| c.eq_ignore_ascii_case("Security"));
    if is_security && out.get("EventID").and_then(|e| e.as_u64()) == Some(4688) {
        add_security_4688_aliases(&mut out);
    }

    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_flatten_system_attrs_and_bare_fields() {
        let raw = json!({
            "Event": {
                "System": {
                    "Provider": {"#attributes": {"Name": "Microsoft-Windows-Sysmon", "Guid": "5770385F"}},
                    "EventID": 1,
                    "Channel": "Microsoft-Windows-Sysmon/Operational",
                    "Computer": "HOST1",
                    "TimeCreated": {"#attributes": {"SystemTime": "2026-01-01T00:00:00Z"}},
                    "Execution": {"#attributes": {"ProcessID": 100, "ThreadID": 200}},
                    "Correlation": null,
                    "Security": {"#attributes": {"UserID": "S-1-5-18"}}
                },
                "EventData": null
            }
        });
        let flat = flatten_evtx_record(&raw);
        assert_eq!(flat["Provider_Name"], "Microsoft-Windows-Sysmon");
        assert_eq!(flat["Provider_Guid"], "5770385F");
        assert_eq!(flat["EventID"], 1);
        assert_eq!(flat["Channel"], "Microsoft-Windows-Sysmon/Operational");
        assert_eq!(flat["Computer"], "HOST1");
        assert_eq!(flat["TimeCreated"], "2026-01-01T00:00:00Z");
        assert_eq!(flat["ExecutionProcessID"], 100);
        assert_eq!(flat["ExecutionThreadID"], 200);
        assert_eq!(flat["UserID"], "S-1-5-18");
        assert!(flat.get("ActivityID").is_none());
    }

    #[test]
    fn test_flatten_qualified_event_id() {
        let raw = json!({
            "Event": {
                "System": {
                    "EventID": {"#attributes": {"Qualifiers": 16384}, "#text": 7045},
                    "Channel": "System"
                },
                "EventData": {"ServiceName": "evil", "ImagePath": "C:\\evil.exe"}
            }
        });
        let flat = flatten_evtx_record(&raw);
        assert_eq!(flat["EventID"], 7045);
        assert_eq!(flat["ServiceName"], "evil");
    }

    #[test]
    fn test_flatten_merges_flat_eventdata() {
        let raw = json!({
            "Event": {
                "System": {"EventID": 1, "Channel": "Security"},
                "EventData": {"Image": "C:\\Windows\\PING.EXE", "CommandLine": "ping -n 6 127.0.0.1"}
            }
        });
        let flat = flatten_evtx_record(&raw);
        assert_eq!(flat["Image"], "C:\\Windows\\PING.EXE");
        assert_eq!(flat["CommandLine"], "ping -n 6 127.0.0.1");
        assert_eq!(flat["EventID"], 1);
    }

    #[test]
    fn test_flatten_joins_scalar_arrays() {
        let raw = json!({
            "Event": {
                "System": {"EventID": 400, "Channel": "Windows PowerShell"},
                "EventData": {"Data": ["Available", "None", "NewEngineState=Available\n\tHostApplication=C:\\evil\\pwsh.exe -enc AAAA"], "Binary": null}
            }
        });
        let flat = flatten_evtx_record(&raw);
        let data = flat["Data"].as_str().unwrap();
        assert!(data.contains("HostApplication=C:\\evil\\pwsh.exe"));
        assert!(data.starts_with("Available\nNone\n"));
    }

    #[test]
    fn test_flatten_descends_into_userdata_wrapper() {
        let raw = json!({
            "Event": {
                "System": {"EventID": 21, "Channel": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"},
                "UserData": {"EventXML": {"#attributes": {"xmlns": "Event_NS"}, "User": "DOM\\bob", "SessionID": 2, "Address": "10.0.0.5"}}
            }
        });
        let flat = flatten_evtx_record(&raw);
        assert_eq!(flat["User"], "DOM\\bob");
        assert_eq!(flat["Address"], "10.0.0.5");
        assert!(flat.get("EventXML").is_none());
    }

    #[test]
    fn test_flatten_adds_sysmon_aliases_for_security_4688() {
        let raw = json!({
            "Event": {
                "System": {"EventID": 4688, "Channel": "Security"},
                "EventData": {
                    "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                    "NewProcessId": "0x1a4",
                    "ProcessId": "0x100",
                    "ParentProcessName": "C:\\Windows\\explorer.exe",
                    "CommandLine": "cmd.exe /c whoami",
                    "SubjectUserName": "bob",
                    "SubjectDomainName": "DOM",
                    "SubjectLogonId": "0x3e7"
                }
            }
        });
        let flat = flatten_evtx_record(&raw);
        assert_eq!(flat["Image"], "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(flat["ParentImage"], "C:\\Windows\\explorer.exe");
        assert_eq!(flat["ProcessId"], "0x1a4");
        assert_eq!(flat["ParentProcessId"], "0x100");
        assert_eq!(flat["User"], "DOM\\bob");
        assert_eq!(flat["LogonId"], "0x3e7");
        assert_eq!(flat["CommandLine"], "cmd.exe /c whoami");
    }

    #[test]
    fn test_flatten_handles_null_eventdata() {
        let raw = json!({
            "Event": {
                "System": {"EventID": 4608, "Channel": "Security"},
                "EventData": null
            }
        });
        let flat = flatten_evtx_record(&raw);
        assert_eq!(flat["EventID"], 4608);
        assert!(flat.get("Image").is_none());
    }

    #[test]
    fn test_flatten_falls_back_on_unrecognized_shape() {
        let raw = json!({"not_an_event": true});
        let flat = flatten_evtx_record(&raw);
        assert_eq!(flat, raw);
    }
}
