/// Line parsers turning plain-text Linux log lines into Sigma-evaluable JSON
/// events. Scoped to v1: RFC3164-ish BSD syslog lines (auth.log/syslog/...)
/// and auditd's `type=... msg=audit(...): key=value ...` format — the two
/// realistic Linux log shapes for a cold/offline scan. See the plan's notes
/// on why auditd is where the real SigmaHQ `product: linux` coverage is.
use regex::Regex;
use serde_json::{json, Map, Value};
use std::sync::OnceLock;

fn syslog_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<program>[^:\[\s]+)(\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$",
        )
        .unwrap()
    })
}

/// Parses one RFC3164-ish BSD syslog line (`auth.log`, `syslog`, `secure`,
/// `messages`, `kern.log`, `daemon.log`, `user.log`). Note: RFC3164 has no
/// year field, so `timestamp` is the raw "Mon Day HH:MM:SS" text as it
/// appears in the log — reconstructing an absolute date is the caller's
/// responsibility (best done from the file's own mtime year, since "now" is
/// meaningless for a forensic collection).
pub fn parse_syslog_line(line: &str) -> Option<Value> {
    let caps = syslog_regex().captures(line.trim_end())?;
    let mut obj = Map::new();
    obj.insert("host".to_string(), json!(&caps["host"]));
    obj.insert("timestamp".to_string(), json!(format!("{} {} {}", &caps["mon"], &caps["day"], &caps["time"])));
    obj.insert("program".to_string(), json!(&caps["program"]));
    if let Some(pid) = caps.name("pid") {
        obj.insert("pid".to_string(), json!(pid.as_str()));
    }
    obj.insert("message".to_string(), json!(&caps["message"]));
    Some(Value::Object(obj))
}

fn auditd_header_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^type=(?P<type>\S+)\s+msg=audit\((?P<epoch>[0-9.]+):(?P<serial>[0-9]+)\):\s*(?P<rest>.*)$").unwrap()
    })
}

fn kv_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"([A-Za-z0-9_]+)=("[^"]*"|\S+)"#).unwrap())
}

/// Parses one auditd line (`audit.log`): `type=SYSCALL msg=audit(epoch:serial): key=value ...`.
/// Maps directly onto what most SigmaHQ `product: linux, service: auditd`
/// rules target (structured key=value fields) — the strongest, most direct
/// mapping among the Linux log formats supported in v1.
pub fn parse_auditd_line(line: &str) -> Option<Value> {
    let caps = auditd_header_regex().captures(line.trim())?;
    let mut obj = Map::new();
    obj.insert("type".to_string(), json!(&caps["type"]));
    obj.insert("audit_epoch".to_string(), json!(&caps["epoch"]));
    obj.insert("audit_serial".to_string(), json!(&caps["serial"]));
    for cap in kv_regex().captures_iter(&caps["rest"]) {
        let key = cap[1].to_string();
        let mut value = cap[2].to_string();
        if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
            value = value[1..value.len() - 1].to_string();
        }
        obj.insert(key, json!(value));
    }
    Some(Value::Object(obj))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_syslog_line_with_pid() {
        let line = "Jan 15 10:23:45 host1 sshd[1234]: Failed password for root from 10.0.0.1 port 22";
        let event = parse_syslog_line(line).unwrap();
        assert_eq!(event["host"], "host1");
        assert_eq!(event["program"], "sshd");
        assert_eq!(event["pid"], "1234");
        assert_eq!(event["timestamp"], "Jan 15 10:23:45");
        assert_eq!(event["message"], "Failed password for root from 10.0.0.1 port 22");
    }

    #[test]
    fn test_parse_syslog_line_without_pid() {
        let line = "Jan 15 10:23:45 host1 kernel: some kernel message";
        let event = parse_syslog_line(line).unwrap();
        assert_eq!(event["program"], "kernel");
        assert!(event.get("pid").is_none());
        assert_eq!(event["message"], "some kernel message");
    }

    #[test]
    fn test_parse_syslog_line_malformed_returns_none() {
        assert!(parse_syslog_line("not a syslog line at all").is_none());
        assert!(parse_syslog_line("").is_none());
    }

    #[test]
    fn test_parse_auditd_line_basic_kv() {
        let line = "type=SYSCALL msg=audit(1699999999.123:456): arch=c000003e syscall=59 success=yes exe=\"/bin/bash\"";
        let event = parse_auditd_line(line).unwrap();
        assert_eq!(event["type"], "SYSCALL");
        assert_eq!(event["syscall"], "59");
        assert_eq!(event["success"], "yes");
        assert_eq!(event["exe"], "/bin/bash");
    }

    #[test]
    fn test_parse_auditd_line_quoted_value_with_spaces() {
        let line = r#"type=EXECVE msg=audit(1699999999.123:456): a0="/bin/ls" a1="-l a" cmd="ls -l a""#;
        let event = parse_auditd_line(line).unwrap();
        assert_eq!(event["a1"], "-l a");
        assert_eq!(event["cmd"], "ls -l a");
    }

    #[test]
    fn test_parse_auditd_line_msg_audit_prefix_extracted() {
        let line = "type=SYSCALL msg=audit(1699999999.123:456): key=rootcmds";
        let event = parse_auditd_line(line).unwrap();
        assert_eq!(event["audit_epoch"], "1699999999.123");
        assert_eq!(event["audit_serial"], "456");
        assert_eq!(event["key"], "rootcmds");
    }

    #[test]
    fn test_parse_auditd_line_not_auditd_returns_none() {
        assert!(parse_auditd_line("Jan 15 10:23:45 host1 sshd[1234]: Failed password").is_none());
    }
}
