//! systemd journal files (`/var/log/journal/<machine-id>/*.journal`, `*.journal~`).
//!
//! On Fedora, RHEL 8 and later, Arch and Debian 12 there is no rsyslog by default: sudo,
//! cron, su, pkexec and unit starts only exist here. The reader is pure Rust (zstd and
//! compact journals supported). Rows:
//!
//! * `linux:journal:sudo`, `su`, `pkexec`, `cron`: the command lines these tools log
//! * `linux:journal:systemd_started`: units started by systemd (system and user managers)
//! * `linux:journal:process`: the first message of every (PID, command line) pair, from the
//!   trusted `_PID` / `_CMDLINE` fields: a process-start approximation for anything that logged

use std::collections::HashSet;
use std::fs::File;
use std::path::Path;

use crate::parsers::evtx::Event;
use crate::utils::epoch_to_iso;

pub fn is_journal_file(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with(".journal") || n.ends_with(".journal~")
}

fn field(entry: &systemd_journal_reader::Entry, key: &str) -> Option<String> {
    entry.fields.get(key).map(|v| v.to_string())
}

/// `KEY=value` pairs inside a sudo/pkexec message (`TTY=pts/0 ; PWD=/home/x ; USER=root ; COMMAND=/usr/bin/id`).
fn kv<'a>(msg: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("{}=", key);
    let start = msg.find(&needle)? + needle.len();
    let rest = &msg[start..];
    let end = rest.find(" ; ").or_else(|| rest.find(']')).unwrap_or(rest.len());
    Some(rest[..end].trim())
}

fn first_token(cmd: &str) -> String {
    cmd.split_whitespace().next().unwrap_or("").trim_matches('"').to_string()
}

pub fn parse_file(path: &Path, computer_hint: &str) -> Vec<Event> {
    let Ok(file) = File::open(path) else { return Vec::new() };
    let debug = std::env::var_os("CAAREA_DEBUG_JOURNAL").is_some();
    let mut reader = match systemd_journal_reader::JournalReader::new(file) {
        Ok(r) => r,
        Err(e) => {
            if debug {
                eprintln!("[journal] {}: open failed: {}", path.display(), e);
            }
            return Vec::new();
        }
    };
    let source = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let mut events = Vec::new();
    let mut seen_processes: HashSet<(u32, String)> = HashSet::new();
    let mut entries = 0usize;
    // kernel audit records journald received on its audit socket (no auditd running):
    // rebuilt as audit.log lines and assembled by the audit parser
    let mut audit_lines: Vec<String> = Vec::new();
    let mut audit_host = computer_hint.to_string();

    while let Some(entry) = reader.next_entry() {
        entries += 1;
        if debug && entries <= 3 {
            eprintln!("[journal] entry realtime={} fields={:?}", entry.realtime, entry.fields.keys().collect::<Vec<_>>());
        }
        if field(&entry, "_TRANSPORT").as_deref() == Some("audit") {
            if let (Some(kind), Some(id), Some(msg)) = (field(&entry, "_AUDIT_TYPE_NAME"), field(&entry, "_AUDIT_ID"), field(&entry, "MESSAGE")) {
                let micros = field(&entry, "_SOURCE_REALTIME_TIMESTAMP").and_then(|s| s.parse::<u64>().ok()).unwrap_or(entry.realtime);
                audit_lines.push(format!("type={} msg=audit({}.{:03}:{}): {}", kind, micros / 1_000_000, (micros % 1_000_000) / 1000, id, msg));
                if let Some(h) = field(&entry, "_HOSTNAME") {
                    audit_host = h;
                }
            }
            continue;
        }
        let secs = (entry.realtime / 1_000_000) as i64;
        let nanos = ((entry.realtime % 1_000_000) * 1_000) as u32;
        let Some(ts) = epoch_to_iso(secs, nanos) else { continue };
        let host = field(&entry, "_HOSTNAME").filter(|h| !h.is_empty()).unwrap_or_else(|| computer_hint.to_string());
        let comm = field(&entry, "_COMM").unwrap_or_default();
        let ident = field(&entry, "SYSLOG_IDENTIFIER").unwrap_or_default();
        let pid: u32 = field(&entry, "_PID").or_else(|| field(&entry, "SYSLOG_PID")).and_then(|p| p.trim().parse().ok()).unwrap_or(0);
        let uid = field(&entry, "_UID").unwrap_or_default();
        let msg = field(&entry, "MESSAGE").unwrap_or_default();
        let who = |e: &systemd_journal_reader::Entry| field(e, "SUDO_USER").unwrap_or_else(|| uid.clone());

        let mk = |ts: String, artifact: &str, subject: String, target: String, proc: String, cmd: String, parent: String| Event {
            timestamp: ts,
            computer: host.clone(),
            artifact: artifact.to_string(),
            event_id: 0,
            pid,
            subject_username: subject,
            target_username: target,
            processname: proc,
            commandline: Some(cmd),
            parentprocessname: parent,
        };

        let tool = if comm.is_empty() { ident.as_str() } else { comm.as_str() };
        match tool {
            "sudo" if msg.contains("COMMAND=") => {
                // "<user> : TTY=pts/0 ; PWD=/home/u ; USER=root ; COMMAND=/usr/bin/id -u"
                let user = msg.split(" : ").next().map(|s| s.trim().to_string()).unwrap_or_else(|| who(&entry));
                let command = kv(&msg, "COMMAND").unwrap_or("").to_string();
                let target = kv(&msg, "USER").unwrap_or("root").to_string();
                let pwd = kv(&msg, "PWD").unwrap_or("");
                events.push(mk(ts, "linux:journal:sudo", user, target, first_token(&command), format!("{} (CWD: {})", command, pwd), format!("{} [{}]", source, "sudo")));
                continue;
            }
            "pkexec" if msg.contains("COMMAND=") => {
                let user = msg.split(':').next().map(|s| s.trim().to_string()).unwrap_or_default();
                let command = kv(&msg, "COMMAND").unwrap_or("").to_string();
                let target = kv(&msg, "USER").unwrap_or("root").to_string();
                events.push(mk(ts, "linux:journal:pkexec", user, target, first_token(&command), command, format!("{} [pkexec]", source)));
                continue;
            }
            "su" | "su-l" if msg.contains("(to ") => {
                // "(to root) alice on pts/1"
                let target = msg.split("(to ").nth(1).and_then(|s| s.split(')').next()).unwrap_or("").to_string();
                let user = msg.split(") ").nth(1).and_then(|s| s.split_whitespace().next()).unwrap_or("").to_string();
                events.push(mk(ts, "linux:journal:su", user, target, "su".to_string(), msg.clone(), format!("{} [su]", source)));
                continue;
            }
            "CRON" | "cron" | "crond" if msg.contains(" CMD (") => {
                // "(root) CMD (/usr/bin/x)"
                let user = msg.trim_start_matches('(').split(')').next().unwrap_or("").to_string();
                let command = msg.split(" CMD (").nth(1).map(|s| s.trim_end_matches(')').to_string()).unwrap_or_default();
                events.push(mk(ts, "linux:journal:cron", user.clone(), user, first_token(&command), command, format!("{} [cron]", source)));
                continue;
            }
            "systemd" if msg.starts_with("Started ") || msg.starts_with("Starting ") => {
                let unit = msg.trim_start_matches("Started ").trim_start_matches("Starting ").trim_end_matches("...").trim().to_string();
                let manager = if uid == "0" || uid.is_empty() { "systemd (system)".to_string() } else { format!("systemd (user {})", uid) };
                if msg.starts_with("Started ") {
                    events.push(mk(ts, "linux:journal:systemd_started", uid.clone(), String::new(), unit, msg.clone(), manager));
                }
                continue;
            }
            _ => {}
        }

        // First sighting of a (pid, command line) pair: the process existed at least from here on
        if let Some(cmdline) = field(&entry, "_CMDLINE").filter(|c| !c.trim().is_empty()) {
            if pid != 0 && seen_processes.insert((pid, cmdline.clone())) {
                let exe = field(&entry, "_EXE").unwrap_or_else(|| first_token(&cmdline));
                events.push(mk(ts, "linux:journal:process", uid.clone(), String::new(), exe, format!("{} (first message: {})", cmdline, msg.chars().take(120).collect::<String>()), source.clone()));
            }
        }
    }
    if !audit_lines.is_empty() {
        let from_audit = crate::parsers::linux::audit::parse_audit_lines(audit_lines.into_iter(), &audit_host);
        events.extend(from_audit.into_iter().map(|mut e| {
            e.parentprocessname = format!("{} (journal audit transport)", e.parentprocessname);
            e
        }));
    }
    if debug {
        eprintln!("[journal] {}: {} entries read, {} rows", path.display(), entries, events.len());
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sudo_fields_are_split() {
        let msg = "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id -u";
        assert_eq!(kv(msg, "COMMAND"), Some("/usr/bin/id -u"));
        assert_eq!(kv(msg, "USER"), Some("root"));
        assert_eq!(kv(msg, "PWD"), Some("/home/alice"));
        assert_eq!(first_token("/usr/bin/id -u"), "/usr/bin/id");
        assert!(is_journal_file("system@0005f1b2-0000.journal~"));
        assert!(!is_journal_file("syslog"));
    }
}
