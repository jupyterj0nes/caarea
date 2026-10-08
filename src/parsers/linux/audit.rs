use chrono::DateTime;
use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::parsers::evtx::Event;

/// Decodes hex-encoded audit commands (e.g. "63617420..." -> "cat /etc/ssh/sshd_config")
fn decode_audit_cmd(raw: &str) -> String {
    let clean = raw.trim_matches(&['\'', '"'][..]);
    if clean.len() >= 2 && clean.len() % 2 == 0 && clean.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut bytes = Vec::with_capacity(clean.len() / 2);
        for chunk in clean.as_bytes().chunks(2) {
            if let Ok(s) = std::str::from_utf8(chunk) {
                if let Ok(b) = u8::from_str_radix(s, 16) {
                    bytes.push(b);
                }
            }
        }
        if let Ok(utf8) = String::from_utf8(bytes) {
            return utf8;
        }
    }
    clean.to_string()
}

/// Parses an audit.log file for execution records (USER_CMD, EXECVE, SYSCALL)
pub fn parse_audit_log(file_path: &Path, computer_name: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return events,
    };

    let user_cmd_re = match Regex::new(
        r"type=USER_CMD\s+msg=audit\((\d+)\.(\d+):\d+\):\s+user\s+pid=(\d+)\s+uid=(\d+)\s+auid=(\d+)(?:.*cwd=([^ ]+))?(?:.*cmd=([^ ']+|'[^']+'))",
    ) {
        Ok(r) => r,
        Err(_) => return events,
    };

    let syscall_re = match Regex::new(
        r#"type=SYSCALL\s+msg=audit\((\d+)\.(\d+):\d+\):.*syscall=(?:59|execve).*pid=(\d+)\s+ppid=(\d+).*auid=(\d+)\s+uid=(\d+).*exe="([^"]+)""#,
    ) {
        Ok(r) => r,
        Err(_) => return events,
    };

    let reader = BufReader::new(file);

    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => continue,
        };

        // 1. Check type=USER_CMD
        if line.contains("type=USER_CMD") {
            if let Some(caps) = user_cmd_re.captures(&line) {
                let secs: i64 = caps[1].parse().unwrap_or(0);
                let msecs: u32 = caps[2].parse().unwrap_or(0);
                let pid: u32 = caps[3].parse().unwrap_or(0);
                let uid = caps[4].to_string();
                let auid = caps[5].to_string();
                let cwd = caps.get(6).map(|m| m.as_str()).unwrap_or("N/A");
                let raw_cmd = caps.get(7).map(|m| m.as_str()).unwrap_or("");

                let decoded_cmd = decode_audit_cmd(raw_cmd);
                let proc_name = decoded_cmd.split_whitespace().next().unwrap_or(&decoded_cmd).to_string();

                let nsecs = msecs * 1_000_000;
                let iso_ts = match DateTime::from_timestamp(secs, nsecs) {
                    Some(dt) => dt.to_rfc3339(),
                    None => continue,
                };

                let user_label = if auid != "4294967295" && !auid.is_empty() {
                    auid
                } else {
                    uid
                };

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
            continue;
        }

        // 2. Check type=SYSCALL (execve)
        if line.contains("type=SYSCALL") && (line.contains("syscall=59") || line.contains("syscall=execve")) {
            if let Some(caps) = syscall_re.captures(&line) {
                let secs: i64 = caps[1].parse().unwrap_or(0);
                let msecs: u32 = caps[2].parse().unwrap_or(0);
                let pid: u32 = caps[3].parse().unwrap_or(0);
                let ppid: u32 = caps[4].parse().unwrap_or(0);
                let auid = caps[5].to_string();
                let uid = caps[6].to_string();
                let exe = caps[7].to_string();

                let nsecs = msecs * 1_000_000;
                let iso_ts = match DateTime::from_timestamp(secs, nsecs) {
                    Some(dt) => dt.to_rfc3339(),
                    None => continue,
                };

                let user_label = if auid != "4294967295" && !auid.is_empty() {
                    auid
                } else {
                    uid
                };

                events.push(Event {
                    timestamp: iso_ts,
                    computer: computer_name.to_string(),
                    artifact: "linux:audit:execve".to_string(),
                    event_id: 0,
                    pid,
                    subject_username: user_label.clone(),
                    target_username: user_label,
                    processname: exe.clone(),
                    commandline: Some(format!("Executed: {} (PPID: {})", exe, ppid)),
                    parentprocessname: format!("PID: {}", ppid),
                });
            }
        }
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
    }
}
