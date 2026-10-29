//! utmp-format login records: `/var/log/wtmp` (logins, logouts, boots), `/var/log/btmp`
//! (failed logins), `/var/run/utmp` (current sessions). 384-byte `struct utmp` records of
//! glibc, little or big endian. Sessions are not executions, but they place a user on the
//! console or pts where the executions happened.

use std::path::Path;

use crate::parsers::evtx::Event;
use crate::utils::epoch_to_iso;

const RECORD: usize = 384;
const USER_PROCESS: i32 = 7;
const DEAD_PROCESS: i32 = 8;
const BOOT_TIME: i32 = 2;
const LOGIN_PROCESS: i32 = 6;
const RUN_LVL: i32 = 1;

pub fn is_utmp_file(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "wtmp" || n == "btmp" || n == "utmp" || n.starts_with("wtmp.") || n.starts_with("btmp.") || n.starts_with("wtmp-") || n.starts_with("btmp-")
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).trim().to_string()
}

fn i32_at(b: &[u8], off: usize, big: bool) -> i32 {
    let a: [u8; 4] = b[off..off + 4].try_into().unwrap();
    if big {
        i32::from_be_bytes(a)
    } else {
        i32::from_le_bytes(a)
    }
}

/// Byte order guess: the type field of real records is tiny (0..=9).
fn detect_big_endian(data: &[u8]) -> bool {
    let le = i32::from_le_bytes(data[0..4].try_into().unwrap());
    let be = i32::from_be_bytes(data[0..4].try_into().unwrap());
    !(0..=9).contains(&le) && (0..=9).contains(&be)
}

pub fn parse_file(path: &Path, computer: &str) -> Vec<Event> {
    let Ok(data) = std::fs::read(path) else { return Vec::new() };
    if data.len() < RECORD {
        return Vec::new();
    }
    let name = path.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    let failed_log = name.starts_with("btmp");
    let big = detect_big_endian(&data);
    let mut events = Vec::new();
    for rec in data.chunks_exact(RECORD) {
        let ut_type = i32_at(rec, 0, big);
        let pid = i32_at(rec, 4, big).max(0) as u32;
        let line = cstr(&rec[8..40]);
        let user = cstr(&rec[44..76]);
        let host = cstr(&rec[76..332]);
        let secs = i32_at(rec, 340, big) as i64;
        let usec = i32_at(rec, 344, big).max(0) as u32;
        if secs <= 0 {
            continue;
        }
        let Some(ts) = epoch_to_iso(secs, usec * 1000) else { continue };
        let (artifact, what) = match ut_type {
            USER_PROCESS if failed_log => ("linux:utmp:failed_login", "Failed login"),
            LOGIN_PROCESS if failed_log => ("linux:utmp:failed_login", "Failed login"),
            USER_PROCESS => ("linux:utmp:login", "Login"),
            DEAD_PROCESS => ("linux:utmp:logout", "Logout"),
            BOOT_TIME => ("linux:utmp:boot", "System boot"),
            RUN_LVL => ("linux:utmp:runlevel", "Run level change"),
            _ => continue,
        };
        if ut_type == DEAD_PROCESS && user.is_empty() && line.is_empty() {
            continue;
        }
        let mut details = format!("{}: {}", what, if user.is_empty() { "(no user)" } else { &user });
        if !line.is_empty() {
            details.push_str(&format!(" on {}", line));
        }
        if !host.is_empty() {
            details.push_str(&format!(" from {}", host));
        }
        events.push(Event {
            timestamp: ts,
            computer: computer.to_string(),
            artifact: artifact.to_string(),
            event_id: 0,
            pid,
            subject_username: user.clone(),
            target_username: String::new(),
            processname: if line.is_empty() { "login".to_string() } else { line.clone() },
            commandline: Some(details),
            parentprocessname: name.clone(),
        });
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(ut_type: i32, pid: i32, line: &str, user: &str, host: &str, secs: i32) -> Vec<u8> {
        let mut r = vec![0u8; RECORD];
        r[0..4].copy_from_slice(&ut_type.to_le_bytes());
        r[4..8].copy_from_slice(&pid.to_le_bytes());
        r[8..8 + line.len()].copy_from_slice(line.as_bytes());
        r[44..44 + user.len()].copy_from_slice(user.as_bytes());
        r[76..76 + host.len()].copy_from_slice(host.as_bytes());
        r[340..344].copy_from_slice(&secs.to_le_bytes());
        r
    }

    #[test]
    fn parses_wtmp_and_btmp() {
        let dir = std::env::temp_dir().join(format!("caarea_utmp_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut data = record(BOOT_TIME, 0, "~", "reboot", "5.15.0", 1710766331);
        data.extend(record(USER_PROCESS, 1234, "pts/0", "alice", "10.0.0.5", 1710766400));
        data.extend(record(DEAD_PROCESS, 1234, "pts/0", "", "", 1710766500));
        std::fs::write(dir.join("wtmp"), &data).unwrap();
        let rows = parse_file(&dir.join("wtmp"), "H");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].artifact, "linux:utmp:boot");
        assert_eq!(rows[1].artifact, "linux:utmp:login");
        assert_eq!(rows[1].subject_username, "alice");
        assert_eq!(rows[1].timestamp, "2024-03-18T12:53:20.000000Z");
        assert_eq!(rows[2].artifact, "linux:utmp:logout");
        std::fs::write(dir.join("btmp"), record(USER_PROCESS, 99, "ssh:notty", "root", "1.2.3.4", 1710766600)).unwrap();
        let b = parse_file(&dir.join("btmp"), "H");
        assert_eq!(b[0].artifact, "linux:utmp:failed_login");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
