//! `RecentFileCache.bcf` (`Windows\AppCompat\Programs`, Windows 7 / Server 2008 R2): the
//! executables run since the last pass of the ProgramDataUpdater task, which then moves
//! them into Amcache. Entries carry no time of their own; every row takes the file's own
//! modification time, an upper bound for the executions it lists.

use std::path::Path;

use super::text::{file_mtime_iso, minus_micros};
use crate::parsers::evtx::Event;

const HEADER_LEN: usize = 0x14;

pub fn is_recentfilecache(name: &str) -> bool {
    name.eq_ignore_ascii_case("RecentFileCache.bcf")
}

/// Paths in file order: `u32` length in UTF-16 units, then the string and its terminator.
pub fn entries(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut pos = HEADER_LEN;
    while pos + 4 <= data.len() {
        let len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        if len == 0 || len > 4096 {
            break;
        }
        let start = pos + 4;
        let end = start + (len + 1) * 2;
        if end > data.len() {
            break;
        }
        let units: Vec<u16> = data[start..start + len * 2].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let s = String::from_utf16_lossy(&units);
        if s.chars().any(|c| c.is_control()) {
            break;
        }
        out.push(s);
        pos = end;
    }
    out
}

pub fn parse_file(path: &Path, computer: &str) -> Vec<Event> {
    let Ok(data) = std::fs::read(path) else { return Vec::new() };
    let mtime = file_mtime_iso(path);
    if mtime.is_empty() {
        return Vec::new();
    }
    let paths = entries(&data);
    let n = paths.len();
    paths
        .into_iter()
        .enumerate()
        .map(|(i, p)| Event {
            timestamp: minus_micros(&mtime, (n - i) as i64),
            computer: computer.to_string(),
            artifact: "recentfilecache".to_string(),
            event_id: 0,
            pid: 0,
            subject_username: String::new(),
            target_username: String::new(),
            processname: p,
            commandline: Some(format!("Executed before {} (RecentFileCache entry {} of {}, file time)", mtime, i + 1, n)),
            parentprocessname: "RecentFileCache.bcf".to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(paths: &[&str]) -> Vec<u8> {
        let mut d = vec![0u8; HEADER_LEN];
        for p in paths {
            let units: Vec<u16> = p.encode_utf16().collect();
            d.extend_from_slice(&(units.len() as u32).to_le_bytes());
            for u in units {
                d.extend_from_slice(&u.to_le_bytes());
            }
            d.extend_from_slice(&[0, 0]);
        }
        d
    }

    #[test]
    fn walks_entries() {
        let d = build(&[r"c:\windows\system32\cmd.exe", r"c:\users\bob\evil.exe"]);
        assert_eq!(entries(&d), vec![r"c:\windows\system32\cmd.exe", r"c:\users\bob\evil.exe"]);
        assert!(entries(&d[..HEADER_LEN + 2]).is_empty());
        assert!(is_recentfilecache("recentfilecache.BCF"));
    }
}
