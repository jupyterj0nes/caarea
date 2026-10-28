//! Program Compatibility Assistant text logs, Windows 11 22H2 and later
//! (`Windows\appcompat\pca\`):
//!
//! * `PcaAppLaunchDic.txt`: `<path>|<yyyy-MM-dd HH:mm:ss.fff>`, the last launch of each program.
//! * `PcaGeneralDb0.txt` / `PcaGeneralDb1.txt`: `<time>|<type>|<path>|<product>|<company>|
//!   <version>|<program id>|<exit code>`, one line per monitored launch.
//!
//! Times are recorded in UTC.

use std::path::Path;

use super::text::decode_text;
use crate::parsers::evtx::Event;
use crate::utils::normalize_iso;

pub fn is_pca_file(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "pcaapplaunchdic.txt" || (n.starts_with("pcageneraldb") && n.ends_with(".txt"))
}

fn pca_time(s: &str) -> Option<String> {
    let t = s.trim();
    if t.len() < 19 {
        return None;
    }
    normalize_iso(&format!("{}T{}Z", &t[..10], &t[11..]))
}

pub fn parse_text(text: &str, source: &str, computer: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let launch_dic = source.to_ascii_lowercase().starts_with("pcaapplaunchdic");
    for line in text.lines() {
        let line = line.trim_matches(|c: char| c == '\u{feff}' || c.is_whitespace());
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('|').collect();
        let (timestamp, path, details) = if launch_dic {
            if parts.len() < 2 {
                continue;
            }
            let Some(ts) = pca_time(parts[1]) else { continue };
            (ts, parts[0].to_string(), "PCA: last launch".to_string())
        } else {
            if parts.len() < 3 {
                continue;
            }
            let Some(ts) = pca_time(parts[0]) else { continue };
            let kind = match parts[1].trim() {
                "0" => "installer / setup",
                "1" => "application",
                "2" => "driver / abnormal exit",
                "3" => "blocked",
                other => other,
            };
            let rest: Vec<&str> = parts[3..].iter().map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
            let exit = parts.get(7).map(|s| s.trim()).unwrap_or("");
            let mut d = format!("PCA {}: {}", kind, rest.join(" | "));
            if !exit.is_empty() {
                d.push_str(&format!(" | exit {}", exit));
            }
            (ts, parts[2].to_string(), d)
        };
        events.push(Event {
            timestamp,
            computer: computer.to_string(),
            artifact: if launch_dic { "pca:launch".to_string() } else { "pca:general".to_string() },
            event_id: 0,
            pid: 0,
            subject_username: String::new(),
            target_username: String::new(),
            processname: path,
            commandline: Some(details),
            parentprocessname: source.to_string(),
        });
    }
    events
}

pub fn parse_file(path: &Path, computer: &str) -> Vec<Event> {
    let Ok(raw) = std::fs::read(path) else { return Vec::new() };
    let source = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    parse_text(&decode_text(&raw), &source, computer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_files() {
        let dic = "C:\\Tools\\procexp64.exe|2026-10-27 09:01:02.123\r\n";
        let r = parse_text(dic, "PcaAppLaunchDic.txt", "H");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].artifact, "pca:launch");
        assert_eq!(r[0].processname, "C:\\Tools\\procexp64.exe");
        assert_eq!(r[0].timestamp, "2026-10-27T09:01:02.123000Z");

        let gen = "2026-10-27 09:05:00.000|2|C:\\Temp\\x.exe|Tool|ACME|1.0|0006a1b2|0xc0000005\r\n";
        let r = parse_text(gen, "PcaGeneralDb0.txt", "H");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].artifact, "pca:general");
        assert_eq!(r[0].processname, "C:\\Temp\\x.exe");
        assert_eq!(r[0].commandline.as_deref(), Some("PCA driver / abnormal exit: Tool | ACME | 1.0 | 0006a1b2 | 0xc0000005 | exit 0xc0000005"));
    }
}
