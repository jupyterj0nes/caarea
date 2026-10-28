//! PowerShell console history (`PSReadLine\ConsoleHost_history.txt`): every command typed
//! in an interactive PowerShell session, one per line, oldest first. The file carries no
//! per-line time: rows take the file's modification time, decremented one microsecond per
//! earlier line so the order survives sorting.

use std::path::Path;

use super::text::{decode_text, file_mtime_iso, minus_micros, user_from_path};
use crate::parsers::evtx::Event;

pub fn is_history_file(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "consolehost_history.txt" || (n.ends_with("_history.txt") && n.contains("host"))
}

pub fn parse_file(path: &Path, computer: &str) -> Vec<Event> {
    let Ok(raw) = std::fs::read(path) else { return Vec::new() };
    let text = decode_text(&raw);
    let lines: Vec<&str> = text.lines().map(|l| l.trim_end()).filter(|l| !l.trim().is_empty()).collect();
    if lines.is_empty() {
        return Vec::new();
    }
    let mtime = file_mtime_iso(path);
    if mtime.is_empty() {
        return Vec::new();
    }
    let user = user_from_path(path);
    let source = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let n = lines.len() as i64;
    lines
        .iter()
        .enumerate()
        .map(|(i, line)| {
            // first token, skipping the call operator; quoted paths with spaces keep their first word
            let mut tokens = line.split_whitespace();
            let mut first = tokens.next().unwrap_or("");
            if first == "&" || first == "." {
                first = tokens.next().unwrap_or("");
            }
            let first = first.trim_matches(|c| c == '"' || c == '\'');
            Event {
                timestamp: minus_micros(&mtime, n - 1 - i as i64),
                computer: computer.to_string(),
                artifact: "powershell:history".to_string(),
                event_id: 0,
                pid: 0,
                subject_username: user.clone(),
                target_username: String::new(),
                processname: first.to_string(),
                commandline: Some(line.to_string()),
                parentprocessname: format!("{} (line {} of {}, file time)", source, i + 1, n),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_keep_their_order_under_one_file_time() {
        let dir = std::env::temp_dir().join(format!("caarea_psrl_{}", std::process::id()));
        let user_dir = dir.join("Users").join("bob").join("PSReadLine");
        std::fs::create_dir_all(&user_dir).unwrap();
        let f = user_dir.join("ConsoleHost_history.txt");
        std::fs::write(&f, "whoami /all\r\n\r\nnet user x /add\r\n& 'C:\\Temp\\a.exe' -x\r\n").unwrap();
        let rows = parse_file(&f, "H");
        assert_eq!(rows.len(), 3);
        assert!(rows[0].timestamp < rows[1].timestamp && rows[1].timestamp < rows[2].timestamp);
        assert_eq!(rows[0].processname, "whoami");
        assert_eq!(rows[2].processname, "C:\\Temp\\a.exe");
        assert_eq!(rows[1].subject_username, "bob");
        assert_eq!(rows[1].commandline.as_deref(), Some("net user x /add"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
