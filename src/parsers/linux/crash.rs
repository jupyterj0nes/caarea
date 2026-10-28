use crate::utils::systemtime_to_iso;
use regex::Regex;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::parsers::evtx::Event;

/// Parses dmesg, syslog, and crash directories for segfaults and exploitation crashes
pub fn parse_segfault_log(file_path: &Path, computer_name: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return events,
    };

    let fallback_timestamp = fs::metadata(file_path)
        .ok()
        .and_then(|m| m.modified().ok())
        .map(systemtime_to_iso)
        .unwrap_or_else(|| "1970-01-01T00:00:00.000000Z".to_string());

    // Matches: "binary[1234]: segfault at 7fff1234 ip ... sp ... error 4 in binary[...]"
    let segfault_re = match Regex::new(
        r"(\S+)\[(\d+)\]:\s+(segfault at [0-9a-fA-F]+ ip [0-9a-fA-F]+.*)",
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

        if line.contains("segfault at ") {
            if let Some(caps) = segfault_re.captures(&line) {
                let proc_name = caps[1].to_string();
                let pid: u32 = caps[2].parse().unwrap_or(0);
                let details = caps[3].to_string();

                events.push(Event {
                    timestamp: fallback_timestamp.clone(),
                    computer: computer_name.to_string(),
                    artifact: "linux:crash:segfault".to_string(),
                    event_id: 0,
                    pid,
                    subject_username: "unknown".to_string(),
                    target_username: "unknown".to_string(),
                    processname: proc_name,
                    commandline: Some(format!("Kernel Segfault: {}", details)),
                    parentprocessname: "kernel".to_string(),
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
    fn test_parse_segfault() {
        let temp_file = std::env::temp_dir().join(format!("test_segfault_{}.log", std::process::id()));
        {
            let mut f = File::create(&temp_file).unwrap();
            writeln!(f, "Sep 23 15:40:12 host kernel: exploit_poc[4567]: segfault at 00007fff ip 00007f56 sp 00007fff error 4 in libc-2.12.so[7f56+1000]").unwrap();
        }

        let events = parse_segfault_log(&temp_file, "TESTHOST");
        let _ = std::fs::remove_file(&temp_file);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].processname, "exploit_poc");
        assert_eq!(events[0].pid, 4567);
        assert!(events[0].commandline.as_ref().unwrap().contains("segfault at 00007fff"));
    }
}
