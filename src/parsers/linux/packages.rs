use chrono::DateTime;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::parsers::evtx::Event;

/// Parses UAC RPM install time query file (live_response/packages/rpm_-q_-a_--queryformat_installtime_name_version_release.txt)
pub fn parse_rpm_query_file(file_path: &Path, computer_name: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return events,
    };

    let reader = BufReader::new(file);

    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => continue,
        };

        // Format: <epoch>~<name>~<version-release>
        let parts: Vec<&str> = line.split('~').collect();
        if parts.len() >= 3 {
            if let Ok(epoch) = parts[0].parse::<i64>() {
                let name = parts[1];
                let version = parts[2];

                let iso_ts = match DateTime::from_timestamp(epoch, 0) {
                    Some(dt) => dt.to_rfc3339(),
                    None => continue,
                };

                events.push(Event {
                    timestamp: iso_ts,
                    computer: computer_name.to_string(),
                    artifact: "linux:package:rpm".to_string(),
                    event_id: 0,
                    pid: 0,
                    subject_username: "root".to_string(),
                    target_username: "N/A".to_string(),
                    processname: name.to_string(),
                    commandline: Some(format!("RPM Package Installed: {} ({})", name, version)),
                    parentprocessname: "rpm/yum".to_string(),
                });
            }
        }
    }

    events
}

/// Parses /var/log/dpkg.log for software installation events
pub fn parse_dpkg_log(file_path: &Path, computer_name: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return events,
    };

    let reader = BufReader::new(file);

    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => continue,
        };

        // Format: "2026-09-25 03:40:36 status installed <pkg> <version>"
        if line.contains("status installed ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                let date_str = parts[0];
                let time_str = parts[1];
                let pkg_name = parts[4];
                let pkg_version = parts[5];

                let iso_ts = format!("{}T{}Z", date_str, time_str);

                events.push(Event {
                    timestamp: iso_ts,
                    computer: computer_name.to_string(),
                    artifact: "linux:package:dpkg".to_string(),
                    event_id: 0,
                    pid: 0,
                    subject_username: "root".to_string(),
                    target_username: "N/A".to_string(),
                    processname: pkg_name.to_string(),
                    commandline: Some(format!("Debian Package Installed: {} ({})", pkg_name, pkg_version)),
                    parentprocessname: "dpkg/apt".to_string(),
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
    fn test_parse_rpm_query() {
        let temp_file = std::env::temp_dir().join(format!("test_rpm_{}.txt", std::process::id()));
        {
            let mut f = File::create(&temp_file).unwrap();
            writeln!(f, "1752747745~BESAgent~10.0.13.93-rhe6").unwrap();
            writeln!(f, "1639396770~jq~1.3-2.el6").unwrap();
        }

        let events = parse_rpm_query_file(&temp_file, "LINUXHOST");
        let _ = std::fs::remove_file(&temp_file);

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].processname, "BESAgent");
        assert!(events[0].commandline.as_ref().unwrap().contains("BESAgent (10.0.13.93-rhe6)"));
        assert_eq!(events[1].processname, "jq");
    }
}
