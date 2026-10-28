use chrono::NaiveDateTime;
use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::parsers::evtx::Event;
use crate::parsers::linux::timezone::HostTimezone;
use crate::utils::iso_utc;

/// Parses live_response/process/ps_-axo_pid_user_lstart_args.txt from UAC or live response.
/// `lstart` is printed in the host's local time, converted with the detected host time zone.
pub fn parse_ps_lstart_file(file_path: &Path, computer_name: &str, tz: &HostTimezone) -> Vec<Event> {
    let mut events = Vec::new();
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return events,
    };

    let reader = BufReader::new(file);

    // Regex to match: PID USER STARTED (e.g. Sat Sep 26 00:08:30 2026) COMMAND
    // Header format: PID USER STARTED COMMAND
    let line_re = match Regex::new(
        r"^\s*(\d+)\s+(\S+)\s+([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(.+)$",
    ) {
        Ok(r) => r,
        Err(_) => return events,
    };

    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => continue,
        };

        if line.trim().starts_with("PID") {
            continue; // Skip header
        }

        if let Some(caps) = line_re.captures(&line) {
            let pid: u32 = caps[1].parse().unwrap_or(0);
            let user = caps[2].to_string();
            let started_str = &caps[3];
            let command = caps[4].to_string();

            // Parse timestamp format: "Sat Sep 26 00:08:30 2026"
            let iso_timestamp = match NaiveDateTime::parse_from_str(started_str, "%a %b %e %H:%M:%S %Y")
                .or_else(|_| NaiveDateTime::parse_from_str(started_str, "%a %b %d %H:%M:%S %Y"))
            {
                Ok(ndt) => iso_utc(&tz.local_to_utc(ndt)),
                Err(_) => continue,
            };

            // First word of command is the process name
            let process_name = command
                .split_whitespace()
                .next()
                .unwrap_or(&command)
                .trim_matches(&['[', ']'][..])
                .to_string();

            events.push(Event {
                timestamp: iso_timestamp,
                computer: computer_name.to_string(),
                artifact: "linux:process:ps_lstart".to_string(),
                event_id: 0,
                pid,
                subject_username: user.clone(),
                target_username: user,
                processname: process_name,
                commandline: Some(command),
                parentprocessname: "N/A".to_string(),
            });
        }
    }

    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_parse_ps_lstart() {
        let temp_file = std::env::temp_dir().join(format!("test_ps_{}.txt", std::process::id()));
        {
            let mut f = File::create(&temp_file).unwrap();
            writeln!(f, "  PID USER                      STARTED COMMAND").unwrap();
            writeln!(f, "    1 root     Sat Sep 26 00:08:30 2026 /sbin/init").unwrap();
            writeln!(f, " 1058 root     Sat Sep 26 00:08:30 2026 /sbin/udevd -d").unwrap();
            writeln!(f, "10615 anita    Sat Sep 26 00:14:52 2026 /bin/sh ./uac full /tmp/out").unwrap();
        }

        let events = parse_ps_lstart_file(&temp_file, "TESTHOST", &HostTimezone::utc());
        let _ = std::fs::remove_file(&temp_file);

        assert_eq!(events.len(), 3);
        assert_eq!(events[0].pid, 1);
        assert_eq!(events[0].processname, "/sbin/init");
        assert_eq!(events[0].subject_username, "root");
        assert!(events[0].timestamp.starts_with("2026-09-26T00:08:30"));

        assert_eq!(events[2].pid, 10615);
        assert_eq!(events[2].processname, "/bin/sh");
        assert_eq!(events[2].subject_username, "anita");
    }
}
