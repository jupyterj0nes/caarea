use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, NaiveTime, Utc};
use regex::Regex;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::parsers::evtx::Event;

/// Infers the year for a syslog line without year ("Sep 20 03:10:01") using file mtime
fn resolve_syslog_timestamp(month_day_time: &str, file_mtime_year: i32, file_mtime_month: u32) -> Option<String> {
    // Format: "Sep 20 03:10:01" or "Sep  2 03:10:01"
    let parts: Vec<&str> = month_day_time.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    let month_str = parts[0];
    let day_str = parts[1];
    let time_str = parts[2];

    let month_num = match month_str.to_lowercase().as_str() {
        "jan" => 1, "feb" => 2, "mar" => 3, "apr" => 4, "may" => 5, "jun" => 6,
        "jul" => 7, "aug" => 8, "sep" => 9, "oct" => 10, "nov" => 11, "dec" => 12,
        _ => return None,
    };

    let day: u32 = day_str.parse().ok()?;
    let time = NaiveTime::parse_from_str(time_str, "%H:%M:%S").ok()?;

    // Adjust year if log month is greater than file mtime month (log wrap across new year)
    let year = if month_num > file_mtime_month {
        file_mtime_year - 1
    } else {
        file_mtime_year
    };

    let date = NaiveDate::from_ymd_opt(year, month_num, day)?;
    let ndt = NaiveDateTime::new(date, time);
    Some(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc).to_rfc3339())
}

/// Parses syslog files (/var/log/cron, /var/log/secure, /var/log/auth.log) for execution events
pub fn parse_syslog_file(file_path: &Path, default_computer: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return events,
    };

    let (mtime_year, mtime_month) = fs::metadata(file_path)
        .ok()
        .and_then(|m| m.modified().ok())
        .map(|st| {
            let dt: DateTime<Utc> = st.into();
            (dt.year(), dt.month())
        })
        .unwrap_or((2026, 9));

    // Regex for cron CMD executions:
    // "Sep 20 03:10:01 lvmercand01 CROND[2177]: (root) CMD (/usr/lib64/sa/sa1 1 1)"
    let cron_re = match Regex::new(
        r"^([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+CROND?\[(\d+)\]:\s+\((\w+)\)\s+CMD\s+\((.+)\)$",
    ) {
        Ok(r) => r,
        Err(_) => return events,
    };

    // Regex for sudo COMMAND executions:
    // "Sep 25 03:40:36 lvmercand01 sudo:  ansible : ... USER=root ; COMMAND=/bin/sed ..."
    let sudo_re = match Regex::new(
        r"^([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sudo:\s+(\S+)\s+:\s+(?:.*;\s+)?USER=(\S+)\s+;\s+COMMAND=(.+)$",
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

        // 1. Cron execution line
        if line.contains("CMD (") && (line.contains("CRON[") || line.contains("CROND[")) {
            if let Some(caps) = cron_re.captures(&line) {
                let time_str = &caps[1];
                let host = &caps[2];
                let pid: u32 = caps[3].parse().unwrap_or(0);
                let user = caps[4].to_string();
                let command = caps[5].to_string();

                let iso_ts = match resolve_syslog_timestamp(time_str, mtime_year, mtime_month) {
                    Some(ts) => ts,
                    None => continue,
                };

                let proc_name = command.split_whitespace().next().unwrap_or(&command).to_string();

                events.push(Event {
                    timestamp: iso_ts,
                    computer: if host.is_empty() { default_computer.to_string() } else { host.to_string() },
                    artifact: "linux:syslog:cron".to_string(),
                    event_id: 0,
                    pid,
                    subject_username: user.clone(),
                    target_username: user,
                    processname: proc_name,
                    commandline: Some(command),
                    parentprocessname: "crond".to_string(),
                });
            }
            continue;
        }

        // 2. Sudo execution line
        if line.contains("COMMAND=") && line.contains("sudo:") {
            if let Some(caps) = sudo_re.captures(&line) {
                let time_str = &caps[1];
                let host = &caps[2];
                let subject_user = caps[3].trim().to_string();
                let target_user = caps[4].trim().to_string();
                let command = caps[5].trim().to_string();

                let iso_ts = match resolve_syslog_timestamp(time_str, mtime_year, mtime_month) {
                    Some(ts) => ts,
                    None => continue,
                };

                let proc_name = command.split_whitespace().next().unwrap_or(&command).to_string();

                events.push(Event {
                    timestamp: iso_ts,
                    computer: if host.is_empty() { default_computer.to_string() } else { host.to_string() },
                    artifact: "linux:syslog:sudo".to_string(),
                    event_id: 0,
                    pid: 0,
                    subject_username: subject_user,
                    target_username: target_user,
                    processname: proc_name,
                    commandline: Some(command),
                    parentprocessname: "sudo".to_string(),
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
    fn test_parse_cron_syslog() {
        let temp_file = std::env::temp_dir().join(format!("test_cron_{}.txt", std::process::id()));
        {
            let mut f = File::create(&temp_file).unwrap();
            writeln!(f, "Sep 20 03:10:01 lvmercand01 CROND[2177]: (root) CMD (/usr/lib64/sa/sa1 1 1)").unwrap();
        }

        let events = parse_syslog_file(&temp_file, "TESTHOST");
        let _ = std::fs::remove_file(&temp_file);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].processname, "/usr/lib64/sa/sa1");
        assert_eq!(events[0].subject_username, "root");
        assert_eq!(events[0].pid, 2177);
        assert_eq!(events[0].computer, "lvmercand01");
    }

    #[test]
    fn test_parse_sudo_syslog() {
        let temp_file = std::env::temp_dir().join(format!("test_sudo_{}.txt", std::process::id()));
        {
            let mut f = File::create(&temp_file).unwrap();
            writeln!(f, "Sep 25 03:40:36 lvmercand01 sudo:  ansible : TTY=unknown ; PWD=/home/ansible ; USER=root ; COMMAND=/bin/pkill -9 -f @pts/").unwrap();
        }

        let events = parse_syslog_file(&temp_file, "TESTHOST");
        let _ = std::fs::remove_file(&temp_file);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].processname, "/bin/pkill");
        assert_eq!(events[0].subject_username, "ansible");
        assert_eq!(events[0].target_username, "root");
        assert_eq!(events[0].commandline, Some("/bin/pkill -9 -f @pts/".to_string()));
    }
}
