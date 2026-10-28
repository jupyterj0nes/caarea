use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, NaiveTime, Utc};
use regex::Regex;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::parsers::evtx::Event;
use crate::parsers::linux::timezone::HostTimezone;
use crate::utils::{iso_utc, parse_flexible_time};

/// Infers the year for a classic syslog timestamp without year ("Sep 20 03:10:01") using the
/// file mtime: if the log month is later than the mtime month the line belongs to the previous year.
/// Classic syslog timestamps carry no zone: they are wall-clock times of the host, converted
/// with the detected host time zone.
fn resolve_classic_timestamp(month_day_time: &str, file_mtime_year: i32, file_mtime_month: u32, tz: &HostTimezone) -> Option<String> {
    let parts: Vec<&str> = month_day_time.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    let month_num = match parts[0].to_lowercase().as_str() {
        "jan" => 1, "feb" => 2, "mar" => 3, "apr" => 4, "may" => 5, "jun" => 6,
        "jul" => 7, "aug" => 8, "sep" => 9, "oct" => 10, "nov" => 11, "dec" => 12,
        _ => return None,
    };

    let day: u32 = parts[1].parse().ok()?;
    let time = NaiveTime::parse_from_str(parts[2], "%H:%M:%S").ok()?;

    let year = if month_num > file_mtime_month { file_mtime_year - 1 } else { file_mtime_year };

    let date = NaiveDate::from_ymd_opt(year, month_num, day)?;
    Some(iso_utc(&tz.local_to_utc(NaiveDateTime::new(date, time))))
}

/// Resolves either a classic (`Sep 20 03:10:01`) or an RFC 3339 / ISO 8601 syslog timestamp
/// (`2026-04-07T21:58:59.622926+02:00`, as written by rsyslog on Debian 12 / Ubuntu 24.04).
fn resolve_syslog_timestamp(raw: &str, file_mtime_year: i32, file_mtime_month: u32, tz: &HostTimezone) -> Option<String> {
    if raw.as_bytes().first().map(|b| b.is_ascii_digit()).unwrap_or(false) {
        if raw.ends_with('Z') || raw.contains('+') || raw.rfind('-').map(|i| i > 10).unwrap_or(false) {
            parse_flexible_time(raw).map(|dt| iso_utc(&dt))
        } else {
            // ISO timestamp without zone: wall-clock time of the host
            parse_flexible_time(raw).map(|dt| iso_utc(&tz.local_to_utc(dt.naive_utc())))
        }
    } else {
        resolve_classic_timestamp(raw, file_mtime_year, file_mtime_month, tz)
    }
}

/// Parses syslog-style files (/var/log/cron, secure, auth.log, syslog, messages) for
/// execution events: cron jobs, sudo commands and su switches. `tz` is the host time zone
/// used for zone-less timestamps.
pub fn parse_syslog_file(file_path: &Path, default_computer: &str, tz: &HostTimezone) -> Vec<Event> {
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
        .unwrap_or_else(|| {
            let now = Utc::now();
            (now.year(), now.month())
        });

    // Generic syslog header: <timestamp> <host> <program>[pid]: <message>
    let header_re = match Regex::new(
        r"^(?P<ts>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<host>\S+)\s+(?P<prog>[^\[\]:\s]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$",
    ) {
        Ok(r) => r,
        Err(_) => return events,
    };

    // "(root) CMD (/usr/lib64/sa/sa1 1 1)"
    let cron_re = match Regex::new(r"^\((?P<user>[^)]+)\)\s+CMD\s+\((?P<cmd>.*)\)\s*$") {
        Ok(r) => r,
        Err(_) => return events,
    };

    // "  ansible : TTY=unknown ; PWD=/home/ansible ; USER=root ; COMMAND=/bin/sed ..."
    let sudo_re = match Regex::new(r"^\s*(?P<user>\S+)\s*:\s*(?:.*?;\s*)?USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.*)$") {
        Ok(r) => r,
        Err(_) => return events,
    };

    // "(to root) alice on pts/1"
    let su_re = match Regex::new(r"^\(to (?P<target>[^)]+)\)\s+(?P<user>\S+)\s+on\s+(?P<tty>\S+)") {
        Ok(r) => r,
        Err(_) => return events,
    };

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
        let prog = caps["prog"].to_lowercase();
        let msg = &caps["msg"];

        let (artifact, subject, target, command, parent) = match prog.as_str() {
            "cron" | "crond" | "anacron" => match cron_re.captures(msg) {
                Some(c) => (
                    "linux:syslog:cron",
                    c["user"].trim().to_string(),
                    c["user"].trim().to_string(),
                    c["cmd"].to_string(),
                    "crond",
                ),
                None => continue,
            },
            "sudo" => match sudo_re.captures(msg) {
                Some(c) => (
                    "linux:syslog:sudo",
                    c["user"].trim().to_string(),
                    c["target"].trim().to_string(),
                    c["cmd"].trim().to_string(),
                    "sudo",
                ),
                None => continue,
            },
            "su" | "su-l" => match su_re.captures(msg) {
                Some(c) => (
                    "linux:syslog:su",
                    c["user"].trim().to_string(),
                    c["target"].trim().to_string(),
                    format!("su to {} on {}", &c["target"], &c["tty"]),
                    "su",
                ),
                None => continue,
            },
            _ => continue,
        };

        let iso_ts = match resolve_syslog_timestamp(&caps["ts"], mtime_year, mtime_month, tz) {
            Some(ts) => ts,
            None => continue,
        };
        let host = &caps["host"];
        let pid: u32 = caps.name("pid").and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
        let proc_name = command.split_whitespace().next().unwrap_or(&command).to_string();

        events.push(Event {
            timestamp: iso_ts,
            computer: if host.is_empty() { default_computer.to_string() } else { host.to_string() },
            artifact: artifact.to_string(),
            event_id: 0,
            pid,
            subject_username: subject,
            target_username: target,
            processname: proc_name,
            commandline: Some(command),
            parentprocessname: parent.to_string(),
        });
    }

    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp(name: &str, lines: &[&str]) -> std::path::PathBuf {
        let temp_file = std::env::temp_dir().join(format!("{}_{}.txt", name, std::process::id()));
        let mut f = File::create(&temp_file).unwrap();
        for l in lines {
            writeln!(f, "{}", l).unwrap();
        }
        temp_file
    }

    #[test]
    fn test_parse_cron_syslog() {
        let temp_file = write_temp("test_cron", &[
            "Sep 20 03:10:01 lvmercand01 CROND[2177]: (root) CMD (/usr/lib64/sa/sa1 1 1)",
            "Sep 20 03:17:01 lvmercand01 CRON[2201]: (www-data) CMD (php /var/www/cron.php)",
        ]);
        let events = parse_syslog_file(&temp_file, "TESTHOST", &HostTimezone::utc());

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].processname, "/usr/lib64/sa/sa1");
        assert_eq!(events[0].subject_username, "root");
        assert_eq!(events[0].pid, 2177);
        assert_eq!(events[0].computer, "lvmercand01");
        assert!(events[0].timestamp.ends_with("-09-20T03:10:01.000000Z"));
        // users with '-' must not be dropped
        assert_eq!(events[1].subject_username, "www-data");
        assert_eq!(events[1].processname, "php");

        // Same file, host running in Europe/Madrid: September is CEST (+02:00)
        let madrid = parse_syslog_file(&temp_file, "TESTHOST", &HostTimezone::from_spec("Europe/Madrid").unwrap());
        let _ = std::fs::remove_file(&temp_file);
        assert!(madrid[0].timestamp.ends_with("-09-20T01:10:01.000000Z"), "{}", madrid[0].timestamp);
    }

    #[test]
    fn test_parse_sudo_syslog() {
        let temp_file = write_temp("test_sudo", &[
            "Sep 25 03:40:36 lvmercand01 sudo:  ansible : TTY=unknown ; PWD=/home/ansible ; USER=root ; COMMAND=/bin/pkill -9 -f @pts/",
            "Sep 25 03:40:37 lvmercand01 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by ansible(uid=1100)",
        ]);
        let events = parse_syslog_file(&temp_file, "TESTHOST", &HostTimezone::utc());
        let _ = std::fs::remove_file(&temp_file);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].processname, "/bin/pkill");
        assert_eq!(events[0].subject_username, "ansible");
        assert_eq!(events[0].target_username, "root");
        assert_eq!(events[0].commandline, Some("/bin/pkill -9 -f @pts/".to_string()));
    }

    #[test]
    fn test_parse_rfc3339_syslog_and_su() {
        // rsyslog high precision format (Debian 12 / Ubuntu 24.04): offset must be honoured
        let temp_file = write_temp("test_rfc3339", &[
            "2026-04-07T22:17:01.123456+02:00 DESKTOP-X CRON[1234]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)",
            "2026-04-07T22:18:05.000000+02:00 DESKTOP-X sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt install nmap",
            "2026-04-07T22:19:00.000000+02:00 DESKTOP-X su[777]: (to root) alice on pts/1",
        ]);
        // A named zone must NOT alter timestamps that carry their own offset
        let events = parse_syslog_file(&temp_file, "TESTHOST", &HostTimezone::from_spec("Asia/Tokyo").unwrap());
        let _ = std::fs::remove_file(&temp_file);

        assert_eq!(events.len(), 3);
        assert_eq!(events[0].timestamp, "2026-04-07T20:17:01.123456Z");
        assert_eq!(events[0].artifact, "linux:syslog:cron");
        assert_eq!(events[1].timestamp, "2026-04-07T20:18:05.000000Z");
        assert_eq!(events[1].commandline.as_deref(), Some("/usr/bin/apt install nmap"));
        assert_eq!(events[2].artifact, "linux:syslog:su");
        assert_eq!(events[2].subject_username, "alice");
        assert_eq!(events[2].target_username, "root");
        assert_eq!(events[2].pid, 777);
    }
}
