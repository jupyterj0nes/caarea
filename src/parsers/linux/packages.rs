use chrono::NaiveDateTime;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::parsers::evtx::Event;
use crate::parsers::linux::timezone::HostTimezone;
use crate::utils::{epoch_to_iso, iso_utc};

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

                let iso_ts = match epoch_to_iso(epoch, 0) {
                    Some(ts) => ts,
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

/// Parses /var/log/dpkg.log for software installation events. dpkg writes host wall-clock
/// times, converted here with the detected host time zone.
pub fn parse_dpkg_log(file_path: &Path, computer_name: &str, tz: &HostTimezone) -> Vec<Event> {
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

                let iso_ts = match NaiveDateTime::parse_from_str(&format!("{} {}", date_str, time_str), "%Y-%m-%d %H:%M:%S") {
                    Ok(ndt) => iso_utc(&tz.local_to_utc(ndt)),
                    Err(_) => continue,
                };

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

/// `/var/log/apt/history.log`: one block per apt run with the exact command line and the
/// user who asked for it. `Start-Date` is host wall-clock time.
pub fn parse_apt_history(file_path: &Path, computer_name: &str, tz: &HostTimezone) -> Vec<Event> {
    let Ok(text) = std::fs::read_to_string(file_path) else { return Vec::new() };
    let mut events = Vec::new();
    for block in text.split("\n\n") {
        let mut start = None;
        let mut cmd = String::new();
        let mut user = String::new();
        let mut summary: Vec<String> = Vec::new();
        for line in block.lines() {
            if let Some(v) = line.strip_prefix("Start-Date: ") {
                start = NaiveDateTime::parse_from_str(v.split_whitespace().collect::<Vec<_>>().join(" ").as_str(), "%Y-%m-%d %H:%M:%S").ok();
            } else if let Some(v) = line.strip_prefix("Commandline: ") {
                cmd = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("Requested-By: ") {
                user = v.trim().to_string();
            } else if let Some((k, v)) = line.split_once(": ") {
                if matches!(k, "Install" | "Upgrade" | "Remove" | "Purge" | "Downgrade" | "Reinstall") {
                    let names: Vec<&str> = v.split("), ").map(|p| p.split(':').next().unwrap_or("").trim()).filter(|s| !s.is_empty()).collect();
                    summary.push(format!("{} {}: {}", k, names.len(), names.iter().take(8).cloned().collect::<Vec<_>>().join(", ")));
                }
            }
        }
        let Some(start) = start else { continue };
        if cmd.is_empty() && summary.is_empty() {
            continue;
        }
        let who = if user.is_empty() { "root".to_string() } else { user.split_whitespace().next().unwrap_or("root").to_string() };
        events.push(Event {
            timestamp: iso_utc(&tz.local_to_utc(start)),
            computer: computer_name.to_string(),
            artifact: "linux:package:apt".to_string(),
            event_id: 0,
            pid: 0,
            subject_username: who,
            target_username: "root".to_string(),
            processname: cmd.split_whitespace().next().unwrap_or("apt").to_string(),
            commandline: Some(if summary.is_empty() { cmd.clone() } else { format!("{} | {}", cmd, summary.join(" | ")) }),
            parentprocessname: "apt".to_string(),
        });
    }
    events
}

/// `/var/log/pacman.log`: `[2026-10-28T12:00:01+0000] [PACMAN] Running 'pacman -S nmap'`.
pub fn parse_pacman_log(file_path: &Path, computer_name: &str) -> Vec<Event> {
    let Ok(text) = std::fs::read_to_string(file_path) else { return Vec::new() };
    let mut events = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix('[') else { continue };
        let Some((ts_raw, rest)) = rest.split_once(']') else { continue };
        let Some(ts) = crate::utils::parse_flexible_time(ts_raw).map(|dt| iso_utc(&dt)) else { continue };
        let rest = rest.trim();
        let (artifact, cmd) = if let Some(c) = rest.strip_prefix("[PACMAN] Running '") {
            ("linux:package:pacman", c.trim_end_matches('\'').to_string())
        } else if let Some(c) = rest.strip_prefix("[ALPM] installed ") {
            ("linux:package:pacman:installed", format!("installed {}", c))
        } else if let Some(c) = rest.strip_prefix("[ALPM] removed ") {
            ("linux:package:pacman:removed", format!("removed {}", c))
        } else {
            continue;
        };
        events.push(Event {
            timestamp: ts,
            computer: computer_name.to_string(),
            artifact: artifact.to_string(),
            event_id: 0,
            pid: 0,
            subject_username: "root".to_string(),
            target_username: "N/A".to_string(),
            processname: cmd.split_whitespace().next().unwrap_or("pacman").to_string(),
            commandline: Some(cmd),
            parentprocessname: "pacman".to_string(),
        });
    }
    events
}

/// `dnf.rpm.log` / `yum.log`: `2026-10-28T12:00:01+0000 SUBDEBUG Installed: nmap-7.92-1.el9.x86_64`
/// and the classic `Oct 28 12:00:01 Installed: nmap-7.92-1.el9.x86_64` (wall-clock, no year).
pub fn parse_rpm_log(file_path: &Path, computer_name: &str, tz: &HostTimezone) -> Vec<Event> {
    let Ok(text) = std::fs::read_to_string(file_path) else { return Vec::new() };
    let year_hint = std::fs::metadata(file_path)
        .and_then(|m| m.modified())
        .ok()
        .map(|t| chrono::DateTime::<chrono::Utc>::from(t).format("%Y").to_string())
        .unwrap_or_else(|| "1970".to_string());
    let mut events = Vec::new();
    for line in text.lines() {
        let Some(pos) = line.find(": ") else { continue };
        let head = &line[..pos];
        let pkg = line[pos + 2..].trim();
        let verb = head.rsplit(' ').next().unwrap_or("");
        if !matches!(verb, "Installed" | "Erased" | "Updated" | "Upgraded" | "Removed" | "Reinstalled") {
            continue;
        }
        let ts = if head.len() > 20 && head.as_bytes()[4] == b'-' {
            crate::utils::parse_flexible_time(head.split_whitespace().next().unwrap_or("")).map(|dt| iso_utc(&dt))
        } else {
            let parts: Vec<&str> = head.split_whitespace().collect();
            if parts.len() >= 3 {
                NaiveDateTime::parse_from_str(&format!("{} {} {} {}", parts[0], parts[1], year_hint, parts[2]), "%b %d %Y %H:%M:%S")
                    .ok()
                    .map(|ndt| iso_utc(&tz.local_to_utc(ndt)))
            } else {
                None
            }
        };
        let Some(ts) = ts else { continue };
        events.push(Event {
            timestamp: ts,
            computer: computer_name.to_string(),
            artifact: format!("linux:package:rpm:{}", verb.to_ascii_lowercase()),
            event_id: 0,
            pid: 0,
            subject_username: "root".to_string(),
            target_username: "N/A".to_string(),
            processname: pkg.to_string(),
            commandline: Some(format!("{}: {}", verb, pkg)),
            parentprocessname: "dnf/yum".to_string(),
        });
    }
    events
}

/// `/var/log/zypp/history`: `2026-10-28 12:00:01|command|root@host|'zypper' 'in' 'nmap'|`.
pub fn parse_zypp_history(file_path: &Path, computer_name: &str, tz: &HostTimezone) -> Vec<Event> {
    let Ok(text) = std::fs::read_to_string(file_path) else { return Vec::new() };
    let mut events = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() < 4 || parts[1] != "command" {
            continue;
        }
        let Ok(ndt) = NaiveDateTime::parse_from_str(parts[0], "%Y-%m-%d %H:%M:%S") else { continue };
        let cmd = parts[3].replace('\'', "");
        events.push(Event {
            timestamp: iso_utc(&tz.local_to_utc(ndt)),
            computer: computer_name.to_string(),
            artifact: "linux:package:zypper".to_string(),
            event_id: 0,
            pid: 0,
            subject_username: parts[2].split('@').next().unwrap_or("root").to_string(),
            target_username: "root".to_string(),
            processname: cmd.split_whitespace().next().unwrap_or("zypper").to_string(),
            commandline: Some(cmd),
            parentprocessname: "zypper".to_string(),
        });
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_apt_history_block() {
        let temp = std::env::temp_dir().join(format!("apt_history_{}.log", std::process::id()));
        std::fs::write(&temp, "Start-Date: 2026-10-28  22:01:08\nCommandline: apt-get -qq install -y sl\nRequested-By: c00pr (1002)\nInstall: sl:amd64 (5.02-1)\nEnd-Date: 2026-10-28  22:01:09\n\nStart-Date: 2026-10-28  22:05:00\nCommandline: apt purge nmap\nRemove: nmap:amd64 (7.80), libpcap0.8:amd64 (1.9)\nEnd-Date: 2026-10-28  22:05:01\n").unwrap();
        let rows = parse_apt_history(&temp, "H", &HostTimezone::utc());
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].timestamp, "2026-10-28T22:01:08.000000Z");
        assert_eq!(rows[0].subject_username, "c00pr");
        assert_eq!(rows[0].processname, "apt-get");
        assert_eq!(rows[0].commandline.as_deref(), Some("apt-get -qq install -y sl | Install 1: sl"));
        assert_eq!(rows[1].commandline.as_deref(), Some("apt purge nmap | Remove 2: nmap, libpcap0.8"));
        let _ = std::fs::remove_file(&temp);
    }

    #[test]
    fn test_pacman_and_rpm_logs() {
        let temp = std::env::temp_dir().join(format!("pacman_{}.log", std::process::id()));
        std::fs::write(&temp, "[2026-10-28T12:00:01+0000] [PACMAN] Running 'pacman -S nmap'\n[2026-10-28T12:00:05+0000] [ALPM] installed nmap (7.95-1)\n").unwrap();
        let rows = parse_pacman_log(&temp, "H");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].commandline.as_deref(), Some("pacman -S nmap"));
        assert_eq!(rows[0].timestamp, "2026-10-28T12:00:01.000000Z");
        std::fs::write(&temp, "2026-10-28T12:00:01+0000 SUBDEBUG Installed: nmap-7.92-1.el9.x86_64\n2026-10-28T12:00:02+0000 INFO --- logging initialized ---\n").unwrap();
        let rows = parse_rpm_log(&temp, "H", &HostTimezone::utc());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].artifact, "linux:package:rpm:installed");
        assert_eq!(rows[0].processname, "nmap-7.92-1.el9.x86_64");
        let _ = std::fs::remove_file(&temp);
    }

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
