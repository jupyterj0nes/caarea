use chrono::{DateTime, Utc};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::parsers::evtx::Event;

/// Parses cron job definition files (/etc/crontab, /etc/cron.d/*, /var/spool/cron/*)
pub fn parse_cron_table_file(file_path: &Path, computer_name: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return events,
    };

    let filename = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let is_spool = file_path.to_string_lossy().contains("spool");

    let fallback_timestamp = fs::metadata(file_path)
        .ok()
        .and_then(|m| m.modified().ok())
        .map(|st| {
            let dt: DateTime<Utc> = st.into();
            dt.to_rfc3339()
        })
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());

    let reader = BufReader::new(file);

    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => continue,
        };

        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("SHELL=") || trimmed.starts_with("PATH=") || trimmed.starts_with("MAILTO=") || trimmed.starts_with("HOME=") {
            continue;
        }

        // Crontab format in /etc/cron.d: min hour dom mon dow user command
        // User crontab in /var/spool/cron: min hour dom mon dow command
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();

        if is_spool {
            // Format: min hour dom mon dow command
            if tokens.len() >= 6 || (tokens[0].starts_with('@') && tokens.len() >= 2) {
                let (user, cmd_tokens) = if tokens[0].starts_with('@') {
                    (filename.to_string(), &tokens[1..])
                } else {
                    (filename.to_string(), &tokens[5..])
                };

                let command = cmd_tokens.join(" ");
                let process_name = cmd_tokens.first().unwrap_or(&"cron").to_string();

                events.push(Event {
                    timestamp: fallback_timestamp.clone(),
                    computer: computer_name.to_string(),
                    artifact: "linux:cron:scheduled_job".to_string(),
                    event_id: 0,
                    pid: 0,
                    subject_username: user.clone(),
                    target_username: user,
                    processname: process_name,
                    commandline: Some(format!("User Cron: {} (Spool: {})", command, filename)),
                    parentprocessname: "crond".to_string(),
                });
            }
        } else {
            // System cron.d format: min hour dom mon dow USER command
            if tokens.len() >= 7 {
                let user = tokens[5].to_string();
                let command = tokens[6..].join(" ");
                let process_name = tokens.get(6).unwrap_or(&"cron").to_string();

                events.push(Event {
                    timestamp: fallback_timestamp.clone(),
                    computer: computer_name.to_string(),
                    artifact: "linux:cron:scheduled_job".to_string(),
                    event_id: 0,
                    pid: 0,
                    subject_username: user.clone(),
                    target_username: user,
                    processname: process_name,
                    commandline: Some(format!("System Cron.d: {} (File: {})", command, filename)),
                    parentprocessname: "crond".to_string(),
                });
            }
        }
    }

    events
}

/// Parses systemd service unit files (/etc/systemd/system/*.service)
pub fn parse_systemd_service_file(file_path: &Path, computer_name: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return events,
    };

    let filename = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let fallback_timestamp = fs::metadata(file_path)
        .ok()
        .and_then(|m| m.modified().ok())
        .map(|st| {
            let dt: DateTime<Utc> = st.into();
            dt.to_rfc3339()
        })
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());

    let reader = BufReader::new(file);
    let mut exec_starts = Vec::new();
    let mut user = "root".to_string();
    let mut description = String::new();

    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => continue,
        };

        let trimmed = line.trim();
        if trimmed.starts_with("ExecStart=") || trimmed.starts_with("ExecStartPre=") || trimmed.starts_with("ExecStartPost=") {
            if let Some(cmd) = trimmed.split('=').nth(1) {
                exec_starts.push(cmd.trim().to_string());
            }
        } else if trimmed.starts_with("User=") {
            if let Some(u) = trimmed.split('=').nth(1) {
                user = u.trim().to_string();
            }
        } else if trimmed.starts_with("Description=") {
            if let Some(d) = trimmed.split('=').nth(1) {
                description = d.trim().to_string();
            }
        }
    }

    for exec in exec_starts {
        let proc_name = exec.split_whitespace().next().unwrap_or(&exec).to_string();
        events.push(Event {
            timestamp: fallback_timestamp.clone(),
            computer: computer_name.to_string(),
            artifact: "linux:systemd:service".to_string(),
            event_id: 0,
            pid: 0,
            subject_username: user.clone(),
            target_username: user.clone(),
            processname: proc_name,
            commandline: Some(format!("Systemd Unit: {} (Desc: {}, Exec: {})", filename, description, exec)),
            parentprocessname: "systemd".to_string(),
        });
    }

    events
}

/// Parses running_processes_full_paths.txt to detect deleted binaries executing in memory
pub fn parse_running_processes_paths(file_path: &Path, computer_name: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return events,
    };

    let fallback_timestamp = fs::metadata(file_path)
        .ok()
        .and_then(|m| m.modified().ok())
        .map(|st| {
            let dt: DateTime<Utc> = st.into();
            dt.to_rfc3339()
        })
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());

    let reader = BufReader::new(file);

    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => continue,
        };

        // Format: lrwxrwxrwx 1 root root 0 Sep 26 00:14 /proc/10615/exe -> /bin/bash (deleted)
        if line.contains("-> ") {
            let parts: Vec<&str> = line.split("-> ").collect();
            if parts.len() >= 2 {
                let target = parts[1].trim();

                let is_deleted = target.contains("(deleted)");
                let is_suspicious_path = target.starts_with("/tmp/") || target.starts_with("/dev/shm/") || target.starts_with("/var/tmp/");

                if is_deleted || is_suspicious_path {
                    let pid_part = parts[0].split("/proc/").nth(1).and_then(|s| s.split('/').next()).unwrap_or("0");
                    let pid: u32 = pid_part.parse().unwrap_or(0);

                    let artifact_label = if is_deleted {
                        "linux:process:deleted_binary_in_memory"
                    } else {
                        "linux:process:temp_path_execution"
                    };

                    events.push(Event {
                        timestamp: fallback_timestamp.clone(),
                        computer: computer_name.to_string(),
                        artifact: artifact_label.to_string(),
                        event_id: 0,
                        pid,
                        subject_username: "root".to_string(),
                        target_username: "root".to_string(),
                        processname: target.split_whitespace().next().unwrap_or(target).to_string(),
                        commandline: Some(format!("Executing Binary Link: {}", target)),
                        parentprocessname: "N/A".to_string(),
                    });
                }
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
    fn test_parse_cron_d() {
        let temp_file = std::env::temp_dir().join(format!("test_crond_{}.txt", std::process::id()));
        {
            let mut f = File::create(&temp_file).unwrap();
            writeln!(f, "SHELL=/bin/bash").unwrap();
            writeln!(f, "* * * * * root /tmp/.rcr/run_dumps.sh").unwrap();
        }

        let events = parse_cron_table_file(&temp_file, "TESTHOST");
        let _ = std::fs::remove_file(&temp_file);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].processname, "/tmp/.rcr/run_dumps.sh");
        assert_eq!(events[0].subject_username, "root");
        assert!(events[0].commandline.as_ref().unwrap().contains("/tmp/.rcr/run_dumps.sh"));
    }
}
