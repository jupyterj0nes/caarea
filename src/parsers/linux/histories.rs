use chrono::{DateTime, Utc};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::parsers::evtx::Event;

/// Infers username from a history file path (e.g. /home/anita/.bash_history -> anita, /root/.viminfo -> root)
pub fn infer_user_from_history_path(path: &Path) -> String {
    let components: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();

    for (i, comp) in components.iter().enumerate() {
        if comp == "home" && i + 1 < components.len() {
            return components[i + 1].clone();
        }
        if comp == "root" {
            return "root".to_string();
        }
    }

    "unknown".to_string()
}

/// Parses .bash_history, handling both timestamped (#epoch) and sequential entries
pub fn parse_bash_history(file_path: &Path, computer_name: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return events,
    };

    let user = infer_user_from_history_path(file_path);
    let fallback_timestamp = fs::metadata(file_path)
        .ok()
        .and_then(|m| m.modified().ok())
        .map(|st| {
            let dt: DateTime<Utc> = st.into();
            dt.to_rfc3339()
        })
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());

    let reader = BufReader::new(file);
    let mut current_epoch: Option<i64> = None;

    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => continue,
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Check if line is an epoch timestamp: #1710766331
        if trimmed.starts_with('#') && trimmed.len() > 1 && trimmed[1..].chars().all(|c| c.is_ascii_digit()) {
            if let Ok(epoch) = trimmed[1..].parse::<i64>() {
                current_epoch = Some(epoch);
                continue;
            }
        }

        let iso_ts = match current_epoch {
            Some(epoch) => DateTime::from_timestamp(epoch, 0)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_else(|| fallback_timestamp.clone()),
            None => fallback_timestamp.clone(),
        };

        let proc_name = trimmed.split_whitespace().next().unwrap_or(trimmed).to_string();

        events.push(Event {
            timestamp: iso_ts,
            computer: computer_name.to_string(),
            artifact: "linux:shell:bash_history".to_string(),
            event_id: 0,
            pid: 0,
            subject_username: user.clone(),
            target_username: user.clone(),
            processname: proc_name,
            commandline: Some(trimmed.to_string()),
            parentprocessname: "bash".to_string(),
        });

        current_epoch = None;
    }

    events
}

/// Parses .zsh_history with format: : <epoch>:<duration>;<command>
pub fn parse_zsh_history(file_path: &Path, computer_name: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return events,
    };

    let user = infer_user_from_history_path(file_path);
    let reader = BufReader::new(file);

    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => continue,
        };

        let trimmed = line.trim();
        if trimmed.starts_with(": ") {
            // Format: ": 1710766331:0;vi /etc/ssh/sshd_config"
            if let Some(semicolon_idx) = trimmed.find(';') {
                let header = &trimmed[2..semicolon_idx];
                let command = &trimmed[semicolon_idx + 1..];

                let epoch_str = header.split(':').next().unwrap_or("");
                if let Ok(epoch) = epoch_str.parse::<i64>() {
                    let iso_ts = DateTime::from_timestamp(epoch, 0)
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());

                    let proc_name = command.split_whitespace().next().unwrap_or(command).to_string();

                    events.push(Event {
                        timestamp: iso_ts,
                        computer: computer_name.to_string(),
                        artifact: "linux:shell:zsh_history".to_string(),
                        event_id: 0,
                        pid: 0,
                        subject_username: user.clone(),
                        target_username: user.clone(),
                        processname: proc_name,
                        commandline: Some(command.to_string()),
                        parentprocessname: "zsh".to_string(),
                    });
                }
            }
        }
    }

    events
}

/// Parses .viminfo (and Neovim shada files), extracting file edit marks, command history, and yanked buffers
pub fn parse_viminfo(file_path: &Path, computer_name: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return events,
    };

    let user = infer_user_from_history_path(file_path);
    let fallback_timestamp = fs::metadata(file_path)
        .ok()
        .and_then(|m| m.modified().ok())
        .map(|st| {
            let dt: DateTime<Utc> = st.into();
            dt.to_rfc3339()
        })
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());

    let reader = BufReader::new(file);

    let mut section = "";

    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => continue,
        };

        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            if trimmed.contains("Línea de órdenes") || trimmed.contains("CommandLine History") {
                section = "cmd";
            } else if trimmed.contains("Marcas en el archivo") || trimmed.contains("File marks") {
                section = "marks";
            } else if trimmed.contains("Registros") || trimmed.contains("Registers") {
                section = "registers";
            } else {
                section = "";
            }
            continue;
        }

        match section {
            "cmd" => {
                if trimmed.starts_with(':') && trimmed.len() > 1 {
                    events.push(Event {
                        timestamp: fallback_timestamp.clone(),
                        computer: computer_name.to_string(),
                        artifact: "linux:editor:vim_command".to_string(),
                        event_id: 0,
                        pid: 0,
                        subject_username: user.clone(),
                        target_username: user.clone(),
                        processname: "vim".to_string(),
                        commandline: Some(format!("Vim Command: {}", trimmed)),
                        parentprocessname: "vim".to_string(),
                    });
                }
            }
            "marks" => {
                // Lines look like: "'0  139  0  /etc/ssh/sshd_config"
                if trimmed.starts_with('\'') {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 4 {
                        let mark = parts[0];
                        let line_num = parts[1];
                        let file_edited = parts[3..].join(" ");

                        events.push(Event {
                            timestamp: fallback_timestamp.clone(),
                            computer: computer_name.to_string(),
                            artifact: "linux:editor:vim_file_edit".to_string(),
                            event_id: 0,
                            pid: 0,
                            subject_username: user.clone(),
                            target_username: user.clone(),
                            processname: "vim".to_string(),
                            commandline: Some(format!("Edited File: {} (mark {}, line {})", file_edited, mark, line_num)),
                            parentprocessname: "vim".to_string(),
                        });
                    }
                }
            }
            _ => {
                // Also check file navigation markers in viminfo (lines starting with "> /path/to/file")
                if trimmed.starts_with("> ") && trimmed.len() > 2 {
                    let file_edited = &trimmed[2..];
                    events.push(Event {
                        timestamp: fallback_timestamp.clone(),
                        computer: computer_name.to_string(),
                        artifact: "linux:editor:vim_file_edit".to_string(),
                        event_id: 0,
                        pid: 0,
                        subject_username: user.clone(),
                        target_username: user.clone(),
                        processname: "vim".to_string(),
                        commandline: Some(format!("Opened/Edited File: {}", file_edited)),
                        parentprocessname: "vim".to_string(),
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
    fn test_parse_timestamped_bash_history() {
        let temp_file = std::env::temp_dir().join(format!("test_bash_hist_{}.txt", std::process::id()));
        {
            let mut f = File::create(&temp_file).unwrap();
            writeln!(f, "#1710766331").unwrap();
            writeln!(f, "vi /etc/salt/minion.d/susemanager.conf").unwrap();
            writeln!(f, "#1749556232").unwrap();
            writeln!(f, "vi /etc/ssh/sshd_config").unwrap();
        }

        let events = parse_bash_history(&temp_file, "LINUXHOST");
        let _ = std::fs::remove_file(&temp_file);

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].processname, "vi");
        assert_eq!(events[0].commandline, Some("vi /etc/salt/minion.d/susemanager.conf".to_string()));
        assert!(events[0].timestamp.starts_with("2024-03-18"));
    }

    #[test]
    fn test_parse_zsh_history() {
        let temp_file = std::env::temp_dir().join(format!("test_zsh_hist_{}.txt", std::process::id()));
        {
            let mut f = File::create(&temp_file).unwrap();
            writeln!(f, ": 1710766331:0;cat /etc/passwd").unwrap();
        }

        let events = parse_zsh_history(&temp_file, "LINUXHOST");
        let _ = std::fs::remove_file(&temp_file);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].processname, "cat");
        assert_eq!(events[0].commandline, Some("cat /etc/passwd".to_string()));
    }
}
