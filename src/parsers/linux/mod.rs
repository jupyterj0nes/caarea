pub mod audit;
pub mod crash;
pub mod histories;
pub mod packages;
pub mod pacct;
pub mod persistence;
pub mod proc;
pub mod syslog;
pub mod web;
pub mod xbel;

use chrono::Local;
use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

use crate::parsers::evtx::Event;

/// Logs a message with Caarea branding and a human-readable timestamp
fn log_message(silent: bool, message: &str) {
    if !silent {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        println!("[CAAREA {}] {}", timestamp, message);
    }
}

/// Detects the computer hostname from UAC or root filesystem files
pub fn detect_linux_hostname(target: &Path) -> String {
    // 1. Search for hostname.txt anywhere up to depth 5
    for entry in WalkDir::new(target).max_depth(5).into_iter().flatten() {
        let p = entry.path();
        if p.is_file() {
            let fname = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if fname == "hostname.txt" || fname == "hostname" {
                if let Ok(content) = fs::read_to_string(p) {
                    let h = content.trim();
                    if !h.is_empty() && !h.contains('/') && !h.contains('\\') {
                        return h.to_string();
                    }
                }
            }
        }
    }

    // 2. Infer from folder name like uac-lvmercand01.sir.renfe.es-linux-20260926001450
    for entry in WalkDir::new(target).max_depth(3).into_iter().flatten() {
        let name = entry.file_name().to_string_lossy();
        if name.starts_with("uac-") || name.starts_with("uac_results_") {
            let clean = name.strip_prefix("uac-").or_else(|| name.strip_prefix("uac_results_")).unwrap_or(&name);
            let parts: Vec<&str> = clean.split(['-', '_']).collect();
            if !parts.is_empty() && !parts[0].is_empty() {
                return parts[0].to_string();
            }
        }
    }

    // Check directory name or fallback
    target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("LinuxHost")
        .to_string()
}

/// Checks if a directory contains Linux or UAC forensic artifacts
pub fn is_linux_target(target: &Path) -> bool {
    if !target.is_dir() {
        return false;
    }

    for entry in WalkDir::new(target).max_depth(3).into_iter().flatten() {
        if entry.file_type().is_dir() {
            let p = entry.path();
            if p.join("live_response").exists()
                || p.join("[root]").exists()
                || (p.join("etc").exists() && p.join("var").join("log").exists())
                || p.join("var").join("log").exists()
                || p.join("audit.log").exists()
            {
                return true;
            }
        }
    }

    false
}

/// Main entry point for processing Linux execution artifacts (UAC triages or root filesystems)
pub fn process_linux_target(target: &Path, silent: bool) -> Result<Vec<Event>, Box<dyn Error>> {
    let hostname = detect_linux_hostname(target);
    log_message(silent, &format!("🐧 Analyzing Linux execution artifacts for host: [{}]", hostname));

    let mut all_events = Vec::new();

    for entry in WalkDir::new(target).into_iter().flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let filename = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        // 1. Process startup / running state
        if filename == "ps_-axo_pid_user_lstart_args.txt" {
            let events = proc::parse_ps_lstart_file(path, &hostname);
            all_events.extend(events);
            continue;
        }

        // 2. Shell and Editor histories
        if filename == ".bash_history" {
            let events = histories::parse_bash_history(path, &hostname);
            all_events.extend(events);
            continue;
        }

        if filename == ".zsh_history" {
            let events = histories::parse_zsh_history(path, &hostname);
            all_events.extend(events);
            continue;
        }

        if filename == ".viminfo" {
            let events = histories::parse_viminfo(path, &hostname);
            all_events.extend(events);
            continue;
        }

        // 3. Desktop recently used files (recently-used.xbel)
        if filename == "recently-used.xbel" {
            let events = xbel::parse_xbel_file(path, &hostname);
            all_events.extend(events);
            continue;
        }

        // 4. Kernel Process Accounting (pacct / psacct)
        if filename == "pacct" || filename.starts_with("pacct.") {
            let events = pacct::parse_pacct_file(path, &hostname);
            all_events.extend(events);
            continue;
        }

        // 5. Kernel audit logs
        if filename == "audit.log" || filename.starts_with("audit.log.") {
            let events = audit::parse_audit_log(path, &hostname);
            all_events.extend(events);
            continue;
        }

        // 6. Syslog: cron and sudo executions
        if filename == "cron" || filename.starts_with("cron-") || filename == "secure" || filename.starts_with("secure-") || filename == "auth.log" || filename.starts_with("auth.log.") {
            let events = syslog::parse_syslog_file(path, &hostname);
            all_events.extend(events);
            continue;
        }

        // 7. Web server access logs (dynamic execution / webshells)
        if filename.contains("access_log") || filename.contains("access.log") {
            let events = web::parse_web_access_log(path, &hostname);
            all_events.extend(events);
            continue;
        }

        // 8. Crash and segfault logs (dmesg.txt, messages)
        if filename == "dmesg.txt" || filename == "dmesg" {
            let events = crash::parse_segfault_log(path, &hostname);
            all_events.extend(events);
            continue;
        }

        // 9. Software package installations
        if filename.contains("rpm_-q_-a_--queryformat_installtime") {
            let events = packages::parse_rpm_query_file(path, &hostname);
            all_events.extend(events);
            continue;
        }

        if filename == "dpkg.log" || filename.starts_with("dpkg.log.") {
            let events = packages::parse_dpkg_log(path, &hostname);
            all_events.extend(events);
            continue;
        }

        // 10. Scheduled Cron Jobs (etc/cron.d/*, var/spool/cron/*, crontab)
        let path_str = path.to_string_lossy();
        if path_str.contains("cron.d") || path_str.contains("spool/cron") || path_str.contains("spool\\cron") || filename == "crontab" {
            let events = persistence::parse_cron_table_file(path, &hostname);
            all_events.extend(events);
            continue;
        }

        // 11. Systemd Service units
        if (path_str.contains("systemd/system") || path_str.contains("systemd\\system")) && filename.ends_with(".service") {
            let events = persistence::parse_systemd_service_file(path, &hostname);
            all_events.extend(events);
            continue;
        }

        // 12. In-memory running process links / deleted binaries
        if filename == "running_processes_full_paths.txt" {
            let events = persistence::parse_running_processes_paths(path, &hostname);
            all_events.extend(events);
            continue;
        }
    }

    all_events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    if !all_events.is_empty() {
        let unique_artifacts: HashSet<_> = all_events.iter().map(|e| e.artifact.clone()).collect();
        let unique_users: HashSet<_> = all_events.iter().map(|e| e.subject_username.clone()).collect();

        log_message(
            silent,
            &format!(
                "\nSTATS Linux Execution Analysis: {}\n\
                ├─ Host: {}\n\
                ├─ First Event: {}\n\
                ├─ Last Event: {}\n\
                ├─ Total Events: {}\n\
                ├─ Unique Users: {}\n\
                ├─ Unique Artifacts: {:?}\n\
                └─────────────────────────\n",
                target.display(),
                hostname,
                all_events.first().unwrap().timestamp,
                all_events.last().unwrap().timestamp,
                all_events.len(),
                unique_users.len(),
                unique_artifacts
            ),
        );
    }

    Ok(all_events)
}
