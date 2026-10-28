pub mod audit;
pub mod crash;
pub mod histories;
pub mod packages;
pub mod pacct;
pub mod persistence;
pub mod proc;
pub mod syslog;
pub mod timezone;
pub mod web;
pub mod xbel;

pub use timezone::HostTimezone;

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

/// Extracts the host from a UAC output name: `uac-<hostname>-<os>-<YYYYMMDDhhmmss>[.tar.gz]`.
/// Hostnames may themselves contain dashes (`uac-srv-web01-linux-20261028150000` → `srv-web01`).
pub fn hostname_from_uac_name(name: &str) -> Option<String> {
    let stem = name
        .trim_end_matches(".tar.gz")
        .trim_end_matches(".tgz")
        .trim_end_matches(".zip")
        .trim_end_matches(".tar");
    if let Some(rest) = stem.strip_prefix("uac-") {
        let parts: Vec<&str> = rest.split('-').collect();
        let host = if parts.len() >= 3 { parts[..parts.len() - 2].join("-") } else { parts[0].to_string() };
        return Some(host).filter(|h| !h.is_empty() && !h.eq_ignore_ascii_case("unknown"));
    }
    if let Some(rest) = stem.strip_prefix("uac_results_") {
        return rest.split(['-', '_']).next().map(|s| s.to_string()).filter(|h| !h.is_empty());
    }
    None
}

/// Detects the Linux hostname from the evidence itself: a `hostname` file (UAC live_response,
/// /etc/hostname, /proc/sys/kernel/hostname) or a UAC-style folder / archive name.
/// Returns `None` when neither is available.
pub fn detect_linux_hostname_opt(target: &Path) -> Option<String> {
    // 1. Search for hostname.txt anywhere up to depth 5
    for entry in WalkDir::new(target).max_depth(5).into_iter().flatten() {
        let p = entry.path();
        if p.is_file() {
            let fname = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if fname == "hostname.txt" || fname == "hostname" {
                if let Ok(content) = fs::read_to_string(p) {
                    let h = content.trim();
                    if !h.is_empty() && !h.contains('/') && !h.contains('\\') {
                        return Some(h.to_string());
                    }
                }
            }
        }
    }

    // 2. Infer from a folder / archive name like uac-lvmercand01.sir.example.es-linux-20260926001450
    for entry in WalkDir::new(target).max_depth(3).into_iter().flatten() {
        let name = entry.file_name().to_string_lossy();
        if let Some(h) = hostname_from_uac_name(&name) {
            return Some(h);
        }
    }

    None
}

/// Detects the computer hostname, falling back to the directory name
pub fn detect_linux_hostname(target: &Path) -> String {
    detect_linux_hostname_opt(target).unwrap_or_else(|| {
        target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("LinuxHost")
            .to_string()
    })
}

/// Checks if a directory contains Linux or UAC forensic artifacts
pub fn is_linux_target(target: &Path) -> bool {
    if !target.is_dir() {
        return false;
    }

    for entry in WalkDir::new(target).max_depth(3).into_iter().flatten() {
        if entry.file_type().is_dir() {
            let p = entry.path();
            if p.join("live_response").is_dir()
                || p.join("[root]").is_dir()
                || p.join("uac.log").is_file()
                || (p.join("etc").is_dir() && p.join("var").join("log").is_dir())
                || p.join("var").join("log").join("audit").is_dir()
            {
                return true;
            }
        }
    }

    false
}

fn lower_components(path: &Path) -> Vec<String> {
    path.components()
        .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
        .collect()
}

/// True for files that hold crontab *definitions*: /etc/crontab, /etc/cron.d/*,
/// /var/spool/cron/<user>, /var/spool/cron/crontabs/<user>.
/// Scripts under cron.daily / cron.hourly / ... are shell scripts, not crontabs.
pub fn is_cron_definition(path: &Path) -> bool {
    let comps = lower_components(path);
    let n = comps.len();
    if n < 2 {
        return false;
    }
    let filename = &comps[n - 1];
    let parent = &comps[n - 2];

    if filename.starts_with('.') {
        return false;
    }
    if parent == "cron.d" {
        return true;
    }
    if n >= 3 && comps[n - 3] == "spool" && (parent == "cron" || parent == "crontabs") {
        return true;
    }
    if n >= 4 && comps[n - 4] == "spool" && comps[n - 3] == "cron" && parent == "crontabs" {
        return true;
    }
    filename == "crontab" && parent != "cron.daily" && parent != "cron.hourly" && parent != "cron.weekly" && parent != "cron.monthly"
}

/// True for systemd unit files under a `systemd/system` (or `systemd/user`) directory.
fn is_systemd_unit(path: &Path, filename: &str) -> bool {
    if !filename.ends_with(".service") {
        return false;
    }
    let comps = lower_components(path);
    comps.windows(2).any(|w| w[0] == "systemd" && (w[1] == "system" || w[1] == "user"))
}

/// Routes a single file to the Linux parser(s) that understand it, by file name and location.
/// Returns an empty vector for files that are not Linux execution artifacts.
pub fn process_linux_file(path: &Path, hostname: &str) -> Vec<Event> {
    process_linux_file_tz(path, hostname, &HostTimezone::utc())
}

/// Same as [`process_linux_file`] with the host time zone used for zone-less timestamps.
pub fn process_linux_file_tz(path: &Path, hostname: &str, tz: &HostTimezone) -> Vec<Event> {
    let filename = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return Vec::new(),
    };
    let compressed = filename.ends_with(".gz") || filename.ends_with(".xz") || filename.ends_with(".bz2");

    // 1. Process startup / running state
    if filename == "ps_-axo_pid_user_lstart_args.txt" {
        return proc::parse_ps_lstart_file(path, hostname, tz);
    }

    // 2. Shell and Editor histories
    if filename == ".bash_history" || filename == ".sh_history" || filename == ".ash_history" || filename == ".history" {
        return histories::parse_bash_history(path, hostname);
    }
    if filename == ".zsh_history" {
        return histories::parse_zsh_history(path, hostname);
    }
    if filename == ".viminfo" {
        return histories::parse_viminfo(path, hostname);
    }

    // 3. Desktop recently used files (recently-used.xbel)
    if filename == "recently-used.xbel" {
        return xbel::parse_xbel_file(path, hostname);
    }

    // 4. Kernel Process Accounting (pacct / psacct / acct)
    if filename == "pacct" || filename.starts_with("pacct.") || filename == "acct" || filename.starts_with("acct.") {
        return if compressed { Vec::new() } else { pacct::parse_pacct_file(path, hostname) };
    }

    // 5. Kernel audit logs
    if filename == "audit.log" || filename.starts_with("audit.log.") {
        return if compressed { Vec::new() } else { audit::parse_audit_log(path, hostname) };
    }

    // 6. Syslog family: cron, sudo and su executions (plus kernel segfaults in the same files)
    let is_syslog_family = filename == "cron"
        || filename.starts_with("cron-")
        || filename.starts_with("cron.log")
        || filename == "secure"
        || filename.starts_with("secure-")
        || filename == "auth.log"
        || filename.starts_with("auth.log.")
        || filename == "syslog"
        || filename.starts_with("syslog.")
        || filename == "messages"
        || filename.starts_with("messages-")
        || filename.starts_with("messages.")
        || filename == "kern.log"
        || filename.starts_with("kern.log.");
    if is_syslog_family {
        if compressed {
            return Vec::new();
        }
        let mut events = syslog::parse_syslog_file(path, hostname, tz);
        events.extend(crash::parse_segfault_log(path, hostname));
        return events;
    }

    // 7. Web server access logs (dynamic execution / webshells)
    if filename.contains("access_log") || filename.contains("access.log") {
        return if compressed { Vec::new() } else { web::parse_web_access_log(path, hostname, tz) };
    }

    // 8. Crash and segfault logs (dmesg)
    if filename == "dmesg.txt" || filename == "dmesg" || filename.starts_with("dmesg.") {
        return if compressed { Vec::new() } else { crash::parse_segfault_log(path, hostname) };
    }

    // 9. Software package installations
    if filename.contains("rpm_-q_-a_--queryformat_installtime") {
        return packages::parse_rpm_query_file(path, hostname);
    }
    if filename == "dpkg.log" || filename.starts_with("dpkg.log.") {
        return if compressed { Vec::new() } else { packages::parse_dpkg_log(path, hostname, tz) };
    }

    // 10. Scheduled Cron Jobs (etc/crontab, etc/cron.d/*, var/spool/cron/*)
    if is_cron_definition(path) {
        return persistence::parse_cron_table_file(path, hostname);
    }

    // 11. Systemd Service units
    if is_systemd_unit(path, filename) {
        return persistence::parse_systemd_service_file(path, hostname);
    }

    // 12. In-memory running process links / deleted binaries
    if filename == "running_processes_full_paths.txt" {
        return persistence::parse_running_processes_paths(path, hostname);
    }

    Vec::new()
}

/// Main entry point for processing Linux execution artifacts (UAC triages or root filesystems)
pub fn process_linux_target(target: &Path, silent: bool) -> Result<Vec<Event>, Box<dyn Error>> {
    process_linux_target_with_hint(target, silent, None, None)
}

/// Same as [`process_linux_target`] with a hostname hint discovered during ingestion (triage
/// package name) and an optional time zone override (`--tz`). Evidence-internal hostname files
/// still win over the hint; without an override the zone is detected from the evidence.
pub fn process_linux_target_with_hint(
    target: &Path,
    silent: bool,
    hint: Option<&str>,
    tz_override: Option<&HostTimezone>,
) -> Result<Vec<Event>, Box<dyn Error>> {
    let hostname = detect_linux_hostname_opt(target)
        .or_else(|| hint.map(|h| h.to_string()))
        .unwrap_or_else(|| detect_linux_hostname(target));
    let tz = tz_override.cloned().unwrap_or_else(|| HostTimezone::detect(target));
    log_message(
        silent,
        &format!(
            "🐧 Analyzing Linux execution artifacts for host: [{}], host time zone: {}",
            hostname,
            tz.describe()
        ),
    );

    let mut all_events = Vec::new();

    for entry in WalkDir::new(target).into_iter().flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        all_events.extend(process_linux_file_tz(path, &hostname, &tz));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cron_definition_detection() {
        assert!(is_cron_definition(Path::new("/x/[root]/etc/cron.d/sysstat")));
        assert!(is_cron_definition(Path::new("C:\\triage\\etc\\cron.d\\backup")));
        assert!(is_cron_definition(Path::new("/x/etc/crontab")));
        assert!(is_cron_definition(Path::new("/x/var/spool/cron/root")));
        assert!(is_cron_definition(Path::new("/x/var/spool/cron/crontabs/www-data")));
        // Scripts, not crontabs:
        assert!(!is_cron_definition(Path::new("/x/etc/cron.daily/logrotate")));
        assert!(!is_cron_definition(Path::new("/x/etc/cron.hourly/0anacron")));
        assert!(!is_cron_definition(Path::new("/x/etc/cron.d/.placeholder")));
    }

    #[test]
    fn test_uac_hostname_parsing() {
        assert_eq!(hostname_from_uac_name("uac-srv-web01-linux-20261028150000.tar.gz").as_deref(), Some("srv-web01"));
        assert_eq!(hostname_from_uac_name("uac-lvmercand01.sir.example.es-linux-20260926001450").as_deref(), Some("lvmercand01.sir.example.es"));
        assert_eq!(hostname_from_uac_name("uac-host-aix-20260101000000").as_deref(), Some("host"));
        assert_eq!(hostname_from_uac_name("uac_results_box01_full").as_deref(), Some("box01"));
        assert_eq!(hostname_from_uac_name("kape_output.zip"), None);
    }

    #[test]
    fn test_systemd_unit_detection() {
        assert!(is_systemd_unit(Path::new("/x/etc/systemd/system/evil.service"), "evil.service"));
        assert!(is_systemd_unit(Path::new("/x/usr/lib/systemd/system/sshd.service"), "sshd.service"));
        assert!(!is_systemd_unit(Path::new("/x/etc/systemd/system/evil.timer"), "evil.timer"));
        assert!(!is_systemd_unit(Path::new("/x/home/u/evil.service"), "evil.service"));
    }
}
