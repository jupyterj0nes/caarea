pub mod audit;
pub mod cloudinit;
pub mod containers;
pub mod crash;
pub mod histories;
pub mod journald;
pub mod packages;
pub mod pacct;
pub mod persistence;
pub mod proc;
pub mod syslog;
pub mod timezone;
pub mod utmp;
pub mod web;
pub mod xbel;

pub use timezone::HostTimezone;

use chrono::Local;
use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::path::Path;
use rayon::prelude::*;
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

/// Inflates a `.gz` or `.xz` log into a private temporary folder, keeping the file name without
/// the compression suffix so the usual routing applies. `None` when the format is not supported
/// or the data is damaged. Files above 1 GB inflated are cut there.
fn decompress_to_temp(path: &Path) -> Option<std::path::PathBuf> {
    use std::io::Read;
    const LIMIT: u64 = 1 << 30;
    let name = path.file_name()?.to_string_lossy().to_string();
    let (plain, kind) = if let Some(p) = name.strip_suffix(".gz") {
        (p.to_string(), "gz")
    } else if let Some(p) = name.strip_suffix(".xz") {
        (p.to_string(), "xz")
    } else {
        return None;
    };
    let raw = fs::File::open(path).ok()?;
    let mut out: Vec<u8> = Vec::new();
    match kind {
        "gz" => {
            let dec = flate2::read::GzDecoder::new(std::io::BufReader::new(raw));
            dec.take(LIMIT).read_to_end(&mut out).ok()?;
        }
        _ => {
            let mut reader = std::io::BufReader::new(raw);
            lzma_rs::xz_decompress(&mut reader, &mut out).ok()?;
            out.truncate(LIMIT as usize);
        }
    }
    let dir = std::env::temp_dir().join(format!("caarea_inflate_{}_{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)));
    fs::create_dir_all(&dir).ok()?;
    let tmp = dir.join(plain);
    fs::write(&tmp, out).ok()?;
    // keep the rotated file's own time for the parsers that use it
    if let Ok(meta) = fs::metadata(path) {
        if let Ok(m) = meta.modified() {
            if let Ok(f) = fs::OpenOptions::new().write(true).open(&tmp) {
                let _ = f.set_modified(m);
            }
        }
    }
    Some(tmp)
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

    // 0. Rotated logs compressed by logrotate (`auth.log.2.gz`, `audit.log.1.xz`): inflated to a
    //    temporary copy with the plain name and routed again. bzip2 is not supported.
    if compressed {
        return match decompress_to_temp(path) {
            Some(tmp) => {
                let events = process_linux_file_tz(&tmp, hostname, tz);
                if let Some(dir) = tmp.parent() {
                    let _ = fs::remove_dir_all(dir);
                }
                events
            }
            None => Vec::new(),
        };
    }

    // 0b. systemd journal files
    if journald::is_journal_file(filename) {
        return journald::parse_file(path, hostname);
    }

    // 0c. containers, cloud-init, cron mail spools
    if containers::is_container_file(path, filename) {
        return containers::parse_file(path, hostname);
    }
    if cloudinit::is_cloud_init_log(filename) {
        return cloudinit::parse_cloud_init_log(path, hostname, tz);
    }
    if cloudinit::is_mail_spool(path) {
        return cloudinit::parse_mail_spool(path, hostname);
    }

    // 1. Process startup / running state
    if filename == "ps_-axo_pid_user_lstart_args.txt" {
        return proc::parse_ps_lstart_file(path, hostname, tz);
    }

    // 2. Shell and Editor histories
    if filename == ".bash_history"
        || filename == ".sh_history"
        || filename == ".ash_history"
        || filename == ".history"
        || filename == ".python_history"
        || filename == ".mysql_history"
        || filename == ".psql_history"
        || filename == ".sqlite_history"
        || filename == ".node_repl_history"
        || filename == ".irb_history"
        || filename == ".rediscli_history"
        || filename == ".lesshst"
    {
        return histories::parse_bash_history(path, hostname);
    }
    if filename == ".zsh_history" {
        return histories::parse_zsh_history(path, hostname);
    }
    if filename == "fish_history" {
        return histories::parse_fish_history(path, hostname);
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
    if (filename == "history.log" || filename.starts_with("history.log.")) && lower_components(path).iter().any(|c| c == "apt") {
        return packages::parse_apt_history(path, hostname, tz);
    }
    if filename == "pacman.log" || filename.starts_with("pacman.log.") {
        return packages::parse_pacman_log(path, hostname);
    }
    if filename == "dnf.rpm.log" || filename.starts_with("dnf.rpm.log.") || filename == "yum.log" || filename.starts_with("yum.log.") {
        return packages::parse_rpm_log(path, hostname, tz);
    }
    if filename == "history" && lower_components(path).iter().any(|c| c == "zypp") {
        return packages::parse_zypp_history(path, hostname, tz);
    }

    // 9b. Login records
    if utmp::is_utmp_file(filename) {
        return utmp::parse_file(path, hostname);
    }

    // 9c. systemd timers: last trigger stamp files and timer units
    if filename.starts_with("stamp-") && filename.ends_with(".timer") {
        return persistence::parse_timer_stamp(path, hostname);
    }
    if filename.ends_with(".timer") && lower_components(path).windows(2).any(|w| w[0] == "systemd" && (w[1] == "system" || w[1] == "user")) {
        return persistence::parse_timer_unit(path, hostname);
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

/// At the root of a staged evidence tree: the files (one per line, relative
/// to the root, forward slashes) whose modification time on the host is not
/// known, because the package they came in carries none for them. The time
/// such a file has on disk is the moment it was unpacked.
pub const UNDATED_MARKER: &str = ".caarea_undated";

/// Empties the time of the events that were dated by the file's own
/// modification time when that time is not the host's (see
/// [`UNDATED_MARKER`]). An event with a time of its own, a log line's, keeps it.
fn blank_unpack_time(events: &mut [Event], path: &Path) {
    let Some(unpacked) = fs::metadata(path).ok().and_then(|m| m.modified().ok()).map(crate::utils::systemtime_to_iso) else { return };
    for e in events.iter_mut() {
        if e.timestamp == unpacked {
            e.timestamp.clear();
        }
    }
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

    // The files are listed first and sorted, then parsed one per task; `collect` keeps the
    // list order, so the timeline does not depend on the thread count or on how the file
    // system enumerates a directory.
    let mut paths: Vec<std::path::PathBuf> = WalkDir::new(target)
        .into_iter()
        .flatten()
        .filter(|e| e.path().is_file() && e.file_name() != UNDATED_MARKER)
        .map(|e| e.into_path())
        .collect();
    paths.sort();
    let undated: HashSet<String> = fs::read_to_string(target.join(UNDATED_MARKER)).map(|l| l.lines().map(str::to_string).collect()).unwrap_or_default();
    let per_file: Vec<Vec<Event>> = paths
        .par_iter()
        .map(|path| {
            let mut file_events = process_linux_file_tz(path, &hostname, &tz);
            if !undated.is_empty() {
                let relative = path.strip_prefix(target).map(|p| p.to_string_lossy().replace('\\', "/")).unwrap_or_default();
                if undated.contains(&relative) {
                    blank_unpack_time(&mut file_events, path);
                }
            }
            crate::utils::stamp_source_file(&mut file_events, &crate::utils::source_file_name(target, path));
            file_events
        })
        .collect();
    all_events.extend(per_file.into_iter().flatten());

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
    /// A staged tree whose marker names one file as undated: the unit dated by that file's
    /// own time comes out with no time; the one whose file has a known time keeps it, and so
    /// does an event with a time of its own.
    #[test]
    fn an_event_dated_by_an_unpacked_file_carries_no_time() {
        let root = std::env::temp_dir().join(format!("caarea_undated_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let units = root.join("etc").join("systemd").join("system");
        fs::create_dir_all(&units).unwrap();
        let unit = "[Unit]
Description=x
[Service]
ExecStart=/opt/x/run.sh
[Install]
WantedBy=multi-user.target
";
        fs::write(units.join("undated.service"), unit).unwrap();
        fs::write(units.join("dated.service"), unit.replace("/opt/x/", "/opt/y/")).unwrap();
        let known = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_709_294_400); // 2024-03-01T12:00:00Z
        fs::OpenOptions::new().write(true).open(units.join("dated.service")).unwrap().set_modified(known).unwrap();
        fs::write(root.join(UNDATED_MARKER), "etc/systemd/system/undated.service").unwrap();

        let events = process_linux_target_with_hint(&root, true, Some("websrv01"), None).unwrap();
        let of = |needle: &str| events.iter().filter(|e| e.commandline.as_deref().unwrap_or("").contains(needle) || e.processname.contains(needle)).collect::<Vec<_>>();
        let (undated, dated) = (of("/opt/x/"), of("/opt/y/"));
        assert!(!undated.is_empty() && !dated.is_empty(), "{:?}", events.iter().map(|e| (&e.artifact, &e.processname, &e.commandline)).collect::<Vec<_>>());
        assert!(undated.iter().all(|e| e.timestamp.is_empty()), "{:?}", undated.iter().map(|e| &e.timestamp).collect::<Vec<_>>());
        assert!(dated.iter().all(|e| e.timestamp.starts_with("2024-03-01T12:00:00")), "{:?}", dated.iter().map(|e| &e.timestamp).collect::<Vec<_>>());
        // the marker itself is not evidence
        assert!(events.iter().all(|e| !e.source_file.contains(UNDATED_MARKER)));

        // an event with a time of its own keeps it, whatever the file's time
        let log = root.join("x.log");
        fs::write(&log, "x").unwrap();
        let mut own = vec![events[0].clone()];
        own[0].timestamp = "2026-11-05T13:37:28.027709Z".to_string();
        blank_unpack_time(&mut own, &log);
        assert_eq!(own[0].timestamp, "2026-11-05T13:37:28.027709Z");
        let _ = fs::remove_dir_all(&root);
    }

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
