pub mod carve;
mod cli;
pub mod ingest;
pub mod parsers;
pub mod provenance;
pub mod timeline;
pub mod utils;

use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use chrono::Local;
use parsers::evtx::{self, Event};
use parsers::linux::HostTimezone;
use parsers::registry;
pub use provenance::{artifact_base, Provenance};

/// Applies a provenance (shadow copy, recovered, carved) to every event of a directory.
/// Live provenance leaves the artifact names untouched.
pub fn tag_events(events: &mut [Event], prov: &Provenance) {
    if prov.is_live() {
        return;
    }
    for e in events.iter_mut() {
        e.artifact = prov.apply(&e.artifact);
    }
}

/// Logs a message with Caarea branding and a human-readable timestamp
fn log_message(silent: bool, message: &str) {
    if !silent {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        println!("[CAAREA {}] {}", timestamp, message);
    }
}

/// Removes exact duplicates (same artifact seen twice, e.g. from a live file and a copy in a
/// triage package, or from the live volume and a shadow copy). Two events are duplicates only
/// when *every* column is identical (ignoring the provenance), so distinct executions that
/// share a timestamp are preserved. When twins collide the one with the best provenance is
/// kept, in this order: live, shadow copy, recovered structure, transaction log, carved,
/// carved and recovered. Among shadow copies the oldest snapshot wins; among carved rows the
/// lowest offset.
pub fn dedup_events(events: &mut Vec<Event>) -> usize {
    let before = events.len();
    events.sort_by(|a, b| {
        let (base_a, prov_a) = provenance::split(&a.artifact);
        let (base_b, prov_b) = provenance::split(&b.artifact);
        a.timestamp
            .cmp(&b.timestamp)
            .then_with(|| a.computer.cmp(&b.computer))
            .then_with(|| base_a.cmp(base_b))
            .then_with(|| a.event_id.cmp(&b.event_id))
            .then_with(|| a.pid.cmp(&b.pid))
            .then_with(|| a.subject_username.cmp(&b.subject_username))
            .then_with(|| a.target_username.cmp(&b.target_username))
            .then_with(|| a.processname.cmp(&b.processname))
            .then_with(|| a.commandline.cmp(&b.commandline))
            .then_with(|| a.parentprocessname.cmp(&b.parentprocessname))
            .then_with(|| prov_a.origin.rank().cmp(&prov_b.origin.rank()))
            .then_with(|| prov_a.detail.cmp(&prov_b.detail))
    });
    events.dedup_by(|later, first| {
        later.timestamp == first.timestamp
            && later.computer == first.computer
            && artifact_base(&later.artifact) == artifact_base(&first.artifact)
            && later.event_id == first.event_id
            && later.pid == first.pid
            && later.subject_username == first.subject_username
            && later.target_username == first.target_username
            && later.processname == first.processname
            && later.commandline == first.commandline
            && later.parentprocessname == first.parentprocessname
    });
    before - events.len()
}

/// Resolves the effective TOI window from `--toi/--toi-window` or `--start-time/--end-time`.
fn resolve_time_window(
    toi: Option<&str>,
    toi_window_hours: f64,
    start_time: Option<&str>,
    end_time: Option<&str>,
) -> Result<(Option<String>, Option<String>), String> {
    if let Some(center) = toi {
        let center_dt = utils::parse_flexible_time(center)
            .ok_or_else(|| format!("❌ Error: cannot parse --toi value '{}'", center))?;
        if !toi_window_hours.is_finite() || toi_window_hours < 0.0 {
            return Err("❌ Error: --toi-window must be a non-negative number of hours".to_string());
        }
        let half = chrono::Duration::seconds((toi_window_hours * 3600.0) as i64);
        return Ok((Some(utils::iso_utc(&(center_dt - half))), Some(utils::iso_utc(&(center_dt + half)))));
    }
    Ok((start_time.map(|s| s.to_string()), end_time.map(|s| s.to_string())))
}

/// Main function to run the tool
pub fn run() -> Result<(), Box<dyn Error>> {
    // Build CLI and parse arguments
    let matches = cli::build_cli().get_matches();

    // Extract CLI arguments
    let directories = matches.get_many::<String>("directories").map(|v| v.cloned().collect());
    let files = matches.get_many::<String>("files").map(|v| v.cloned().collect());
    let modules = matches.get_one::<String>("modules").map(|s| s.as_str()).unwrap_or("all");
    let output = matches.get_one::<String>("output").unwrap();
    let silent = matches.get_flag("silent");
    let overwrite = matches.get_flag("overwrite");
    let toi = matches.get_one::<String>("toi").map(|s| s.as_str());
    let toi_window: f64 = matches
        .get_one::<String>("toi_window")
        .and_then(|s| s.parse().ok())
        .unwrap_or(24.0);
    let start_arg = matches.get_one::<String>("start_time").map(|s| s.as_str());
    let end_arg = matches.get_one::<String>("end_time").map(|s| s.as_str());
    let tz_override: Option<HostTimezone> = match matches.get_one::<String>("tz") {
        Some(spec) => Some(HostTimezone::from_spec(spec).ok_or_else(|| {
            format!("❌ Error: cannot parse --tz value '{}' (use an IANA name such as Europe/Madrid, UTC, or ±HH:MM)", spec)
        })?),
        None => None,
    };

    log_message(silent, &format!("CAAREA v{} - Execution Artifacts Timeliner", env!("CARGO_PKG_VERSION")));
    log_message(silent, "Extracting and analyzing execution artifacts for digital forensics and incident response (DFIR)");

    // Validate inputs
    cli::validate_input(&directories, &files, output, modules, silent, overwrite)?;

    if let Some(ref tz) = tz_override {
        log_message(silent, &format!("🕒 Linux host time zone forced by --tz: {}", tz.name));
    }

    let (start_time, end_time) = resolve_time_window(toi, toi_window, start_arg, end_arg)?;
    if start_time.is_some() || end_time.is_some() {
        log_message(
            silent,
            &format!(
                "🎯 Time of Interest (TOI) filter active: [{} .. {}] (all timestamps UTC)",
                start_time.as_deref().unwrap_or("Beginning"),
                end_time.as_deref().unwrap_or("End")
            ),
        );
    }

    // Prepare evidence targets (unpacking triage archives, ZIP, TAR.GZ, disk images if present)
    let stage_dir = matches.get_one::<String>("stage_dir").map(std::path::PathBuf::from);
    let workspace = ingest::prepare_evidence(directories.as_deref(), files.as_deref(), silent, stage_dir.as_deref())?;

    let run_evtx = modules == "evtx" || modules == "all";
    let run_registry = modules == "registry" || modules == "all";
    let run_windows = modules == "windows" || modules == "all";
    let run_linux = modules == "linux" || modules == "all";

    let mut all_events: Vec<Event> = vec![];

    // Process directories. In "all" mode every parser family runs on every directory: a
    // mixed evidence folder (KAPE zips next to UAC tarballs) must not lose one platform.
    for dir in &workspace.directories {
        let path = Path::new(dir);
        let hint = workspace.hostname_hint(dir);
        let origin = workspace.origin(dir);
        let looks_linux = parsers::linux::is_linux_target(path);
        log_message(
            silent,
            &format!(
                "📁 Target {} detected as {}{}{}",
                path.display(),
                if looks_linux { "Linux / UAC" } else { "Windows / generic" },
                hint.map(|h| format!(" [host hint: {}]", h)).unwrap_or_default(),
                origin.map(|o| format!(" [{}]", o)).unwrap_or_default()
            ),
        );

        let mut dir_events: Vec<Event> = Vec::new();
        if run_evtx {
            dir_events.extend(evtx::process_evtx_target(path, silent)?);
        }
        if run_registry {
            dir_events.extend(registry::process_registry_target_with_hint(path, silent, hint)?);
        }
        if run_windows {
            dir_events.extend(parsers::windows::process_windows_target(path, silent, hint));
            dir_events.extend(parsers::ntfs::process_ntfs_target(path, silent, hint));
        }
        if run_linux {
            dir_events.extend(parsers::linux::process_linux_target_with_hint(path, silent, hint, tz_override.as_ref())?);
        }
        if let Some(prov) = origin {
            tag_events(&mut dir_events, prov);
        }
        all_events.extend(dir_events);
    }

    // Process individual files
    for file in &workspace.files {
        let path = Path::new(file);

        // Detect file type by header / magic bytes
        let mut header = [0u8; 8];
        let bytes_read = File::open(path).and_then(|mut f| f.read(&mut header)).unwrap_or(0);
        let looks_evtx = utils::is_evtx(&header[..bytes_read]);
        let looks_hive = utils::is_registry_hive(&header[..bytes_read.min(4)]);

        if looks_evtx {
            if run_evtx {
                all_events.extend(evtx::process_evtx_target(path, silent)?);
            }
        } else if looks_hive {
            if run_registry {
                all_events.extend(registry::parse_registry_file(path, silent)?);
            }
        } else if let Some(win_events) = parsers::windows::process_windows_file(path, &header[..bytes_read], silent) {
            if run_windows {
                all_events.extend(win_events);
            }
        } else if let Some(ntfs_events) = parsers::ntfs::process_ntfs_file(path, &header[..bytes_read], silent) {
            if run_windows {
                all_events.extend(ntfs_events);
            }
        } else if run_linux {
            let parent = path.parent();
            let hostname = parent
                .map(parsers::linux::detect_linux_hostname)
                .unwrap_or_else(|| "LinuxHost".to_string());
            let tz = tz_override
                .clone()
                .or_else(|| parent.map(HostTimezone::detect))
                .unwrap_or_else(HostTimezone::utc);
            let linux_events = parsers::linux::process_linux_file_tz(path, &hostname, &tz);
            if linux_events.is_empty() {
                log_message(silent, &format!("⚠️ No parser recognised file: {}", path.display()));
            }
            all_events.extend(linux_events);
        } else {
            log_message(silent, &format!("⚠️ File is neither EVTX nor a registry hive, skipped: {}", path.display()));
        }
    }

    // Remove exact duplicates (same artifact collected twice)
    let removed = dedup_events(&mut all_events);
    if removed > 0 {
        log_message(silent, &format!("Removed {} exact duplicate events.", removed));
    }
    let pre_filter_count = all_events.len();

    // Apply Time of Interest (TOI) filter if requested
    let filtered_events = utils::filter_by_toi(all_events, start_time.as_deref(), end_time.as_deref());
    if start_time.is_some() || end_time.is_some() {
        log_message(
            silent,
            &format!(
                "Filtered {} events to {} events within Time of Interest window.",
                pre_filter_count,
                filtered_events.len()
            ),
        );
    }

    // Sort and export the timeline
    let sorted_timeline = timeline::create_timeline(filtered_events, vec![]);
    log_message(silent, &format!("Saving timeline to: {}", output));
    timeline::export_timeline(&sorted_timeline, output, silent)?;

    // Show total extracted events at the end
    log_message(silent, "✅ Processing completed successfully!");
    log_message(silent, &format!("Extracted a total of {} execution events.", sorted_timeline.len()));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(ts: &str, proc_name: &str, cmd: &str, pid: u32) -> Event {
        Event {
            timestamp: ts.to_string(),
            computer: "H".to_string(),
            artifact: "linux:shell:bash_history".to_string(),
            event_id: 0,
            pid,
            subject_username: "u".to_string(),
            target_username: "u".to_string(),
            processname: proc_name.to_string(),
            commandline: Some(cmd.to_string()),
            parentprocessname: "bash".to_string(),
        }
    }

    #[test]
    fn test_dedup_keeps_distinct_events_sharing_timestamp() {
        let ts = "2026-10-28T13:31:52.000000Z";
        let mut events = vec![
            ev(ts, "cd", "cd /tmp", 0),
            ev(ts, "cd", "cd /dev/shm", 0),
            ev(ts, "chmod", "chmod +x x.sh", 0),
            ev(ts, "chmod", "chmod 777 /tmp", 0),
            ev(ts, "chmod", "chmod 777 /tmp", 0), // true duplicate
            ev(ts, "cmd.exe", "cmd /c a", 10),
            ev(ts, "cmd.exe", "cmd /c a", 11), // same command, different pid: distinct
        ];
        let removed = dedup_events(&mut events);
        assert_eq!(removed, 1);
        assert_eq!(events.len(), 6);
    }

    #[test]
    fn test_dedup_prefers_live_over_shadow_copy_twins() {
        let ts = "2026-09-04T08:00:00.000000Z";
        let live = ev(ts, "cmd.exe", "cmd /c live", 10);
        let mut old_copy = ev(ts, "cmd.exe", "cmd /c live", 10);
        let mut only_in_vss = ev(ts, "evil.exe", "evil.exe -x", 11);
        let mut only_in_vss_newer = ev(ts, "evil.exe", "evil.exe -x", 11);
        tag_events(std::slice::from_mut(&mut old_copy), &Provenance::vss("2026-09-01T00:00:00Z"));
        tag_events(std::slice::from_mut(&mut only_in_vss_newer), &Provenance::vss("2026-09-02T00:00:00Z"));
        tag_events(std::slice::from_mut(&mut only_in_vss), &Provenance::vss("2026-09-01T00:00:00Z"));
        assert_eq!(only_in_vss.artifact, "linux:shell:bash_history:vss [2026-09-01T00:00:00Z]");
        assert_eq!(artifact_base(&only_in_vss.artifact), "linux:shell:bash_history");

        let mut events = vec![old_copy, only_in_vss_newer, live.clone(), only_in_vss];
        let removed = dedup_events(&mut events);
        assert_eq!(removed, 2);
        assert_eq!(events.len(), 2);
        assert!(events.iter().any(|e| e == &live), "live twin must survive untagged");
        assert!(events.iter().any(|e| e.artifact.ends_with(":vss [2026-09-01T00:00:00Z]") && e.processname == "evil.exe"));
    }

    #[test]
    fn test_dedup_precedence_is_live_vss_deleted_carved() {
        use provenance::Origin;
        let ts = "2026-09-04T08:00:00.000000Z";
        let mk = |origin: Origin, detail: &str| {
            let mut e = ev(ts, "x.exe", "x.exe", 1);
            tag_events(std::slice::from_mut(&mut e), &Provenance::new(origin, detail));
            e
        };
        let mut events = vec![
            mk(Origin::CarvedDeleted, "@0x10"),
            mk(Origin::Carved, "@0x20"),
            mk(Origin::Carved, "@0x10"),
            mk(Origin::Deleted, ""),
            mk(Origin::Vss, "2026-09-02T00:00:00Z"),
        ];
        assert_eq!(dedup_events(&mut events), 4);
        assert_eq!(events[0].artifact, "linux:shell:bash_history:vss [2026-09-02T00:00:00Z]");

        let mut carved_only = vec![mk(Origin::Carved, "@0x20"), mk(Origin::Carved, "@0x10")];
        assert_eq!(dedup_events(&mut carved_only), 1);
        assert_eq!(carved_only[0].artifact, "linux:shell:bash_history:carved [@0x10]");

        let live = ev(ts, "x.exe", "x.exe", 1);
        let mut with_live = vec![mk(Origin::Deleted, ""), live.clone()];
        assert_eq!(dedup_events(&mut with_live), 1);
        assert_eq!(with_live[0], live);
    }

    #[test]
    fn test_resolve_time_window() {
        let (s, e) = resolve_time_window(Some("2026-09-24T12:00:00Z"), 6.0, None, None).unwrap();
        assert_eq!(s.as_deref(), Some("2026-09-24T06:00:00.000000Z"));
        assert_eq!(e.as_deref(), Some("2026-09-24T18:00:00.000000Z"));
        let (s2, e2) = resolve_time_window(None, 24.0, Some("2025-01-01"), None).unwrap();
        assert_eq!(s2.as_deref(), Some("2025-01-01"));
        assert!(e2.is_none());
        assert!(resolve_time_window(Some("not a date"), 1.0, None, None).is_err());
    }
}
