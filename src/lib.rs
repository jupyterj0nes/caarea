mod cli;
pub mod ingest;
pub mod parsers;
pub mod timeline;
pub mod utils;

use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use chrono::Local;
use parsers::evtx;
use parsers::registry;

/// Logs a message with Caarea branding and a human-readable timestamp
fn log_message(silent: bool, message: &str) {
    if !silent {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        println!("[CAAREA {}] {}", timestamp, message);
    }
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
    let start_time = matches.get_one::<String>("start_time").map(|s| s.as_str());
    let end_time = matches.get_one::<String>("end_time").map(|s| s.as_str());

    if matches.get_one::<String>("modules").is_none() {
        log_message(silent, "No module specified. Defaulting to 'all' for full analysis.");
    }

    log_message(silent, "CAAREA - Execution Artifacts Timeliner");
    log_message(silent, "Extracting and analyzing execution artifacts for digital forensics and incident response (DFIR)");

    if start_time.is_some() || end_time.is_some() {
        log_message(
            silent,
            &format!(
                "🎯 Time of Interest (TOI) filter active: [{} .. {}]",
                start_time.unwrap_or("Beginning"),
                end_time.unwrap_or("End")
            ),
        );
    }

    // Validate inputs
    cli::validate_input(&directories, &files, output, silent, overwrite)?;

    // Prepare evidence targets (unpacking triage archives, ZIP, TAR.GZ if present)
    let workspace = ingest::prepare_evidence(
        directories.as_deref(),
        files.as_deref(),
        silent,
    )?;

    // Process files and directories
    let mut all_events = vec![];

    // Process directories with intelligent platform routing
    for dir in &workspace.directories {
        let path = Path::new(dir);

        if parsers::linux::is_linux_target(path) {
            // Target is a Linux system / UAC triage
            if modules == "linux" || modules == "all" {
                let linux_events = parsers::linux::process_linux_target(path, silent)?;
                all_events.extend(linux_events);
            }
        } else {
            // Target is Windows (or generic filesystem)
            if modules == "evtx" || modules == "all" {
                let evtx_events = evtx::process_evtx_target(path, silent)?;
                all_events.extend(evtx_events);
            }
            if modules == "registry" || modules == "all" {
                let reg_events = registry::process_registry_target(path, silent)?;
                all_events.extend(reg_events);
            }
            if modules == "linux" {
                let linux_events = parsers::linux::process_linux_target(path, silent)?;
                all_events.extend(linux_events);
            }
        }
    }

    // Process individual files
    for file in &workspace.files {
        let path = Path::new(file);
        match modules {
            "evtx" => {
                let evtx_events = evtx::process_evtx_target(path, silent)?;
                all_events.extend(evtx_events);
            }
            "registry" => {
                let reg_events = registry::parse_registry_file(path, silent)?;
                all_events.extend(reg_events);
            }
            "all" => {
                // Detect file type by header / magic bytes
                let mut header = [0u8; 8];
                let mut is_handled = false;
                if let Ok(mut f) = File::open(path) {
                    let bytes_read = f.read(&mut header).unwrap_or(0);
                    if utils::is_evtx(&header[..bytes_read]) {
                        let evtx_events = evtx::process_evtx_target(path, silent)?;
                        all_events.extend(evtx_events);
                        is_handled = true;
                    } else if utils::is_registry_hive(&header[..bytes_read.min(4)]) {
                        let reg_events = registry::parse_registry_file(path, silent)?;
                        all_events.extend(reg_events);
                        is_handled = true;
                    }
                }

                if !is_handled {
                    // Fallback: Try EVTX parser first, then Registry parser
                    if let Ok(evtx_events) = evtx::process_evtx_target(path, silent) {
                        if !evtx_events.is_empty() {
                            all_events.extend(evtx_events);
                            continue;
                        }
                    }
                    if let Ok(reg_events) = registry::parse_registry_file(path, silent) {
                        all_events.extend(reg_events);
                    }
                }
            }
            _ => return Err(format!("❌ Error: Unknown module '{}'", modules).into()),
        }
    }

    let pre_filter_count = all_events.len();

    // Deduplicate events across shadow copies
    all_events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp).then_with(|| a.event_id.cmp(&b.event_id)));
    all_events.dedup_by(|a, b| a.timestamp == b.timestamp && a.event_id == b.event_id && a.artifact == b.artifact && a.processname == b.processname);

    // Apply Time of Interest (TOI) filter if requested
    let filtered_events = utils::filter_by_toi(all_events, start_time, end_time);
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
