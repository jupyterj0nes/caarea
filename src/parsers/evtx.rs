use evtx::EvtxParser;
use rayon::prelude::*;
use serde_json::Value;
use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::path::Path;
use chrono::Local;
use indicatif::{ProgressBar, ProgressStyle}; // Barra de progreso

/// List of important EVTX files to process (can be expanded later)
pub const TARGET_EVTX_FILES: [&str; 4] = ["Security.evtx", "System.evtx", "Windows PowerShell.evtx", "Microsoft-Windows-PowerShell%4Operational.evtx"];

/// Structure for an extracted event
#[derive(Debug, Clone)]
pub struct Event {
    pub timestamp: String,
    pub computer: String,
    pub artifact: String,
    pub event_id: u64,
    pub pid: u32,
    pub subject_username: String,
    pub target_username: String,
    pub processname: String,
    pub commandline: Option<String>,
    pub parentprocessname: String,
}

/// Logs a message with a human-readable timestamp and CAAREA branding
fn log_message(silent: bool, message: &str) {
    if !silent {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        println!("[CAAREA {}] {}", timestamp, message);
    }
}

/// Processes an EVTX target (file or directory) and returns extracted events
pub fn process_evtx_target(target: &Path, silent: bool) -> Result<Vec<Event>, Box<dyn Error>> {
    let mut all_events = vec![];

    if target.is_dir() {
        log_message(silent, &format!("Scanning directory: {}", target.display()));

        let evtx_files = find_evtx_files(target);
        log_message(silent, &format!("Found {} EVTX files", evtx_files.len()));

        // Barra de progreso para mostrar avance
        let pb = ProgressBar::new(evtx_files.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {msg}")
                .unwrap(),
        );

        let processed_events: Vec<Vec<Event>> = evtx_files
            .par_iter()
            .filter_map(|file| {
                let file_path = Path::new(file);
                let filename = file_path.file_name().unwrap().to_string_lossy().to_string();

                if TARGET_EVTX_FILES.contains(&filename.as_str()) {
                    log_message(silent, &format!("Processing EVTX file: {}", file_path.display()));

                    if let Ok(mut evtx_events) = parse_evtx(file) {
                        evtx_events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
                        print_evtx_statistics(file_path, &evtx_events, silent);
                        pb.inc(1);
                        return Some(evtx_events);
                    }
                }
                None
            })
            .collect();

        pb.finish_and_clear();

        all_events = processed_events.into_iter().flatten().collect();
    } else if target.is_file() {
        let filename = target.file_name().unwrap().to_string_lossy().to_string();
        if TARGET_EVTX_FILES.contains(&filename.as_str()) {
            log_message(silent, &format!("Processing EVTX file: {}", target.display()));
            let mut evtx_events = parse_evtx(target.to_str().unwrap())?;

            evtx_events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
            print_evtx_statistics(target, &evtx_events, silent);

            all_events.extend(evtx_events);
        }
    }

    Ok(all_events)
}

/// Prints statistics for a processed EVTX file
fn print_evtx_statistics(file_path: &Path, events: &[Event], silent: bool) {
    if events.is_empty() {
        log_message(silent, &format!("No relevant events found in: {}", file_path.display()));
        return;
    }

    let first_event = &events.first().unwrap().timestamp;
    let last_event = &events.last().unwrap().timestamp;
    let total_events = events.len();

    let unique_users: HashSet<_> = events.iter().map(|e| e.subject_username.clone()).collect();
    let unique_users_count = unique_users.len();

    let commandline_count = events.iter()
        .filter(|e| e.commandline.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false))
        .count();

    log_message(silent, &format!(
        "\nSTATS EVTX Analysis: {}\n\
        ├─ First Event: {}\n\
        ├─ Last Event: {}\n\
        ├─ Total Events: {}\n\
        ├─ Unique Users: {}\n\
        ├─ Events with CommandLine: {}\n\
        └─────────────────────────\n",
        file_path.display(),
        first_event,
        last_event,
        total_events,
        unique_users_count,
        commandline_count
    ));
}

/// Scans a directory and counts the total number of EVTX files (including subdirectories)
pub fn count_evtx_files(target: &Path) -> usize {
    find_evtx_files(target).len()
}

/// Finds EVTX files in a directory recursively or processes a single file
pub fn find_evtx_files(target: &Path) -> Vec<String> {
    let mut evtx_files = vec![];

    if target.is_file() {
        if let Some(ext) = target.extension() {
            if ext == "evtx" {
                evtx_files.push(target.to_string_lossy().to_string());
            }
        }
    } else if target.is_dir() {
        if let Ok(entries) = fs::read_dir(target) {
            for entry in entries.flatten() {
                let path = entry.path();
                evtx_files.extend(find_evtx_files(&path));
            }
        }
    }

    evtx_files
}

/// Parses an EVTX file and extracts relevant events
pub fn parse_evtx(file_path: &str) -> Result<Vec<Event>, Box<dyn Error>> {
    let mut parser = EvtxParser::from_path(file_path)?;

    let events: Vec<Event> = parser
        .records_json()
        .par_bridge()
        .filter_map(|record| {
            if let Ok(record) = record {
                extract_event_4688(&record.data)
            } else {
                None
            }
        })
        .collect();

    Ok(events)
}

/// Extracts relevant information from an Event 4688 JSON record
fn extract_event_4688(json_str: &str) -> Option<Event> {
    let parsed: Value = serde_json::from_str(json_str).ok()?;
    
    
    let event_id_val = &parsed["Event"]["System"]["EventID"];
    let event_id = if let Some(obj) = event_id_val.as_object() {
        if let Some(text_val) = obj.get("#text") {
            text_val.as_u64().or_else(|| text_val.as_str().and_then(|s| s.parse::<u64>().ok())).unwrap_or(0)
        } else {
            0
        }
    } else {
        event_id_val.as_u64().or_else(|| event_id_val.as_str().and_then(|s| s.parse::<u64>().ok())).unwrap_or(0)
    };

    if event_id != 4688 && event_id != 7045 && event_id != 400 {
        return None;
    }

    let timestamp = parsed["Event"]["System"]["TimeCreated"]["#attributes"]["SystemTime"]
        .as_str()
        .unwrap_or("Unknown Timestamp")
        .to_string();

    let computer = parsed["Event"]["System"]["Computer"]
        .as_str()
        .unwrap_or("Unknown Computer")
        .to_string();

    let mut eventdata = &parsed["Event"]["EventData"];
    if eventdata.is_null() { eventdata = &parsed["Event"]["UserData"]["EventXML"]; }

    let mut subject_username = String::new();
    let mut target_username = String::new();
    let mut processname = String::new();
    let mut commandline = None;
    let mut parentprocessname = String::new();
    let mut pid: u32 = 0;

    if let Some(event_obj) = eventdata.as_object() {
        for (key, value) in event_obj.iter() {
            let value_str = value.as_str().unwrap_or("").to_string();

                        match key.as_str() {
                "SubjectUserName" => subject_username = value_str,
                "SubjectDomainName" => {
                    subject_username = format!("{}{}", value_str, subject_username);
                }
                "TargetUserName" => target_username = value_str,
                "TargetDomainName" => {
                    target_username = format!("{}{}", value_str, target_username);
                }
                "NewProcessName" => processname = value_str.clone(),
                "CommandLine" => commandline = Some(value_str.clone()),
                "ParentProcessName" => parentprocessname = value_str,
                "ProcessId" => {
                    pid = u32::from_str_radix(value_str.trim_start_matches("0x"), 16).unwrap_or(0);
                }
                // EVTX 7045 (Service Install) mapping
                "ServiceName" => processname = value_str.clone(),
                "ImagePath" => commandline = Some(value_str.clone()),
                "ServiceAccount" => subject_username = value_str,
                // EVTX 400 (PowerShell) mapping
                "HostVersion" => processname = format!("PowerShell v{}", value_str),
                "HostApplication" => commandline = Some(value_str.clone()),
                // EVTX 4697 (Security Service Install) mapping
                "ServiceFileName" => commandline = Some(value_str.clone()),
                // EVTX 4104 (PowerShell Script Block)
                "ScriptBlockText" => {
                    processname = "PowerShell Script Block".to_string();
                    commandline = Some(value_str.clone());
                }
                _ => {}
            }
        }
    }

    Some(Event {
        timestamp,
        computer,
        artifact: format!("evtx:{}!", event_id).replace("!", ""),
        event_id,
        pid,
        subject_username,
        target_username,
        processname,
        commandline,
        parentprocessname,
    })
}
