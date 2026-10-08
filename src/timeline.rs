use crate::parsers::evtx::Event;
use crate::utils::escape_csv;
use std::fs::File;
use std::io::{Write, BufWriter};
use chrono::Local;

/// Logs a message with Caarea branding and a human-readable timestamp
fn log_message(silent: bool, message: &str) {
    if !silent {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        println!("[CAAREA {}] {}", timestamp, message);
    }
}

/// Merges execution and registry events, sorting them chronologically
pub fn create_timeline(mut events: Vec<Event>, mut registry: Vec<Event>) -> Vec<Event> {
    events.append(&mut registry);
    events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    events
}

/// Exports the timeline to a CSV file
pub fn export_timeline(events: &[Event], output_file: &str, silent: bool) -> std::io::Result<()> {
    let file = File::create(output_file)?;
    let mut writer = BufWriter::new(file);

    // Write the CSV header with unified artifact column
    writeln!(
        writer,
        "\"timestamp\",\"computer\",\"artifact\",\"event_id\",\"pid\",\"subject_username\",\
        \"target_username\",\"processname\",\"commandline\",\"parentprocessname\""
    )?;

    // Save each event to the file with properly escaped CSV cells
    for event in events {
        writeln!(
            writer,
            "\"{}\",\"{}\",\"{}\",{},{},\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"",
            escape_csv(&event.timestamp),
            escape_csv(&event.computer),
            escape_csv(&event.artifact),
            event.event_id,
            event.pid,
            escape_csv(&event.subject_username),
            escape_csv(&event.target_username),
            escape_csv(&event.processname),
            escape_csv(event.commandline.as_deref().unwrap_or("N/A")),
            escape_csv(&event.parentprocessname)
        )?;
    }

    log_message(silent, &format!("✅ Timeline successfully saved to: {}", output_file));

    Ok(())
}
