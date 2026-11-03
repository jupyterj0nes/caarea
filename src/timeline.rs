use crate::hunt::{Tail, EMPTY_TAIL};
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

/// Header of the timeline: the ten event columns and the analysis tail.
pub const HEADER: &str = "\"timestamp\",\"computer\",\"artifact\",\"event_id\",\"pid\",\"subject_username\",\"target_username\",\"processname\",\"commandline\",\"parentprocessname\",\"hunt\",\"hunt_score\",\"hunt_why\",\"verdict\",\"notes\"";

/// Number of columns every timeline has: ten of the event, five of the tail.
pub const COLUMNS: usize = 15;

/// Exports the timeline to a CSV file: the ten event columns, then the tail of each row.
/// `tails` lines up with `events`; where it is shorter (no hunt) the tail is empty.
pub fn export_timeline(events: &[Event], tails: &[Tail], output_file: &str, silent: bool) -> std::io::Result<()> {
    let file = File::create(output_file)?;
    let mut writer = BufWriter::new(file);

    writeln!(writer, "{}", HEADER)?;

    // Save each event to the file with properly escaped CSV cells, then its tail
    // (bare `,,,,,` when nothing judged the row).
    for (i, event) in events.iter().enumerate() {
        let tail = tails.get(i).map(Tail::csv).unwrap_or_else(|| EMPTY_TAIL.to_string());
        writeln!(
            writer,
            "\"{}\",\"{}\",\"{}\",{},{},\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"{}",
            escape_csv(&event.timestamp),
            escape_csv(&event.computer),
            escape_csv(&event.artifact),
            event.event_id,
            event.pid,
            escape_csv(&event.subject_username),
            escape_csv(&event.target_username),
            escape_csv(&event.processname),
            escape_csv(event.commandline.as_deref().unwrap_or("N/A")),
            escape_csv(&event.parentprocessname),
            tail
        )?;
    }

    log_message(silent, &format!("✅ Timeline successfully saved to: {}", output_file));

    Ok(())
}
