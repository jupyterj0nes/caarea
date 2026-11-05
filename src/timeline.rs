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

/// Header of the timeline: fourteen event columns in the verticals of masstin's timeline
/// (the same kind of value in the same position: time, host, event type, id, how the row was
/// obtained, who it ran as, the image, its parent, who ran it, the process id, the command
/// line, the file it was read from; `reserved_1` and `reserved_2` where masstin's domains
/// have no execution equivalent), then the analysis tail the four tools share.
pub const HEADER: &str = "\"timestamp\",\"computer\",\"artifact\",\"event_id\",\"state\",\"target_username\",\"reserved_1\",\"processname\",\"parentprocessname\",\"subject_username\",\"reserved_2\",\"pid\",\"commandline\",\"source_file\",\"hunt\",\"hunt_score\",\"hunt_why\",\"verdict\",\"notes\"";

/// Number of columns every timeline has: fourteen of the event, five of the tail.
pub const COLUMNS: usize = 19;

/// The event columns of one row, in the order of [`HEADER`], without the tail.
pub fn event_csv(event: &Event) -> String {
    let state = crate::provenance::split(&event.artifact).1.origin.to_string();
    format!(
        "\"{}\",\"{}\",\"{}\",{},\"{}\",\"{}\",\"\",\"{}\",\"{}\",\"{}\",\"\",{},\"{}\",\"{}\"",
        escape_csv(&event.timestamp),
        escape_csv(&event.computer),
        escape_csv(&event.artifact),
        event.event_id,
        state,
        escape_csv(&event.target_username),
        escape_csv(&event.processname),
        escape_csv(&event.parentprocessname),
        escape_csv(&event.subject_username),
        event.pid,
        escape_csv(event.commandline.as_deref().unwrap_or("N/A")),
        escape_csv(&event.source_file),
    )
}

/// Exports the timeline to a CSV file: the fourteen event columns, then the tail of each row.
/// `tails` lines up with `events`; where it is shorter (no hunt) the tail is empty.
pub fn export_timeline(events: &[Event], tails: &[Tail], output_file: &str, silent: bool) -> std::io::Result<()> {
    let file = File::create(output_file)?;
    let mut writer = BufWriter::new(file);

    writeln!(writer, "{}", HEADER)?;

    // Save each event to the file with properly escaped CSV cells, then its tail
    // (bare `,,,,,` when nothing judged the row).
    for (i, event) in events.iter().enumerate() {
        let tail = tails.get(i).map(Tail::csv).unwrap_or_else(|| EMPTY_TAIL.to_string());
        writeln!(writer, "{}{}", event_csv(event), tail)?;
    }

    log_message(silent, &format!("✅ Timeline successfully saved to: {}", output_file));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_and_row_have_nineteen_columns_in_masstins_verticals() {
        let names: Vec<&str> = HEADER.split(',').map(|c| c.trim_matches('"')).collect();
        assert_eq!(names.len(), COLUMNS);
        assert_eq!(COLUMNS, 19);
        // the verticals of masstin's timeline: time, host, type, id, how obtained, target user,
        // (domain), the image, (source address: the parent), subject user, (domain), session id
        // (the pid), detail (the command line), the file it came from, then the tail
        assert_eq!(names[0], "timestamp");
        assert_eq!(names[1], "computer");
        assert_eq!(names[2], "artifact");
        assert_eq!(names[4], "state");
        assert_eq!(names[5], "target_username");
        assert_eq!(names[6], "reserved_1");
        assert_eq!(names[7], "processname");
        assert_eq!(names[8], "parentprocessname");
        assert_eq!(names[9], "subject_username");
        assert_eq!(names[10], "reserved_2");
        assert_eq!(names[11], "pid");
        assert_eq!(names[12], "commandline");
        assert_eq!(names[13], "source_file");
        assert_eq!(&names[14..], ["hunt", "hunt_score", "hunt_why", "verdict", "notes"]);
        let e = Event {
            source_file: "export/logs/Security.evtx".to_string(),
            timestamp: "2026-10-28T20:20:00.000000Z".to_string(),
            computer: "DEV-SRV01".to_string(),
            artifact: "evtx:4688:vss [2026-09-04T08:12:53Z]".to_string(),
            event_id: 4688,
            pid: 4321,
            subject_username: "DEV\\admin".to_string(),
            target_username: String::new(),
            processname: "C:\\Windows\\System32\\cmd.exe".to_string(),
            commandline: Some("cmd.exe /c whoami".to_string()),
            parentprocessname: "explorer.exe".to_string(),
            meta: None,
        };
        let row = event_csv(&e);
        assert_eq!(row.matches(',').count(), 13, "{}", row);
        assert!(row.contains(",4688,\"vss\",\"\",\"\",\"C:\\Windows\\System32\\cmd.exe\",\"explorer.exe\",\"DEV\\admin\",\"\",4321,"), "{}", row);
        assert!(row.ends_with(",\"export/logs/Security.evtx\""), "{}", row);
        let live = Event { artifact: "evtx:4688".to_string(), ..e.clone() };
        assert!(event_csv(&live).contains(",4688,\"live\","));
    }
}
