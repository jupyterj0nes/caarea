use chrono::DateTime;
use crate::parsers::evtx::Event;

/// Converts a 64-bit Windows FILETIME (100-nanosecond intervals since 1601-01-01 UTC)
/// into an ISO 8601 UTC formatted string (e.g. "2024-02-04T12:35:00Z").
pub fn filetime_to_iso(filetime: u64) -> Option<String> {
    if filetime == 0 {
        return None;
    }

    const WINDOWS_TICK_100NS: i64 = 10_000_000;
    const SECS_BETWEEN_1601_AND_1970: i64 = 11_644_473_600;

    let ticks = filetime as i64;
    let secs_since_1601 = ticks / WINDOWS_TICK_100NS;
    let rem_ticks = ticks % WINDOWS_TICK_100NS;

    let unix_secs = secs_since_1601.checked_sub(SECS_BETWEEN_1601_AND_1970)?;
    let nsecs = (rem_ticks.max(0) * 100) as u32;

    DateTime::from_timestamp(unix_secs, nsecs).map(|dt| dt.to_rfc3339())
}

/// Resolves well-known Windows SIDs to human-readable names.
/// If the SID is not well-known, returns the original SID string.
pub fn resolve_sid(sid: &str) -> String {
    match sid {
        "S-1-5-18" => "NT AUTHORITY\\SYSTEM".to_string(),
        "S-1-5-19" => "NT AUTHORITY\\LOCAL SERVICE".to_string(),
        "S-1-5-20" => "NT AUTHORITY\\NETWORK SERVICE".to_string(),
        "S-1-5-32-544" => "BUILTIN\\Administrators".to_string(),
        "S-1-5-32-545" => "BUILTIN\\Users".to_string(),
        "S-1-5-32-546" => "BUILTIN\\Guests".to_string(),
        "S-1-5-32-547" => "BUILTIN\\Power Users".to_string(),
        "S-1-5-32-548" => "BUILTIN\\Account Operators".to_string(),
        "S-1-5-32-549" => "BUILTIN\\Server Operators".to_string(),
        "S-1-5-32-550" => "BUILTIN\\Print Operators".to_string(),
        "S-1-5-32-551" => "BUILTIN\\Backup Operators".to_string(),
        "S-1-5-32-552" => "BUILTIN\\Replicators".to_string(),
        other => other.to_string(),
    }
}

/// Checks if buffer starts with EVTX file signature ("ElfFile\0")
pub fn is_evtx(buffer: &[u8]) -> bool {
    buffer.len() >= 8 && &buffer[..8] == b"ElfFile\0"
}

/// Checks if buffer starts with Windows Registry Hive signature ("regf")
pub fn is_registry_hive(buffer: &[u8]) -> bool {
    buffer.len() >= 4 && &buffer[..4] == b"regf"
}

/// Escapes double quotes inside CSV cell according to RFC 4180
pub fn escape_csv(val: &str) -> String {
    val.replace('"', "\"\"")
}

/// Filters events by a Time of Interest (TOI) window
pub fn filter_by_toi(events: Vec<Event>, start: Option<&str>, end: Option<&str>) -> Vec<Event> {
    if start.is_none() && end.is_none() {
        return events;
    }
    let start_norm = start.map(|s| s.replace(' ', "T"));
    let end_norm = end.map(|e| e.replace(' ', "T"));

    events
        .into_iter()
        .filter(|e| {
            let ts = e.timestamp.as_str();
            if let Some(ref s) = start_norm {
                if ts < s.as_str() {
                    return false;
                }
            }
            if let Some(ref en) = end_norm {
                if ts > en.as_str() {
                    return false;
                }
            }
            true
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filetime_to_iso() {
        assert_eq!(filetime_to_iso(0), None);
        // 133500000000000000 FILETIME corresponds to 2024-01-17 21:20:00 UTC
        let iso = filetime_to_iso(133500000000000000).unwrap();
        assert!(iso.starts_with("2024-01-17T21:20:00"));
    }

    #[test]
    fn test_resolve_sid() {
        assert_eq!(resolve_sid("S-1-5-18"), "NT AUTHORITY\\SYSTEM");
        assert_eq!(resolve_sid("S-1-5-21-12345678-1001"), "S-1-5-21-12345678-1001");
    }

    #[test]
    fn test_signatures() {
        assert!(is_evtx(b"ElfFile\0\x01\x02"));
        assert!(!is_evtx(b"NOTANEVTX"));
        assert!(is_registry_hive(b"regf\x00\x00\x00\x00"));
        assert!(!is_registry_hive(b"test"));
    }

    #[test]
    fn test_escape_csv() {
        assert_eq!(escape_csv("normal text"), "normal text");
        assert_eq!(escape_csv("cmd /c \"echo hello\""), "cmd /c \"\"echo hello\"\"");
    }

    #[test]
    fn test_filter_by_toi() {
        let events = vec![
            Event {
                timestamp: "2024-01-01T10:00:00Z".to_string(),
                computer: "PC1".to_string(),
                artifact: "evtx:4688".to_string(),
                event_id: 4688,
                pid: 100,
                subject_username: "user".to_string(),
                target_username: "user".to_string(),
                processname: "a.exe".to_string(),
                commandline: None,
                parentprocessname: "p.exe".to_string(),
            },
            Event {
                timestamp: "2024-01-02T10:00:00Z".to_string(),
                computer: "PC1".to_string(),
                artifact: "evtx:4688".to_string(),
                event_id: 4688,
                pid: 101,
                subject_username: "user".to_string(),
                target_username: "user".to_string(),
                processname: "b.exe".to_string(),
                commandline: None,
                parentprocessname: "p.exe".to_string(),
            },
            Event {
                timestamp: "2024-01-03T10:00:00Z".to_string(),
                computer: "PC1".to_string(),
                artifact: "evtx:4688".to_string(),
                event_id: 4688,
                pid: 102,
                subject_username: "user".to_string(),
                target_username: "user".to_string(),
                processname: "c.exe".to_string(),
                commandline: None,
                parentprocessname: "p.exe".to_string(),
            },
        ];

        let filtered = filter_by_toi(events.clone(), Some("2024-01-02 00:00:00"), Some("2024-01-02 23:59:59"));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].processname, "b.exe");

        let filtered_start = filter_by_toi(events.clone(), Some("2024-01-02"), None);
        assert_eq!(filtered_start.len(), 2);
    }
}
