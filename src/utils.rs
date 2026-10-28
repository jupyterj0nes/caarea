use chrono::{DateTime, NaiveDate, NaiveDateTime, SecondsFormat, Utc};
use std::time::SystemTime;

use crate::parsers::evtx::Event;

/// Canonical timestamp representation used by every parser:
/// `YYYY-MM-DDTHH:MM:SS.ffffffZ` (UTC, microseconds, fixed width).
/// Because the width is fixed, lexicographic order == chronological order,
/// which the sorter, the deduplicator and the TOI filter rely on.
pub fn iso_utc(dt: &DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Micros, true)
}

/// Converts a Unix epoch (seconds + nanoseconds) into the canonical timestamp.
pub fn epoch_to_iso(secs: i64, nanos: u32) -> Option<String> {
    DateTime::<Utc>::from_timestamp(secs, nanos).map(|dt| iso_utc(&dt))
}

/// Converts a naive (zone-less) datetime into the canonical timestamp, assuming UTC.
pub fn naive_to_iso(ndt: NaiveDateTime) -> String {
    iso_utc(&DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc))
}

/// Converts a filesystem `SystemTime` (e.g. a file mtime) into the canonical timestamp.
pub fn systemtime_to_iso(st: SystemTime) -> String {
    let dt: DateTime<Utc> = st.into();
    iso_utc(&dt)
}

/// Parses a flexible textual timestamp: RFC 3339 (`Z` or offset), ISO without zone,
/// `YYYY-MM-DD HH:MM:SS` with a space, or a bare date. Zone-less values are taken as UTC.
pub fn parse_flexible_time(s: &str) -> Option<DateTime<Utc>> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(t) {
        return Some(dt.with_timezone(&Utc));
    }
    let t2 = t.replacen(' ', "T", 1);
    if let Ok(dt) = DateTime::parse_from_rfc3339(&t2) {
        return Some(dt.with_timezone(&Utc));
    }
    let bare = t2.trim_end_matches('Z');
    for fmt in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%dT%H"] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(bare, fmt) {
            return Some(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc));
        }
    }
    if let Ok(d) = NaiveDate::parse_from_str(bare, "%Y-%m-%d") {
        let ndt = d.and_hms_opt(0, 0, 0)?;
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc));
    }
    None
}

/// Normalizes any supported textual timestamp into the canonical representation.
pub fn normalize_iso(s: &str) -> Option<String> {
    parse_flexible_time(s).map(|dt| iso_utc(&dt))
}

/// Parses a user supplied Time-of-Interest bound. A bare date used as an *end* bound
/// is expanded to the last microsecond of that day so `--end-time 2025-01-02` includes the 2nd.
pub fn parse_toi_bound(s: &str, is_end: bool) -> Option<String> {
    let t = s.trim();
    let date_only = NaiveDate::parse_from_str(t, "%Y-%m-%d").is_ok();
    let dt = parse_flexible_time(t)?;
    let dt = if date_only && is_end {
        dt + chrono::Duration::days(1) - chrono::Duration::microseconds(1)
    } else {
        dt
    };
    Some(iso_utc(&dt))
}

/// Converts a 64-bit Windows FILETIME (100-nanosecond intervals since 1601-01-01 UTC)
/// into the canonical timestamp.
pub fn filetime_to_iso(filetime: u64) -> Option<String> {
    if filetime == 0 {
        return None;
    }

    const WINDOWS_TICK_100NS: i64 = 10_000_000;
    const SECS_BETWEEN_1601_AND_1970: i64 = 11_644_473_600;

    let ticks = i64::try_from(filetime).ok()?;
    let secs_since_1601 = ticks / WINDOWS_TICK_100NS;
    let rem_ticks = ticks % WINDOWS_TICK_100NS;

    let unix_secs = secs_since_1601.checked_sub(SECS_BETWEEN_1601_AND_1970)?;
    let nsecs = (rem_ticks.max(0) * 100) as u32;

    epoch_to_iso(unix_secs, nsecs)
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

/// Filters events by a Time of Interest (TOI) window. Both ends are inclusive and may be
/// given in any format accepted by [`parse_toi_bound`].
pub fn filter_by_toi(events: Vec<Event>, start: Option<&str>, end: Option<&str>) -> Vec<Event> {
    if start.is_none() && end.is_none() {
        return events;
    }
    let start_norm = start.and_then(|s| parse_toi_bound(s, false));
    let end_norm = end.and_then(|e| parse_toi_bound(e, true));

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

    fn ev(ts: &str, proc_name: &str) -> Event {
        Event {
            timestamp: ts.to_string(),
            computer: "PC1".to_string(),
            artifact: "evtx:4688".to_string(),
            event_id: 4688,
            pid: 100,
            subject_username: "user".to_string(),
            target_username: "user".to_string(),
            processname: proc_name.to_string(),
            commandline: None,
            parentprocessname: "p.exe".to_string(),
        }
    }

    #[test]
    fn test_filetime_to_iso() {
        assert_eq!(filetime_to_iso(0), None);
        // 133500000000000000 FILETIME corresponds to 2024-01-17 21:20:00 UTC
        assert_eq!(filetime_to_iso(133500000000000000).unwrap(), "2024-01-17T21:20:00.000000Z");
    }

    #[test]
    fn test_canonical_format_is_fixed_width_utc() {
        assert_eq!(epoch_to_iso(1710766331, 0).unwrap(), "2024-03-18T12:52:11.000000Z");
        assert_eq!(epoch_to_iso(1710766331, 123_000_000).unwrap(), "2024-03-18T12:52:11.123000Z");
        assert_eq!(normalize_iso("2026-09-24T10:05:00Z").unwrap(), "2026-09-24T10:05:00.000000Z");
        assert_eq!(normalize_iso("2026-09-24T12:05:00+02:00").unwrap(), "2026-09-24T10:05:00.000000Z");
        assert_eq!(normalize_iso("2026-09-24 10:05:00").unwrap(), "2026-09-24T10:05:00.000000Z");
        assert_eq!(normalize_iso("2026-09-24").unwrap(), "2026-09-24T00:00:00.000000Z");
        assert!(normalize_iso("garbage").is_none());
    }

    #[test]
    fn test_toi_bounds() {
        assert_eq!(parse_toi_bound("2025-01-02", false).unwrap(), "2025-01-02T00:00:00.000000Z");
        assert_eq!(parse_toi_bound("2025-01-02", true).unwrap(), "2025-01-02T23:59:59.999999Z");
        assert_eq!(parse_toi_bound("2025-01-02T10:00:00", true).unwrap(), "2025-01-02T10:00:00.000000Z");
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
            ev("2024-01-01T10:00:00.000000Z", "a.exe"),
            ev("2024-01-02T10:00:00.000000Z", "b.exe"),
            ev("2024-01-02T23:30:00.000000Z", "b2.exe"),
            ev("2024-01-03T10:00:00.000000Z", "c.exe"),
        ];

        let filtered = filter_by_toi(events.clone(), Some("2024-01-02 00:00:00"), Some("2024-01-02 23:59:59"));
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].processname, "b.exe");

        // A bare end date must include the whole day
        let filtered_day = filter_by_toi(events.clone(), Some("2024-01-02"), Some("2024-01-02"));
        assert_eq!(filtered_day.len(), 2);

        let filtered_start = filter_by_toi(events.clone(), Some("2024-01-02"), None);
        assert_eq!(filtered_start.len(), 3);
    }
}
