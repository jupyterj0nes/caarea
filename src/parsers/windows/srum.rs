//! SRUM, the System Resource Usage Monitor (`Windows\System32\sru\SRUDB.dat`, an ESE
//! database): per application and user, CPU time, bytes read and written, network traffic
//! and (Windows 10 1709+) start and duration of every run, in hourly windows kept for up to
//! 60 days. Read with the pure-Rust `sootmark-ese` reader; a dirty database still yields
//! what its pages hold.

use std::collections::HashMap;
use std::path::Path;

use ese::{Database, Value};

use crate::parsers::evtx::Event;
use crate::utils::{epoch_to_iso, filetime_to_iso, resolve_sid};

const ID_MAP: &str = "SruDbIdMapTable";
const APP_RESOURCE: &str = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}";
const NETWORK_USAGE: &str = "{973F5D5C-1D90-4944-BE8E-24B94231A174}";
const APP_TIMELINE: &str = "{5C8CF1C7-7257-4F13-B223-970EF5939312}";
// Not read: network connectivity ({DD6636C4-…}, per interface, no application) and the
// Windows 10 1809+ "SDP" tables ({EEE2F477-…} network, {DC3D3B50-…} processor,
// {17F4D97B-…} volume, {841A7317-…} disk), which are per interface, volume or "Total".

pub fn is_srum(name: &str) -> bool {
    name.eq_ignore_ascii_case("SRUDB.dat")
}

/// OLE automation date (days since 1899-12-30) to canonical UTC.
fn ole_to_iso(d: f64) -> Option<String> {
    let secs = (d - 25_569.0) * 86_400.0;
    if !secs.is_finite() || !(946_684_800.0..2_208_988_800.0).contains(&secs) {
        return None;
    }
    epoch_to_iso(secs.trunc() as i64, ((secs.fract()) * 1e9) as u32)
}

fn time_of(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::DateTime(d) => ole_to_iso(*d),
        Value::I64(ft) if *ft > 0 => filetime_to_iso(*ft as u64),
        _ => None,
    }
}

fn int_of(v: Option<&Value>) -> i64 {
    v.and_then(|x| x.as_i64()).unwrap_or(0)
}

fn decode_sid(b: &[u8]) -> String {
    if b.len() < 8 || b[0] != 1 {
        return String::new();
    }
    let subs = b[1] as usize;
    if b.len() < 8 + subs * 4 {
        return String::new();
    }
    let auth = u64::from_be_bytes([0, 0, b[2], b[3], b[4], b[5], b[6], b[7]]);
    let mut s = format!("S-1-{}", auth);
    for i in 0..subs {
        s.push_str(&format!("-{}", u32::from_le_bytes(b[8 + i * 4..12 + i * 4].try_into().unwrap())));
    }
    s
}

fn utf16(b: &[u8]) -> String {
    let units: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
    String::from_utf16_lossy(&units)
}

pub struct SrumResult {
    pub events: Vec<Event>,
    pub problems: usize,
}

pub fn parse_file(path: &Path, computer: &str) -> Result<SrumResult, String> {
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let db = Database::open(&bytes).map_err(|e| format!("not an ESE database: {}", e))?;
    let mut problems = db.problems.len();
    let source = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    if std::env::var_os("CAAREA_DEBUG_SRUM").is_some() {
        for t in &db.tables {
            let n = db.rows(&t.name).map(|r| r.count()).unwrap_or(0);
            eprintln!("srum table {} rows {} columns {:?}", t.name, n, t.column_names());
        }
        for p in &db.problems {
            eprintln!("srum problem: {}", p);
        }
    }

    // id -> name (applications, users as SID or account)
    let mut names: HashMap<i64, String> = HashMap::new();
    if let (Some(table), Ok(rows)) = (db.table(ID_MAP), db.rows(ID_MAP)) {
        for row in rows {
            let idx = int_of(row.get(table, "IdIndex"));
            let kind = int_of(row.get(table, "IdType"));
            let Some(blob) = row.get(table, "IdBlob").and_then(|v| v.as_bytes()) else { continue };
            let name = if kind == 3 { resolve_sid(&decode_sid(blob)) } else { utf16(blob) };
            if !name.is_empty() {
                names.insert(idx, name);
            }
        }
    }
    let name_of = |id: i64| names.get(&id).cloned().unwrap_or_else(|| format!("#{}", id));
    let mut events = Vec::new();
    let mk = |ts: String, artifact: &str, user: String, app: String, details: String| Event {
        timestamp: ts,
        computer: computer.to_string(),
        artifact: artifact.to_string(),
        event_id: 0,
        pid: 0,
        subject_username: user,
        target_username: String::new(),
        processname: app,
        commandline: Some(details),
        parentprocessname: source.clone(),
    };

    if let (Some(table), Ok(mut rows)) = (db.table(APP_TIMELINE), db.rows(APP_TIMELINE)) {
        for row in rows.by_ref() {
            let Some(end) = time_of(row.get(table, "EndTime")).or_else(|| time_of(row.get(table, "TimeStamp"))) else { continue };
            let duration_ms = int_of(row.get(table, "DurationMS"));
            let app = name_of(int_of(row.get(table, "AppId")));
            let user = name_of(int_of(row.get(table, "UserId")));
            // start = end - duration
            let start = if duration_ms > 0 {
                chrono::DateTime::parse_from_rfc3339(&end)
                    .ok()
                    .map(|dt| crate::utils::iso_utc(&(dt.with_timezone(&chrono::Utc) - chrono::Duration::milliseconds(duration_ms))))
                    .unwrap_or_else(|| end.clone())
            } else {
                end.clone()
            };
            events.push(mk(
                start,
                "srum:app_timeline",
                user,
                app,
                format!("SRUM app timeline: ran for {:.1} s (until {}); flags {}", duration_ms as f64 / 1000.0, end, int_of(row.get(table, "Flags"))),
            ));
        }
        problems += rows.problems().len();
    }
    if let (Some(table), Ok(mut rows)) = (db.table(APP_RESOURCE), db.rows(APP_RESOURCE)) {
        for row in rows.by_ref() {
            let Some(ts) = time_of(row.get(table, "TimeStamp")) else { continue };
            let app = name_of(int_of(row.get(table, "AppId")));
            let user = name_of(int_of(row.get(table, "UserId")));
            let fg = int_of(row.get(table, "ForegroundCycleTime"));
            let bg = int_of(row.get(table, "BackgroundCycleTime"));
            let read = int_of(row.get(table, "ForegroundBytesRead")) + int_of(row.get(table, "BackgroundBytesRead"));
            let written = int_of(row.get(table, "ForegroundBytesWritten")) + int_of(row.get(table, "BackgroundBytesWritten"));
            events.push(mk(
                ts,
                "srum:app_resource",
                user,
                app,
                format!("SRUM resource usage in the hour ending here: CPU cycles fg {} bg {}, read {} bytes, written {} bytes", fg, bg, read, written),
            ));
        }
        problems += rows.problems().len();
    }
    if let (Some(table), Ok(mut rows)) = (db.table(NETWORK_USAGE), db.rows(NETWORK_USAGE)) {
        for row in rows.by_ref() {
            let Some(ts) = time_of(row.get(table, "TimeStamp")) else { continue };
            let app = name_of(int_of(row.get(table, "AppId")));
            let user = name_of(int_of(row.get(table, "UserId")));
            let sent = int_of(row.get(table, "BytesSent"));
            let recv = int_of(row.get(table, "BytesRecvd"));
            if sent == 0 && recv == 0 {
                continue;
            }
            events.push(mk(
                ts,
                "srum:network_usage",
                user,
                app,
                format!("SRUM network usage in the hour ending here: sent {} bytes, received {} bytes (interface {})", sent, recv, int_of(row.get(table, "InterfaceLuid"))),
            ));
        }
        problems += rows.problems().len();
    }
    Ok(SrumResult { events, problems })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ole_dates_and_sids() {
        assert_eq!(ole_to_iso(46_112.5).as_deref(), Some("2026-03-31T12:00:00.000000Z"));
        assert!(ole_to_iso(1.0).is_none());
        let sid = [1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        assert_eq!(decode_sid(&sid), "S-1-5-18");
        assert_eq!(resolve_sid(&decode_sid(&sid)), "NT AUTHORITY\\SYSTEM");
        assert_eq!(utf16(&"x\u{0}".encode_utf16().flat_map(|u| u.to_le_bytes()).collect::<Vec<_>>()), "x");
    }
}
