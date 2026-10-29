//! Windows Timeline (`Users\<user>\AppData\Local\ConnectedDevicesPlatform\<account>\
//! ActivitiesCache.db`, Windows 10 1803 to 11): applications opened and the time each one
//! held the focus, kept for about 30 days. SQLite; the database and its write-ahead log
//! are copied to a scratch folder before opening so the evidence copy is never written.
//! The `ActivityOperation` table (changes queued for the cloud) is read too: it keeps rows
//! already removed from `Activity`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use rusqlite::types::Value;
use rusqlite::{Connection, OpenFlags};

use super::text::user_from_path;
use crate::parsers::evtx::Event;
use crate::utils::epoch_to_iso;

pub fn is_timeline(name: &str) -> bool {
    name.eq_ignore_ascii_case("ActivitiesCache.db")
}

fn text_of(v: Value) -> String {
    match v {
        Value::Text(s) => s,
        Value::Blob(b) => String::from_utf8_lossy(&b).into_owned(),
        Value::Integer(i) => i.to_string(),
        Value::Real(r) => r.to_string(),
        Value::Null => String::new(),
    }
}

/// The application named in the `AppId` JSON, preferring the local executable form.
pub fn app_from_appid(json: &str) -> String {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else { return String::new() };
    let Some(arr) = v.as_array() else { return String::new() };
    for wanted in ["x_exe_path", "windows_win32", "packageId", "windows_universal", "afs_crossplatform", "host"] {
        for item in arr {
            if item.get("platform").and_then(|p| p.as_str()) == Some(wanted) {
                if let Some(app) = item.get("application").and_then(|a| a.as_str()) {
                    if !app.is_empty() {
                        return app.to_string();
                    }
                }
            }
        }
    }
    arr.iter().find_map(|i| i.get("application").and_then(|a| a.as_str()).map(str::to_string)).unwrap_or_default()
}

struct Row {
    id: Vec<u8>,
    app: String,
    activity_type: i64,
    start: i64,
    end: i64,
    payload: serde_json::Value,
    pending: bool,
}

fn copy_db(path: &Path) -> Option<PathBuf> {
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("caarea-timeline-{}-{}", std::process::id(), stamp));
    std::fs::create_dir_all(&dir).ok()?;
    let db = dir.join("ActivitiesCache.db");
    std::fs::copy(path, &db).ok()?;
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    let wal = PathBuf::from(wal);
    if wal.is_file() {
        let _ = std::fs::copy(&wal, dir.join("ActivitiesCache.db-wal"));
    }
    Some(db)
}

fn read_rows(db: &Path) -> Result<Vec<Row>, String> {
    let conn = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX).map_err(|e| e.to_string())?;
    let mut rows = Vec::new();
    for (table, pending) in [("Activity", false), ("ActivityOperation", true)] {
        let sql = format!("SELECT Id, AppId, ActivityType, StartTime, EndTime, Payload FROM {}", table);
        let Ok(mut stmt) = conn.prepare(&sql) else { continue };
        let iter = stmt
            .query_map([], |r| {
                Ok(Row {
                    id: r.get::<_, Option<Vec<u8>>>(0)?.unwrap_or_default(),
                    app: app_from_appid(&text_of(r.get::<_, Value>(1)?)),
                    activity_type: r.get::<_, Option<i64>>(2)?.unwrap_or(0),
                    start: r.get::<_, Option<i64>>(3)?.unwrap_or(0),
                    end: r.get::<_, Option<i64>>(4)?.unwrap_or(0),
                    payload: serde_json::from_str(&text_of(r.get::<_, Value>(5)?)).unwrap_or(serde_json::Value::Null),
                    pending,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.extend(iter.flatten());
    }
    Ok(rows)
}

pub fn parse_file(path: &Path, computer: &str) -> Result<Vec<Event>, String> {
    let db = copy_db(path).ok_or_else(|| "cannot copy the database to a scratch folder".to_string())?;
    let result = read_rows(&db);
    if let Some(dir) = db.parent() {
        let _ = std::fs::remove_dir_all(dir);
    }
    let rows = result?;
    if std::env::var_os("CAAREA_DEBUG_TIMELINE").is_some() {
        let mut by_type: std::collections::BTreeMap<i64, (usize, String)> = std::collections::BTreeMap::new();
        for r in &rows {
            let e = by_type.entry(r.activity_type).or_insert((0, String::new()));
            e.0 += 1;
            if e.1.is_empty() {
                e.1 = format!("{} | {}", r.app, r.payload);
            }
        }
        for (t, (n, sample)) in by_type {
            eprintln!("timeline type {} rows {} sample {}", t, n, sample.chars().take(300).collect::<String>());
        }
    }
    let user = user_from_path(path);
    let account = path.parent().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let mut seen: HashSet<(Vec<u8>, i64, i64)> = HashSet::new();
    let mut events = Vec::new();
    for row in rows {
        if row.start <= 0 || row.app.is_empty() {
            continue;
        }
        // Types 5 (opened), 6 (in focus), 10 (clipboard), 16 (copy / paste) describe the user;
        // the system's own bookkeeping activities (11, 12, 15) only when they name a program.
        let user_activity = matches!(row.activity_type, 5 | 6 | 10 | 16);
        if !(user_activity || row.app.contains('\\') || row.app.to_ascii_lowercase().ends_with(".exe")) {
            continue;
        }
        if !seen.insert((row.id.clone(), row.activity_type, row.start)) {
            continue;
        }
        let Some(ts) = epoch_to_iso(row.start, 0) else { continue };
        let end = if row.end > row.start { epoch_to_iso(row.end, 0) } else { None };
        let p = &row.payload;
        let str_of = |k: &str| p.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let (artifact, mut details) = match row.activity_type {
            5 => {
                let mut d = String::from("Timeline: opened");
                for (k, label) in [("displayText", ""), ("contentUri", " content"), ("activationUri", " via"), ("appDisplayName", " app")] {
                    let v = str_of(k);
                    if !v.is_empty() {
                        d.push_str(&format!("{} {}", label, v));
                    }
                }
                ("timeline:activity", d)
            }
            6 => {
                let secs = p.get("activeDurationSeconds").and_then(|v| v.as_i64()).unwrap_or(0);
                let mut d = format!("Timeline: in focus for {} s", secs);
                if let Some(e) = &end {
                    d.push_str(&format!(" (until {})", e));
                }
                ("timeline:focus", d)
            }
            10 => ("timeline:clipboard", "Timeline: clipboard content copied".to_string()),
            16 => ("timeline:clipboard", "Timeline: copy / paste".to_string()),
            t => ("timeline:activity", format!("Timeline: activity type {}", t)),
        };
        if row.pending {
            details.push_str(" [from ActivityOperation]");
        }
        if !account.is_empty() {
            details.push_str(&format!(" account {}", account));
        }
        events.push(Event {
            timestamp: ts,
            computer: computer.to_string(),
            artifact: artifact.to_string(),
            event_id: 0,
            pid: 0,
            subject_username: user.clone(),
            target_username: String::new(),
            processname: row.app,
            commandline: Some(details),
            parentprocessname: "ActivitiesCache.db".to_string(),
        });
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_id_prefers_executable() {
        let j = r#"[{"application":"Microsoft.WindowsNotepad_8wekyb3d8bbwe!App","platform":"packageId"},{"application":"C:\\Windows\\notepad.exe","platform":"x_exe_path"}]"#;
        assert_eq!(app_from_appid(j), r"C:\Windows\notepad.exe");
        assert_eq!(app_from_appid("nonsense"), "");
    }

    #[test]
    fn reads_a_database() {
        let dir = std::env::temp_dir().join(format!("caarea-timeline-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let db = dir.join("ActivitiesCache.db");
        let _ = std::fs::remove_file(&db);
        {
            let c = Connection::open(&db).unwrap();
            c.execute_batch(
                "CREATE TABLE Activity (Id BLOB, AppId TEXT, ActivityType INT, StartTime INT, EndTime INT, Payload BLOB);
                 CREATE TABLE ActivityOperation (Id BLOB, AppId TEXT, ActivityType INT, StartTime INT, EndTime INT, Payload BLOB);
                 INSERT INTO Activity VALUES (x'01', '[{\"application\":\"C:\\\\x\\\\evil.exe\",\"platform\":\"x_exe_path\"}]', 5, 1700000000, 1700000060, '{\"displayText\":\"evil\"}');
                 INSERT INTO Activity VALUES (x'02', '[{\"application\":\"C:\\\\x\\\\evil.exe\",\"platform\":\"x_exe_path\"}]', 6, 1700000000, 1700000060, '{\"activeDurationSeconds\":60}');
                 INSERT INTO ActivityOperation VALUES (x'03', '[{\"application\":\"cmd.exe\",\"platform\":\"x_exe_path\"}]', 5, 1700000100, 0, '{}');",
            )
            .unwrap();
        }
        let ev = parse_file(&db, "PC").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(ev.len(), 3);
        assert_eq!(ev[0].artifact, "timeline:activity");
        assert_eq!(ev[0].timestamp, "2023-11-14T22:13:20.000000Z");
        assert_eq!(ev[0].processname, r"C:\x\evil.exe");
        assert!(ev[1].commandline.as_deref().unwrap().contains("in focus for 60 s (until 2023-11-14T22:14:20.000000Z)"));
        assert!(ev[2].commandline.as_deref().unwrap().contains("[from ActivityOperation]"));
    }
}
