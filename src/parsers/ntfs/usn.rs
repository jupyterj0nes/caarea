//! `$UsnJrnl:$J` as execution evidence. Every program run rewrites its Prefetch file about
//! ten seconds later, and the journal keeps that write long after the Prefetch folder has
//! rolled over, so the journal extends the execution history well beyond the eight runs a
//! `.pf` remembers. Binaries dropped, renamed or deleted, logs truncated and histories
//! removed are reported too.

use std::collections::HashMap;
use std::path::Path;

use super::{extension, is_evidence_file, is_system_path, EXEC_EXTENSIONS};
use crate::parsers::evtx::Event;
use crate::utils::filetime_to_iso;

const USN_COMMON_HEADER: usize = 8;
const USN_V2_FIXED: usize = 60;
const USN_V3_FIXED: usize = 76;
const USN_MAX_RECORD: usize = 4096;
/// Largest journal copy read into memory.
const MAX_JOURNAL_BYTES: u64 = 2 << 30;

pub const DATA_OVERWRITE: u32 = 0x0000_0001;
pub const DATA_EXTEND: u32 = 0x0000_0002;
pub const DATA_TRUNCATION: u32 = 0x0000_0004;
pub const FILE_CREATE: u32 = 0x0000_0100;
pub const FILE_DELETE: u32 = 0x0000_0200;
pub const RENAME_OLD_NAME: u32 = 0x0000_1000;
pub const RENAME_NEW_NAME: u32 = 0x0000_2000;
pub const CLOSE: u32 = 0x8000_0000;

pub fn decode_reason(reason: u32) -> String {
    const NAMES: [(u32, &str); 25] = [
        (0x0000_0001, "DATA_OVERWRITE"),
        (0x0000_0002, "DATA_EXTEND"),
        (0x0000_0004, "DATA_TRUNCATION"),
        (0x0000_0010, "NAMED_DATA_OVERWRITE"),
        (0x0000_0020, "NAMED_DATA_EXTEND"),
        (0x0000_0040, "NAMED_DATA_TRUNCATION"),
        (0x0000_0100, "FILE_CREATE"),
        (0x0000_0200, "FILE_DELETE"),
        (0x0000_0400, "EA_CHANGE"),
        (0x0000_0800, "SECURITY_CHANGE"),
        (0x0000_1000, "RENAME_OLD_NAME"),
        (0x0000_2000, "RENAME_NEW_NAME"),
        (0x0000_4000, "INDEXABLE_CHANGE"),
        (0x0000_8000, "BASIC_INFO_CHANGE"),
        (0x0001_0000, "HARD_LINK_CHANGE"),
        (0x0002_0000, "COMPRESSION_CHANGE"),
        (0x0004_0000, "ENCRYPTION_CHANGE"),
        (0x0008_0000, "OBJECT_ID_CHANGE"),
        (0x0010_0000, "REPARSE_POINT_CHANGE"),
        (0x0020_0000, "STREAM_CHANGE"),
        (0x0040_0000, "TRANSACTED_CHANGE"),
        (0x0080_0000, "INTEGRITY_CHANGE"),
        (0x0100_0000, "DESIRED_STORAGE_CLASS_CHANGE"),
        (0x4000_0000, "0x40000000"),
        (0x8000_0000, "CLOSE"),
    ];
    let parts: Vec<&str> = NAMES.iter().filter(|(bit, _)| reason & bit != 0).map(|(_, n)| *n).collect();
    if parts.is_empty() {
        format!("0x{:08X}", reason)
    } else {
        parts.join("+")
    }
}

/// One decoded V2/V3 record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsnRecord {
    pub entry: u64,
    pub sequence: u16,
    pub parent: u64,
    pub filetime: u64,
    pub reason: u32,
    pub attributes: u32,
    pub name: String,
    pub length: usize,
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// Parses the record at the start of `buf`. `None` when it is not a plausible V2/V3 record.
pub fn parse_record(buf: &[u8]) -> Option<UsnRecord> {
    if buf.len() < USN_COMMON_HEADER {
        return None;
    }
    let length = u32_at(buf, 0) as usize;
    if !(USN_V2_FIXED..=USN_MAX_RECORD).contains(&length) || !length.is_multiple_of(8) || length > buf.len() {
        return None;
    }
    let major = u16_at(buf, 4);
    let (fixed, refs_wide) = match major {
        2 => (USN_V2_FIXED, false),
        3 => (USN_V3_FIXED, true),
        _ => return None,
    };
    if length < fixed {
        return None;
    }
    let (entry_ref, parent_ref, rest) = if refs_wide {
        (u64_at(buf, 8), u64_at(buf, 24), 40)
    } else {
        (u64_at(buf, 8), u64_at(buf, 16), 24)
    };
    // rest: usn(8) time(8) reason(4) source(4) security(4) attrs(4) name_len(2) name_off(2)
    let filetime = u64_at(buf, rest + 8);
    let reason = u32_at(buf, rest + 16);
    let attributes = u32_at(buf, rest + 28);
    let name_len = u16_at(buf, rest + 32) as usize;
    let name_off = u16_at(buf, rest + 34) as usize;
    let mut name = String::new();
    if name_len > 0 && name_off >= fixed && name_off + name_len <= length {
        let units: Vec<u16> = buf[name_off..name_off + name_len].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        name = String::from_utf16_lossy(&units);
    }
    Some(UsnRecord {
        entry: entry_ref & 0x0000_FFFF_FFFF_FFFF,
        sequence: (entry_ref >> 48) as u16,
        parent: parent_ref & 0x0000_FFFF_FFFF_FFFF,
        filetime,
        reason,
        attributes,
        name,
        length,
    })
}

/// Executable name a Prefetch file was made for: `CMD.EXE-D269B812.pf` -> `CMD.EXE`.
pub fn prefetch_executable(pf_name: &str) -> String {
    let stem = pf_name.rsplit_once('.').map(|(s, _)| s).unwrap_or(pf_name);
    match stem.rsplit_once('-') {
        Some((exe, hash)) if hash.len() == 8 && hash.chars().all(|c| c.is_ascii_hexdigit()) => exe.to_string(),
        _ => stem.to_string(),
    }
}

/// Classifies a record; `None` when it is not execution evidence.
/// Returns `(artifact kind, description)`.
pub fn classify(rec: &UsnRecord, path_known: bool, path_lower: &str) -> Option<(&'static str, String)> {
    let name_lower = rec.name.to_ascii_lowercase();
    let ext = extension(&name_lower);
    let r = rec.reason;
    let closed = r & CLOSE != 0;
    let is_dir = rec.attributes & 0x10 != 0;
    if is_dir || rec.name.is_empty() {
        return None;
    }
    if ext == "pf" {
        let exe = prefetch_executable(&rec.name);
        if r & FILE_DELETE != 0 {
            return Some(("deleted", format!("Prefetch file deleted: {} ({})", rec.name, exe)));
        }
        if !closed {
            return None;
        }
        if r & FILE_CREATE != 0 {
            return Some(("prefetch_created", format!("First run recorded by Prefetch: {} ({})", exe, rec.name)));
        }
        if r & (DATA_EXTEND | DATA_OVERWRITE | DATA_TRUNCATION) != 0 {
            return Some(("prefetch_updated", format!("Program run (Prefetch file rewritten): {} ({})", exe, rec.name)));
        }
        return None;
    }
    if is_evidence_file(&name_lower) {
        if ext == "evtx" && r & DATA_TRUNCATION != 0 && closed {
            return Some(("log_cleared", format!("Event log truncated: {}", rec.name)));
        }
        if r & FILE_DELETE != 0 {
            return Some(("deleted", format!("Forensic file deleted: {}", rec.name)));
        }
        if name_lower == "consolehost_history.txt" && r & DATA_TRUNCATION != 0 && closed {
            return Some(("log_cleared", "PowerShell history truncated".to_string()));
        }
        return None;
    }
    if !EXEC_EXTENSIONS.contains(&ext.as_str()) {
        return None;
    }
    // Without a path only the strong signals are kept: libraries and drivers churn with updates.
    if super::is_package_noise(path_lower) {
        return None;
    }
    if path_known {
        if is_system_path(path_lower) {
            return None;
        }
    } else if matches!(ext.as_str(), "dll" | "sys" | "ocx" | "cpl" | "msi" | "msp" | "py" | "pyw") {
        return None;
    }
    if r & FILE_DELETE != 0 {
        return Some(("file_delete", format!("Executable deleted: {}", rec.name)));
    }
    if !closed {
        return None;
    }
    if r & FILE_CREATE != 0 {
        return Some(("file_create", format!("Executable written: {}", rec.name)));
    }
    if r & RENAME_NEW_NAME != 0 {
        return Some(("renamed", format!("Executable renamed to: {}", rec.name)));
    }
    if r & (DATA_EXTEND | DATA_OVERWRITE | DATA_TRUNCATION) != 0 {
        return Some(("file_modified", format!("Executable modified: {}", rec.name)));
    }
    None
}

pub struct UsnResult {
    pub events: Vec<Event>,
    pub records: usize,
    pub prefetch_rows: usize,
}

/// Parses a journal buffer. `dirs` maps directory record numbers to volume-relative paths
/// (from the `$MFT` of the same volume) so historical names get their folder back.
pub fn parse_buffer(data: &[u8], source: &str, computer: &str, dirs: &HashMap<u64, String>) -> UsnResult {
    let mut events = Vec::new();
    let mut records = 0usize;
    let mut prefetch_rows = 0usize;
    let mut pos = 0usize;
    while pos + USN_COMMON_HEADER <= data.len() {
        // zero padding: records are 8-byte aligned, holes are long, skip by words
        if u32_at(data, pos) == 0 {
            // jump over a run of zero bytes quickly
            let mut p = pos + 8;
            while p + 8 <= data.len() && u64_at(data, p) == 0 {
                p += 8;
            }
            pos = p;
            continue;
        }
        let Some(rec) = parse_record(&data[pos..]) else {
            pos += 8;
            continue;
        };
        records += 1;
        pos += rec.length;
        let Some(ts) = filetime_to_iso(rec.filetime) else { continue };
        let dir = dirs.get(&rec.parent);
        let path_known = dir.is_some();
        let full = match dir {
            Some(d) if d.is_empty() => format!("C:\\{}", rec.name),
            Some(d) => format!("C:\\{}\\{}", d, rec.name),
            None => format!("C:\\[UNKNOWN]\\{}", rec.name),
        };
        let path_lower = full.trim_start_matches("C:\\").to_ascii_lowercase();
        let Some((kind, description)) = classify(&rec, path_known, &path_lower) else { continue };
        if kind.starts_with("prefetch") {
            prefetch_rows += 1;
        }
        let exe_for_pf = if kind.starts_with("prefetch") { Some(prefetch_executable(&rec.name)) } else { None };
        events.push(Event {
            timestamp: ts,
            computer: computer.to_string(),
            artifact: format!("ntfs:usn:{}", kind),
            event_id: 0,
            pid: 0,
            subject_username: String::new(),
            target_username: String::new(),
            processname: exe_for_pf.unwrap_or_else(|| full.clone()),
            commandline: Some(format!("{} | USN {} | MFT #{} | {}", description, decode_reason(rec.reason), rec.entry, full)),
            parentprocessname: source.to_string(),
        });
    }
    UsnResult { events, records, prefetch_rows }
}

pub fn parse_usn_file(path: &Path, computer: &str, dirs: &HashMap<u64, String>) -> Result<UsnResult, String> {
    let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if meta.len() > MAX_JOURNAL_BYTES {
        return Err(format!("journal copy is {} bytes, larger than the {} byte limit", meta.len(), MAX_JOURNAL_BYTES));
    }
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let source = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "$UsnJrnl:$J".to_string());
    Ok(parse_buffer(&data, &source, computer, dirs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(entry: u64, parent: u64, filetime: u64, reason: u32, attrs: u32, name: &str) -> Vec<u8> {
        let name_bytes: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let mut len = USN_V2_FIXED + name_bytes.len();
        len = (len + 7) & !7;
        let mut b = vec![0u8; len];
        b[0..4].copy_from_slice(&(len as u32).to_le_bytes());
        b[4..6].copy_from_slice(&2u16.to_le_bytes());
        b[8..16].copy_from_slice(&(entry | (7u64 << 48)).to_le_bytes());
        b[16..24].copy_from_slice(&(parent | (1u64 << 48)).to_le_bytes());
        b[32..40].copy_from_slice(&filetime.to_le_bytes());
        b[40..44].copy_from_slice(&reason.to_le_bytes());
        b[52..56].copy_from_slice(&attrs.to_le_bytes());
        b[56..58].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        b[58..60].copy_from_slice(&(USN_V2_FIXED as u16).to_le_bytes());
        b[60..60 + name_bytes.len()].copy_from_slice(&name_bytes);
        b
    }

    #[test]
    fn classifies_prefetch_runs_and_drops() {
        let ft = 133_552_399_310_000_000u64; // 2024-03-18T12:52:11Z
        let mut data = vec![0u8; 64]; // leading hole
        data.extend(record(100, 50, ft, FILE_CREATE | DATA_EXTEND | CLOSE, 0x20, "CMD.EXE-D269B812.pf"));
        data.extend(record(100, 50, ft + 10_000_000, DATA_EXTEND | DATA_OVERWRITE | CLOSE, 0x20, "CMD.EXE-D269B812.pf"));
        data.extend(record(101, 60, ft, FILE_CREATE | CLOSE, 0x20, "evil.exe"));
        data.extend(record(102, 61, ft, FILE_CREATE | CLOSE, 0x20, "kernel32.dll"));
        data.extend(record(103, 62, ft, DATA_TRUNCATION | CLOSE, 0x20, "Security.evtx"));
        data.extend(record(104, 60, ft, FILE_CREATE | CLOSE, 0x20, "readme.txt"));
        let mut dirs = HashMap::new();
        dirs.insert(50u64, "Windows\\Prefetch".to_string());
        dirs.insert(60u64, "Users\\bob\\Downloads".to_string());
        dirs.insert(61u64, "Windows\\System32".to_string());
        let res = parse_buffer(&data, "$J", "H", &dirs);
        assert_eq!(res.records, 6);
        let kinds: Vec<&str> = res.events.iter().map(|e| e.artifact.as_str()).collect();
        assert_eq!(kinds, vec!["ntfs:usn:prefetch_created", "ntfs:usn:prefetch_updated", "ntfs:usn:file_create", "ntfs:usn:log_cleared"]);
        assert_eq!(res.events[0].processname, "CMD.EXE");
        assert_eq!(res.events[0].timestamp, "2024-03-18T12:52:11.000000Z");
        assert_eq!(res.events[2].processname, "C:\\Users\\bob\\Downloads\\evil.exe");
        assert!(res.events[3].commandline.as_deref().unwrap().contains("Event log truncated"));
        assert_eq!(res.prefetch_rows, 2);
        assert_eq!(prefetch_executable("NOTEPAD.EXE-9FB27C0E.pf"), "NOTEPAD.EXE");
        assert_eq!(decode_reason(FILE_CREATE | CLOSE), "FILE_CREATE+CLOSE");
    }

    #[test]
    fn without_mft_only_strong_signals() {
        let ft = 133_552_399_310_000_000u64;
        let mut data = Vec::new();
        data.extend(record(1, 2, ft, FILE_CREATE | CLOSE, 0x20, "x.dll"));
        data.extend(record(1, 2, ft, FILE_CREATE | CLOSE, 0x20, "x.exe"));
        let res = parse_buffer(&data, "$J", "H", &HashMap::new());
        assert_eq!(res.events.len(), 1);
        assert_eq!(res.events[0].processname, "C:\\[UNKNOWN]\\x.exe");
    }
}
