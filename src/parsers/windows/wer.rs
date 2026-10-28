//! Windows Error Reporting reports (`ProgramData\Microsoft\Windows\WER\Report{Archive,Queue}\
//! *\Report.wer` and the per-user copies under `AppData\Local`): which program crashed or
//! hung, when, with which module and exception. Attack tooling crashes often, and the report
//! survives log clearing.

use std::collections::HashMap;
use std::path::Path;

use super::text::{decode_text, file_mtime_iso, user_from_path};
use crate::parsers::evtx::Event;
use crate::utils::filetime_to_iso;

pub fn is_report(name: &str) -> bool {
    name.eq_ignore_ascii_case("Report.wer")
}

pub fn parse_text(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    map
}

/// Signature values in order (`Sig[0].Value`, `Sig[1].Value`, ...).
fn signatures(m: &HashMap<String, String>) -> Vec<String> {
    let mut out = Vec::new();
    for i in 0..16 {
        match m.get(&format!("Sig[{}].Value", i)) {
            Some(v) => out.push(v.clone()),
            None => break,
        }
    }
    out
}

pub fn parse_file(path: &Path, computer: &str) -> Vec<Event> {
    let Ok(raw) = std::fs::read(path) else { return Vec::new() };
    let m = parse_text(&decode_text(&raw));
    if !m.contains_key("EventType") && !m.contains_key("Sig[0].Name") {
        return Vec::new();
    }
    let timestamp = ["EventTime", "UploadTime"]
        .iter()
        .filter_map(|k| m.get(*k))
        .filter_map(|v| v.parse::<u64>().ok())
        .filter_map(filetime_to_iso)
        .next()
        .unwrap_or_else(|| file_mtime_iso(path));
    if timestamp.is_empty() {
        return Vec::new();
    }
    let sigs = signatures(&m);
    let app_from_target = m
        .get("TargetAppId")
        .and_then(|t| t.rsplit('!').next())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let processname = m
        .get("AppPath")
        .cloned()
        .or(app_from_target)
        .or_else(|| m.get("AppName").cloned())
        .or_else(|| sigs.first().cloned())
        .unwrap_or_else(|| "unknown application".to_string());
    let pid = m
        .get("AppSessionGuid")
        .and_then(|g| g.split('-').next())
        .and_then(|h| u32::from_str_radix(h, 16).ok())
        .unwrap_or(0);
    let event_type = m.get("EventType").cloned().unwrap_or_default();
    let friendly = m.get("FriendlyEventName").cloned().unwrap_or_default();
    let mut details = format!("WER {}", event_type);
    if !friendly.is_empty() {
        details.push_str(&format!(" ({})", friendly));
    }
    if !sigs.is_empty() {
        details.push_str(": ");
        details.push_str(&sigs.iter().filter(|s| !s.is_empty()).cloned().collect::<Vec<_>>().join(" | "));
    }
    if let Some(fatal) = m.get("IsFatal") {
        if fatal == "1" {
            details.push_str(" | fatal");
        }
    }
    let folder = path
        .parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    vec![Event {
        timestamp,
        computer: computer.to_string(),
        artifact: "wer".to_string(),
        event_id: 0,
        pid,
        subject_username: user_from_path(path),
        target_username: String::new(),
        processname,
        commandline: Some(details),
        parentprocessname: folder,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_report_fields() {
        let text = "Version=1\r\nEventType=CLR20r3\r\nEventTime=134376925580654585\r\nNsAppName=powershell.exe\r\nAppSessionGuid=00001658-0000-000c-1859-c2121a67dd01\r\nTargetAppId=W:0000f519!00006cbc!powershell.exe\r\nIsFatal=1\r\nSig[0].Name=Problem Signature 01\r\nSig[0].Value=powershell.exe\r\nSig[1].Name=P2\r\nSig[1].Value=10.0.17763.1\r\n";
        let dir = std::env::temp_dir().join(format!("caarea_wer_{}", std::process::id()));
        let rep = dir.join("AppCrash_powershell.exe_abc");
        std::fs::create_dir_all(&rep).unwrap();
        let f = rep.join("Report.wer");
        let utf16: Vec<u8> = [0xFF, 0xFE].into_iter().chain(text.encode_utf16().flat_map(|u| u.to_le_bytes())).collect();
        std::fs::write(&f, utf16).unwrap();
        let rows = parse_file(&f, "H");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].processname, "powershell.exe");
        assert_eq!(rows[0].pid, 0x1658);
        assert_eq!(rows[0].timestamp, "2026-10-28T20:22:38.065458Z");
        assert_eq!(rows[0].commandline.as_deref(), Some("WER CLR20r3: powershell.exe | 10.0.17763.1 | fatal"));
        assert_eq!(rows[0].parentprocessname, "AppCrash_powershell.exe_abc");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
