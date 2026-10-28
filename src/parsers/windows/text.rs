//! Small helpers shared by the text-based Windows artifacts: encoding detection, file
//! times, user from a profile path.

use std::path::Path;

use crate::utils::systemtime_to_iso;

/// Decodes a Windows text file: UTF-16 LE/BE with BOM, UTF-8 with or without BOM, or
/// BOM-less UTF-16 LE (detected by the NUL pattern of ASCII text).
pub fn decode_text(raw: &[u8]) -> String {
    if raw.starts_with(&[0xFF, 0xFE]) {
        return utf16(&raw[2..], true);
    }
    if raw.starts_with(&[0xFE, 0xFF]) {
        return utf16(&raw[2..], false);
    }
    if raw.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(&raw[3..]).into_owned();
    }
    let sample = &raw[..raw.len().min(512)];
    if sample.len() >= 4 {
        let odd_nul = sample.iter().skip(1).step_by(2).filter(|&&b| b == 0).count();
        if odd_nul * 10 > (sample.len() / 2) * 8 {
            return utf16(raw, true);
        }
    }
    String::from_utf8_lossy(raw).into_owned()
}

fn utf16(raw: &[u8], little_endian: bool) -> String {
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| if little_endian { u16::from_le_bytes([c[0], c[1]]) } else { u16::from_be_bytes([c[0], c[1]]) })
        .collect();
    String::from_utf16_lossy(&units)
}

/// Last modification time of a file as canonical UTC, or an empty string.
pub fn file_mtime_iso(path: &Path) -> String {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .map(systemtime_to_iso)
        .unwrap_or_default()
}

/// The profile name after a `Users` (or `Documents and Settings`) component, if any.
pub fn user_from_path(path: &Path) -> String {
    // The last `Users` component wins: evidence is often staged under the analyst's own
    // profile (`C:\Users\<analyst>\AppData\Local\Temp\...\Users\<suspect>\...`).
    let comps: Vec<String> = path.components().map(|c| c.as_os_str().to_string_lossy().to_string()).collect();
    for i in (0..comps.len().saturating_sub(1)).rev() {
        let lc = comps[i].to_ascii_lowercase();
        if lc == "users" || lc == "documents and settings" {
            let candidate = &comps[i + 1];
            if !candidate.to_ascii_lowercase().ends_with(".dat") {
                return candidate.clone();
            }
        }
    }
    String::new()
}

/// Subtracts `micros` microseconds from a canonical timestamp, keeping the format. Used to
/// keep the order of lines that share one file time.
pub fn minus_micros(ts: &str, micros: i64) -> String {
    match chrono::DateTime::parse_from_rfc3339(ts) {
        Ok(dt) => crate::utils::iso_utc(&(dt.with_timezone(&chrono::Utc) - chrono::Duration::microseconds(micros))),
        Err(_) => ts.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_bom_and_bomless_utf16() {
        let mut le = vec![0xFF, 0xFE];
        le.extend("hi".encode_utf16().flat_map(|u| u.to_le_bytes()));
        assert_eq!(decode_text(&le), "hi");
        let bomless: Vec<u8> = "whoami /all\r\nnet user\r\n".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(decode_text(&bomless), "whoami /all\r\nnet user\r\n");
        assert_eq!(decode_text(b"\xEF\xBB\xBFplain"), "plain");
        assert_eq!(decode_text(b"plain"), "plain");
    }

    #[test]
    fn user_from_profile_path() {
        assert_eq!(user_from_path(Path::new(r"C:\Users\bob\AppData\Roaming\x.txt")), "bob");
        assert_eq!(user_from_path(Path::new("/evidence/C/Users/administrator.DEV-SRV01/AppData/x")), "administrator.DEV-SRV01");
        assert_eq!(user_from_path(Path::new(r"C:\Windows\x")), "");
    }

    #[test]
    fn minus_micros_keeps_format() {
        assert_eq!(minus_micros("2026-10-28T20:22:56.507000Z", 3), "2026-10-28T20:22:56.506997Z");
    }
}
