//! NTFS metadata as execution evidence: `$MFT` records (live and freed) and the change
//! journal `$UsnJrnl:$J`.
//!
//! This is not a file-system timeline (allymacb does that). Only what tells the story of
//! an execution is kept: binaries and scripts written outside the system folders, their
//! renames and deletions, Prefetch files created or rewritten (every program run leaves one
//! of those), event logs truncated, histories and reports deleted. Resident `$DATA` of small
//! scripts is quoted in the row.

pub mod mft;
pub mod usn;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::Local;
use walkdir::WalkDir;

use crate::parsers::evtx::Event;
use crate::parsers::windows::detect_hostname;

fn log_message(silent: bool, message: &str) {
    if !silent {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        println!("[CAAREA {}] {}", timestamp, message);
    }
}

/// Executable and script extensions whose creation, change, rename or deletion is reported.
pub const EXEC_EXTENSIONS: [&str; 25] = [
    "exe", "dll", "sys", "com", "scr", "pif", "cpl", "ocx", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "hta", "msi", "msp", "jar", "py", "pyw", "job",
];

/// Package and SDK trees whose thousands of scripts and libraries churn with every install
/// or upgrade and say nothing about execution.
pub fn is_package_noise(path_lower: &str) -> bool {
    const MARKERS: [&str; 14] = [
        "site-packages\\",
        "\\lib\\python",
        "node_modules\\",
        "\\_vendor\\",
        "\\__pycache__\\",
        "\\appdata\\local\\pip\\",
        "\\appdata\\local\\temp\\pip-",
        "\\appdata\\local\\microsoft\\onedrive\\",
        "\\appdata\\local\\microsoft\\teams\\",
        "\\appdata\\local\\google\\chrome\\",
        "\\appdata\\local\\microsoft\\edge\\",
        "\\appdata\\local\\squirreltemp\\",
        "\\windows\\installer\\",
        "\\examples\\",
    ];
    let p = format!("\\{}", path_lower);
    MARKERS.iter().any(|m| p.contains(m))
}

/// Script extensions whose resident content is worth quoting.
pub const SCRIPT_EXTENSIONS: [&str; 11] = ["bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "hta", "py"];

/// File name extension, lower case, without the dot.
pub fn extension(name: &str) -> String {
    name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default()
}

/// Forensic files whose deletion or truncation is reported wherever they are.
pub fn is_evidence_file(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let ext = extension(&n);
    if ext == "pf" || ext == "evtx" {
        return true;
    }
    let stem = n.trim_end_matches(".log1").trim_end_matches(".log2");
    matches!(stem, "system" | "software" | "sam" | "security" | "default" | "ntuser.dat" | "usrclass.dat" | "amcache.hve")
        || n == "consolehost_history.txt"
        || n == "report.wer"
        || n.starts_with("mplog-")
        || n == "$usnjrnl"
}

/// Is a volume-relative path (no drive, backslashes, lower case) somewhere a binary is
/// expected to live? Everything under Windows and Program Files is, except the folders an
/// intruder actually uses there.
pub fn is_system_path(path_lower: &str) -> bool {
    let p = path_lower.trim_start_matches('\\');
    let (first, rest) = match p.split_once('\\') {
        Some((f, r)) => (f, r),
        None => return false, // file in the volume root: interesting
    };
    match first {
        "windows" => {
            let sub = rest.split('\\').next().unwrap_or("").to_string();
            let has_subdir = rest.contains('\\');
            if !has_subdir {
                return false; // directly under C:\Windows
            }
            !matches!(sub.as_str(), "temp" | "tasks" | "prefetch" | "debug" | "tracing" | "logs" | "panther")
                && !rest.starts_with("system32\\tasks\\")
        }
        "program files" | "program files (x86)" | "programdata" => {
            if first == "programdata" {
                return rest.starts_with("microsoft\\") || rest.starts_with("package cache\\");
            }
            true
        }
        "$windows.~bt" | "$windows.~ws" | "windows.old" | "recovery" | "system volume information" => true,
        _ => false,
    }
}

/// Does the file name look like an `$MFT` copy from a triage package or an image extraction?
pub fn is_mft_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "$mft" || n.ends_with("$mft") || n.ends_with("_mft") || n == "mft" || n == "$mft.bin"
}

/// Does the file name look like a `$UsnJrnl:$J` copy?
pub fn is_usn_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "$j"
        || n == "$usnjrnl%3a$j"
        || n == "$usnjrnl_$j"
        || n == "$usnjrnl$j"
        || n == "$usnjrnl-$j"
        || n == "usnjrnl.bin"
        || (n.contains("usnjrnl") && n.ends_with("$j"))
}

/// Walks `target` for `$MFT` and `$UsnJrnl:$J` copies and returns the execution rows.
pub fn process_ntfs_target(target: &Path, silent: bool, hint: Option<&str>) -> Vec<Event> {
    let mut mfts: Vec<PathBuf> = Vec::new();
    let mut usns: Vec<PathBuf> = Vec::new();
    for entry in WalkDir::new(target).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if is_mft_name(&name) {
            mfts.push(entry.into_path());
        } else if is_usn_name(&name) {
            usns.push(entry.into_path());
        }
    }
    if mfts.is_empty() && usns.is_empty() {
        return Vec::new();
    }
    let computer = detect_hostname(target, hint);
    let mut events = Vec::new();
    let mut dirs: HashMap<u64, String> = HashMap::new();
    for path in &mfts {
        match mft::parse_mft_file(path, &computer) {
            Ok(res) => {
                log_message(
                    silent,
                    &format!(
                        "🧾 $MFT {}: {} records, {} directories, {} execution rows ({} from freed records)",
                        path.display(),
                        res.records,
                        res.dirs.len(),
                        res.events.len(),
                        res.deleted_rows
                    ),
                );
                if dirs.is_empty() {
                    dirs = res.dirs;
                }
                events.extend(res.events);
            }
            Err(e) => log_message(silent, &format!("  ⚠️ $MFT {}: {}", path.display(), e)),
        }
    }
    for path in &usns {
        match usn::parse_usn_file(path, &computer, &dirs) {
            Ok(res) => {
                log_message(
                    silent,
                    &format!(
                        "🧾 $UsnJrnl {}: {} records, {} execution rows ({} prefetch runs)",
                        path.display(),
                        res.records,
                        res.events.len(),
                        res.prefetch_rows
                    ),
                );
                events.extend(res.events);
            }
            Err(e) => log_message(silent, &format!("  ⚠️ $UsnJrnl {}: {}", path.display(), e)),
        }
    }
    events
}

/// A single `$MFT` or `$J` given with `-f`. `None` when the file is neither.
pub fn process_ntfs_file(path: &Path, header: &[u8], silent: bool) -> Option<Vec<Event>> {
    let name = path.file_name()?.to_string_lossy().to_string();
    let looks_mft = is_mft_name(&name) || header.starts_with(b"FILE0") || header.starts_with(b"FILE");
    let computer = path.parent().map(|p| detect_hostname(p, None)).unwrap_or_else(|| "Unknown".to_string());
    if looks_mft && (is_mft_name(&name) || header.starts_with(b"FILE")) {
        return match mft::parse_mft_file(path, &computer) {
            Ok(res) => Some(res.events),
            Err(e) => {
                log_message(silent, &format!("  ⚠️ $MFT {}: {}", path.display(), e));
                Some(Vec::new())
            }
        };
    }
    if is_usn_name(&name) {
        let dirs = HashMap::new();
        return match usn::parse_usn_file(path, &computer, &dirs) {
            Ok(res) => Some(res.events),
            Err(e) => {
                log_message(silent, &format!("  ⚠️ $UsnJrnl {}: {}", path.display(), e));
                Some(Vec::new())
            }
        };
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_paths() {
        assert!(is_system_path("windows\\system32\\cmd.exe"));
        assert!(is_system_path("windows\\winsxs\\x\\y.dll"));
        assert!(!is_system_path("windows\\temp\\a.exe"));
        assert!(!is_system_path("windows\\evil.exe"));
        assert!(!is_system_path("windows\\system32\\tasks\\evil"));
        assert!(is_system_path("program files\\app\\a.exe"));
        assert!(is_system_path("programdata\\microsoft\\windows defender\\x.exe"));
        assert!(!is_system_path("programdata\\evil\\a.exe"));
        assert!(!is_system_path("users\\bob\\downloads\\a.exe"));
        assert!(!is_system_path("evil.exe"));
    }

    #[test]
    fn names() {
        assert!(is_mft_name("$MFT"));
        assert!(is_mft_name("C_$MFT"));
        assert!(is_usn_name("$UsnJrnl%3A$J"));
        assert!(is_usn_name("$J"));
        assert!(is_evidence_file("CMD.EXE-D269B812.pf"));
        assert!(is_evidence_file("NTUSER.DAT.LOG1"));
        assert!(!is_evidence_file("notes.txt"));
        assert_eq!(extension("A.B.EXE"), "exe");
    }
}
