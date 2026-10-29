//! Jump Lists and shortcuts (`Recent\AutomaticDestinations\*.automaticDestinations-ms`,
//! `Recent\CustomDestinations\*.customDestinations-ms`, `Recent\*.lnk`): which application
//! opened which file or ran which command, and when. Automatic destinations carry a
//! last-access time and an access count per target; a shortcut's own modification time is
//! when it was last used.

use std::path::Path;

use lnk_core::{parse_automatic_destinations, parse_custom_destinations, parse_shell_link, JumpListKind, ShellLink};

use super::text::{file_mtime_iso, user_from_path};
use crate::parsers::evtx::Event;
use crate::utils::epoch_to_iso;

/// Well-known AppIDs (CRC64 of the application path or explicit AppUserModelId), so the
/// row names the program instead of a hash. Unknown ids are kept as they are.
const KNOWN_APP_IDS: &[(&str, &str)] = &[
    ("f01b4d95cf55d32a", "Windows Explorer"),
    ("1b4dd67f29cb1962", "Windows Explorer (Windows 7)"),
    ("5f7b5f1e01b83767", "Quick Access"),
    ("7e4dca80246863e3", "Control Panel"),
    ("9b9cdc69c1c24e2b", "Notepad"),
    ("918e0ecb43d17e23", "Notepad (32-bit)"),
    ("bc0c37e84e063727", "cmd.exe"),
    ("1bc392b8e104a00e", "Remote Desktop Connection"),
    ("5d696d521de238c3", "Google Chrome"),
    ("6824f4a902c78fbd", "Mozilla Firefox"),
    ("9d1f905ce5044aee", "Microsoft Edge"),
    ("28c8b86deab549a1", "Internet Explorer"),
    ("12dc1ea8e34b5a6", "Paint"),
    ("a52b0784bd667468", "Photos"),
    ("83b03b46dcd30a0e", "Windows Media Player"),
    ("290532160612e071", "WinRAR"),
    ("4975d6798a8bdf66", "7-Zip"),
    ("23646679aaccfae0", "Adobe Reader"),
    ("a7bd71699cd38d1c", "Word 2010"),
    ("9839aec31243a928", "Excel 2010"),
    ("ae6df75df512bd06", "PowerPoint 2010"),
];

fn app_label(app_id: &str) -> String {
    let lower = app_id.to_ascii_lowercase();
    match KNOWN_APP_IDS.iter().find(|(id, _)| *id == lower) {
        Some((_, name)) => format!("{} ({})", name, app_id),
        None => app_id.to_string(),
    }
}

pub fn is_jumplist(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with(".automaticdestinations-ms") || n.ends_with(".customdestinations-ms")
}

pub fn is_lnk(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".lnk")
}

/// Target and command line of a shell link, best effort.
fn describe(link: &ShellLink) -> (String, String) {
    let target = link
        .link_info
        .as_ref()
        .and_then(|i| i.local_base_path.clone())
        .or_else(|| link.link_target_idlist.as_ref().and_then(|l| l.path.clone()))
        .or_else(|| link.string_data.relative_path.clone())
        .or_else(|| link.link_info.as_ref().and_then(|i| i.common_network_relative_link.as_ref()).map(|_| "(network path)".to_string()))
        .unwrap_or_default();
    let mut details = String::new();
    if let Some(a) = &link.string_data.arguments {
        if !a.is_empty() {
            details.push_str(&format!(" args: {}", a));
        }
    }
    if let Some(w) = &link.string_data.working_dir {
        if !w.is_empty() {
            details.push_str(&format!(" cwd: {}", w));
        }
    }
    if let Some(t) = &link.tracker {
        if !t.machine_id.is_empty() {
            details.push_str(&format!(" machine: {}", t.machine_id));
        }
    }
    if link.header.write_time > 0 {
        if let Some(w) = epoch_to_iso(link.header.write_time, 0) {
            details.push_str(&format!(" target modified {}", w));
        }
    }
    (target, details)
}

pub fn parse_jumplist(path: &Path, computer: &str) -> Vec<Event> {
    let Ok(data) = std::fs::read(path) else { return Vec::new() };
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let lower = name.to_ascii_lowercase();
    let list = if lower.ends_with(".automaticdestinations-ms") {
        parse_automatic_destinations(&data, Some(&name))
    } else {
        parse_custom_destinations(&data, Some(&name))
    };
    let Some(list) = list else { return Vec::new() };
    let user = user_from_path(path);
    let mtime = file_mtime_iso(path);
    let app = app_label(&list.app_id.clone().unwrap_or_else(|| name.split('.').next().unwrap_or(&name).to_string()));
    let mut events = Vec::new();
    for entry in &list.entries {
        let (target, details) = describe(&entry.link);
        let (ts, extra) = match &entry.destlist {
            Some(d) if d.last_access > 0 => (
                epoch_to_iso(d.last_access, 0),
                format!(
                    " entry {}{}{}",
                    d.entry_number,
                    d.access_count.map(|c| format!(" accessed {} time(s)", c)).unwrap_or_default(),
                    if d.pinned { " pinned" } else { "" }
                ),
            ),
            _ => (if mtime.is_empty() { None } else { Some(mtime.clone()) }, " (list file time)".to_string()),
        };
        let Some(ts) = ts else { continue };
        let kind = match list.kind {
            JumpListKind::Automatic => "jumplist:automatic",
            JumpListKind::Custom => "jumplist:custom",
            _ => "jumplist",
        };
        if target.is_empty() && details.is_empty() {
            continue;
        }
        events.push(Event {
            timestamp: ts,
            computer: computer.to_string(),
            artifact: kind.to_string(),
            event_id: 0,
            pid: 0,
            subject_username: user.clone(),
            target_username: String::new(),
            processname: target.clone(),
            commandline: Some(format!("Opened by app {}:{}{}", app, extra, details)),
            parentprocessname: name.clone(),
        });
    }
    events
}

pub fn parse_lnk(path: &Path, computer: &str) -> Vec<Event> {
    let Ok(data) = std::fs::read(path) else { return Vec::new() };
    let Some(link) = parse_shell_link(&data) else { return Vec::new() };
    let mtime = file_mtime_iso(path);
    if mtime.is_empty() {
        return Vec::new();
    }
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let (target, details) = describe(&link);
    if target.is_empty() {
        return Vec::new();
    }
    vec![Event {
        timestamp: mtime,
        computer: computer.to_string(),
        artifact: "lnk".to_string(),
        event_id: 0,
        pid: 0,
        subject_username: user_from_path(path),
        target_username: String::new(),
        processname: target,
        commandline: Some(format!("Shortcut used (file time):{}", details)),
        parentprocessname: name,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(is_jumplist("5f7b5f1e01b83767.automaticDestinations-ms"));
        assert!(is_jumplist("x.customDestinations-ms"));
        assert!(is_lnk("Report.docx.lnk"));
        assert!(!is_lnk("Report.docx"));
        assert!(parse_shell_link(&[0u8; 10]).is_none());
        assert_eq!(app_label("F01B4D95CF55D32A"), "Windows Explorer (F01B4D95CF55D32A)");
        assert_eq!(app_label("deadbeef"), "deadbeef");
    }
}
