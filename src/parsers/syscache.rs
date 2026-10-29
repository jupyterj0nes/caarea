//! `Syscache.hve` (`System Volume Information`, Windows 7 / Server 2008 R2): the
//! Application Experience service's record of executables it looked at, one key per file
//! under `DefaultObjectStore\ObjectTable` with the file's MFT reference, its SHA-1
//! (`AeFileID`) and the Amcache program id. The key's own write time is when the file was
//! processed, which follows its first execution closely.

use sootmark_registry::{Data, Hive};

use crate::parsers::evtx::Event;
use crate::utils::filetime_to_iso;

pub fn is_syscache_name(name: &str) -> bool {
    name.eq_ignore_ascii_case("Syscache.hve")
}

pub fn events(hive: &Hive, computer: &str, source: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let Ok(Some(table)) = hive.open(r"DefaultObjectStore\ObjectTable") else { return events };
    let Ok(objects) = table.subkeys() else { return events };
    for key in objects {
        let Some(ts) = filetime_to_iso(key.last_written) else { continue };
        let mut file_id: Option<u64> = None;
        let mut usn: Option<u64> = None;
        let mut sha1 = String::new();
        let mut program = String::new();
        if let Ok(values) = key.values() {
            for v in values.into_iter().flatten() {
                match (v.name.as_str(), v.data()) {
                    ("_FileId_", Data::Qword(q)) => file_id = Some(q),
                    ("_FileId_", Data::Bytes(b)) if b.len() >= 8 => file_id = Some(u64::from_le_bytes(b[..8].try_into().unwrap())),
                    ("_Usn_", Data::Qword(q)) => usn = Some(q),
                    ("_Usn_", Data::Bytes(b)) if b.len() >= 8 => usn = Some(u64::from_le_bytes(b[..8].try_into().unwrap())),
                    ("AeFileID", Data::String(s)) => sha1 = s.trim_start_matches('0').to_string(),
                    ("AeProgramID", Data::String(s)) => program = s,
                    _ => {}
                }
            }
        }
        let Some(fid) = file_id else { continue };
        let (entry, seq) = (fid & 0x0000_FFFF_FFFF_FFFF, (fid >> 48) as u16);
        let mut details = format!("Syscache: file processed by the Application Experience service (key time); MFT entry {} seq {}", entry, seq);
        if !sha1.is_empty() {
            details.push_str(&format!(" SHA1 {}", sha1));
        }
        if !program.is_empty() {
            details.push_str(&format!(" program {}", program));
        }
        if let Some(u) = usn {
            details.push_str(&format!(" USN {}", u));
        }
        events.push(Event {
            timestamp: ts,
            computer: computer.to_string(),
            artifact: "registry:syscache".to_string(),
            event_id: 0,
            pid: 0,
            subject_username: String::new(),
            target_username: String::new(),
            processname: format!("MFT entry {} ({})", entry, key.name),
            commandline: Some(details),
            parentprocessname: source.to_string(),
        });
    }
    events
}
