use chrono::DateTime;
use std::fs;
use std::path::Path;

use crate::parsers::evtx::Event;

/// Parses Linux kernel Process Accounting binary files (pacct / psacct)
/// Implements parsing for Linux struct acct_v3 (64 bytes per record)
pub fn parse_pacct_file(file_path: &Path, computer_name: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let data = match fs::read(file_path) {
        Ok(d) => d,
        Err(_) => return events,
    };

    if data.len() < 64 {
        return events;
    }

    // Records are 64 bytes each
    for chunk in data.chunks_exact(64) {
        let flag = chunk[0];
        let version = chunk[1];

        // Process acct_v3 records (version == 3) or legacy records
        let (uid, pid, ppid, btime, comm_slice) = if version == 3 {
            let uid = u32::from_le_bytes([chunk[8], chunk[9], chunk[10], chunk[11]]);
            let pid = u32::from_le_bytes([chunk[16], chunk[17], chunk[18], chunk[19]]);
            let ppid = u32::from_le_bytes([chunk[20], chunk[21], chunk[22], chunk[23]]);
            let btime = u32::from_le_bytes([chunk[24], chunk[25], chunk[26], chunk[27]]) as i64;
            let comm = &chunk[32..48];
            (uid, pid, ppid, btime, comm)
        } else {
            // Legacy acct v1 / v2 fallback
            let uid = u16::from_le_bytes([chunk[4], chunk[5]]) as u32;
            let btime = u32::from_le_bytes([chunk[8], chunk[9], chunk[10], chunk[11]]) as i64;
            let comm = &chunk[0..16];
            (uid, 0, 0, btime, comm)
        };

        if btime == 0 {
            continue;
        }

        let iso_ts = match DateTime::from_timestamp(btime, 0) {
            Some(dt) => dt.to_rfc3339(),
            None => continue,
        };

        let comm = String::from_utf8_lossy(comm_slice)
            .trim_matches('\0')
            .trim()
            .to_string();

        if comm.is_empty() {
            continue;
        }

        let is_superuser = (flag & 0x02) != 0;
        let dumped_core = (flag & 0x08) != 0;
        let killed_by_signal = (flag & 0x10) != 0;

        let details = format!(
            "Command: {}, UID: {}, SuperUser: {}, CoreDump: {}, KilledBySignal: {}",
            comm, uid, is_superuser, dumped_core, killed_by_signal
        );

        let user_label = if is_superuser || uid == 0 {
            "root".to_string()
        } else {
            uid.to_string()
        };

        events.push(Event {
            timestamp: iso_ts,
            computer: computer_name.to_string(),
            artifact: "linux:process:pacct".to_string(),
            event_id: 0,
            pid,
            subject_username: user_label.clone(),
            target_username: user_label,
            processname: comm,
            commandline: Some(details),
            parentprocessname: if ppid > 0 { format!("PID: {}", ppid) } else { "N/A".to_string() },
        });
    }

    events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_synthetic_pacct_v3() {
        let mut record = vec![0u8; 64];
        record[0] = 0x02; // flag ASU (superuser)
        record[1] = 3;    // version 3
        record[8..12].copy_from_slice(&0u32.to_le_bytes()); // uid 0
        record[16..20].copy_from_slice(&1234u32.to_le_bytes()); // pid 1234
        record[20..24].copy_from_slice(&1u32.to_le_bytes()); // ppid 1
        record[24..28].copy_from_slice(&1710766331u32.to_le_bytes()); // epoch
        record[32..39].copy_from_slice(b"secret\0");

        let temp_file = std::env::temp_dir().join(format!("test_pacct_{}.bin", std::process::id()));
        fs::write(&temp_file, &record).unwrap();

        let events = parse_pacct_file(&temp_file, "TESTHOST");
        let _ = fs::remove_file(&temp_file);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].processname, "secret");
        assert_eq!(events[0].pid, 1234);
        assert_eq!(events[0].subject_username, "root");
        assert!(events[0].timestamp.starts_with("2024-03-18"));
    }
}
