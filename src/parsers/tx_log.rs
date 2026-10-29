//! Windows registry transaction log replay (in memory, evidence files are never modified).
//!
//! The replayer lives in [`blockcarve::hive_logs`], shared with faramir and masstin: new-format
//! `HvLE` entries verified by their Marvin32 hashes and applied in consecutive sequence order,
//! old-format `DIRT` logs applied when their timestamp matches the hive. This module only
//! reports what was done in caarea's console style.

use blockcarve::hive_logs::{self, Outcome};
use chrono::Local;
use std::borrow::Cow;
use std::path::Path;

/// Logs a message with Caarea branding and a human-readable timestamp
fn log_message(silent: bool, message: &str) {
    if !silent {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        println!("[CAAREA {}] {}", timestamp, message);
    }
}

/// Replays transaction logs (.LOG, .LOG1, .LOG2 next to the hive) into a primary registry hive
/// buffer. Returns the hive unchanged (borrowed, no copy) when nothing has to be applied, or a
/// new in-memory buffer with the recovered data.
pub fn replay_hive_logs<'a>(hive_path: &Path, hive_data: &'a [u8], silent: bool) -> Cow<'a, [u8]> {
    let replay = hive_logs::replay_beside(hive_path, hive_data);
    let hive = hive_path.display();
    for (log, why) in &replay.skipped_old {
        log_message(silent, &format!("⚠️ Skipping old-format log {}: {}", log.display(), why));
    }
    match &replay.outcome {
        Outcome::NotAHive | Outcome::Clean => {}
        Outcome::NoLogs => log_message(
            silent,
            &format!("⚠️ Hive {} is dirty but no transaction log (.LOG1/.LOG2) is present next to it", hive),
        ),
        Outcome::NoApplicableEntries { expected_seq, rejected } => log_message(
            silent,
            &format!(
                "⚠️ Hive {} is dirty but its logs hold no applicable HvLE entries (expected sequence {}, {} rejected by hash)",
                hive, expected_seq, rejected
            ),
        ),
        Outcome::NewFormat { entries, pages, logs, from_seq, to_seq, gap, rejected } => log_message(
            silent,
            &format!(
                "🔄 Replayed {} HvLE log entr{} ({} dirty pages) from {} log file(s) into {} (sequence {} → {}){}{}",
                entries,
                if *entries == 1 { "y" } else { "ies" },
                pages,
                logs,
                hive,
                from_seq,
                to_seq,
                if *gap { ", stopped at a sequence gap" } else { "" },
                if *rejected > 0 { format!(", {} entr(y/ies) rejected by hash", rejected) } else { String::new() }
            ),
        ),
        Outcome::OldFormat { pages, log } => log_message(
            silent,
            &format!("🔄 Replayed {} dirty pages (old DIRT format) from {} into {}", pages, log.display(), hive),
        ),
        Outcome::NothingUsable => log_message(
            silent,
            &format!("⚠️ Hive {} is dirty but no usable transaction log data was found", hive),
        ),
    }
    replay.data
}

#[cfg(test)]
mod tests {
    use super::*;

    /// End-to-end through the file system: a dirty hive with a `.LOG1` beside it comes back
    /// replayed. The recovery rules themselves are tested in blockcarve (yarp corpus included).
    #[test]
    fn test_replays_the_log_next_to_the_hive() {
        let dir = std::env::temp_dir().join(format!("caarea_txlog_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let hive_path = dir.join("SOFTWARE");
        let mut hive = vec![0u8; 4096 + 1024];
        hive[..4].copy_from_slice(b"regf");
        hive[4..8].copy_from_slice(&7u32.to_le_bytes());
        hive[8..12].copy_from_slice(&6u32.to_le_bytes());
        hive[12..20].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        hive[0x28..0x2C].copy_from_slice(&1024u32.to_le_bytes());
        // Old-format log: base block (seq 7/7, same timestamp), DIRT vector marking page 1
        let mut log = hive[..512].to_vec();
        log[8..12].copy_from_slice(&7u32.to_le_bytes());
        log[0x1C..0x20].copy_from_slice(&1u32.to_le_bytes()); // file type 1: old-format log
        log.extend_from_slice(b"DIRT");
        log.push(0b0000_0010);
        log.resize(1024, 0);
        let mut page = vec![0xABu8; 512];
        page[..5].copy_from_slice(b"DIRTY");
        log.extend_from_slice(&page);
        std::fs::write(&hive_path, &hive).unwrap();
        std::fs::write(dir.join("SOFTWARE.LOG1"), &log).unwrap();

        let recovered = replay_hive_logs(&hive_path, &hive, true);
        let owned = recovered.to_vec();
        let clean = replay_hive_logs(&hive_path, &owned, true);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(matches!(recovered, Cow::Owned(_)));
        assert_eq!(&recovered[4096 + 512..4096 + 517], b"DIRTY");
        assert!(matches!(clean, Cow::Borrowed(_)), "a replayed hive is clean");
    }
}
