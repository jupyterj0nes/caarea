use std::fs;
use std::path::Path;

use crate::parsers::evtx::Event;
use crate::utils::epoch_to_iso;

/// Size of every accounting record (`struct acct` and `struct acct_v3` are both 64 bytes).
pub const ACCT_RECORD_SIZE: usize = 64;
/// `ACCT_COMM` in `include/uapi/linux/acct.h`
const ACCT_COMM: usize = 16;
/// High bit of `ac_version`: set when the record was written by a big-endian kernel.
const ACCT_BYTEORDER: u8 = 0x80;

// ac_flag bits
const AFORK: u8 = 0x01;
const ASU: u8 = 0x02;
const ACORE: u8 = 0x08;
const AXSIG: u8 = 0x10;

/// Decoded fields of one accounting record, independent of the on-disk struct version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcctRecord {
    pub flag: u8,
    pub version: u8,
    pub uid: u32,
    pub pid: u32,
    pub ppid: u32,
    pub btime: i64,
    pub comm: String,
}

fn rd_u16(b: &[u8], off: usize, be: bool) -> u16 {
    let a = [b[off], b[off + 1]];
    if be {
        u16::from_be_bytes(a)
    } else {
        u16::from_le_bytes(a)
    }
}

fn rd_u32(b: &[u8], off: usize, be: bool) -> u32 {
    let a = [b[off], b[off + 1], b[off + 2], b[off + 3]];
    if be {
        u32::from_be_bytes(a)
    } else {
        u32::from_le_bytes(a)
    }
}

fn comm_from(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

/// Decodes a single 64-byte accounting record.
///
/// Layouts (from `include/uapi/linux/acct.h`):
///
/// `struct acct_v3` (ac_version == 3):
/// `flag@0 version@1 tty@2 exitcode@4 uid@8 gid@12 pid@16 ppid@20 btime@24 etime@28
///  utime@32 stime@34 mem@36 io@38 rw@40 minflt@42 majflt@44 swaps@46 comm[16]@48`
///
/// legacy `struct acct` (ac_version 0, 1 or 2):
/// `flag@0 version@1 uid16@2 gid16@4 tty@6 btime@8 utime@12 ... swaps@28 ahz@30
///  exitcode@32 comm[17]@36 etime_hi@53 etime_lo@54 uid32@56 gid32@60`
pub fn parse_acct_record(chunk: &[u8]) -> Option<AcctRecord> {
    if chunk.len() < ACCT_RECORD_SIZE {
        return None;
    }
    let flag = chunk[0];
    let raw_version = chunk[1];
    let be = raw_version & ACCT_BYTEORDER != 0;
    let version = raw_version & !ACCT_BYTEORDER;

    let (uid, pid, ppid, btime, comm) = match version {
        3 => (
            rd_u32(chunk, 8, be),
            rd_u32(chunk, 16, be),
            rd_u32(chunk, 20, be),
            rd_u32(chunk, 24, be) as i64,
            comm_from(&chunk[48..48 + ACCT_COMM]),
        ),
        0..=2 => {
            let uid16 = rd_u16(chunk, 2, be) as u32;
            let uid32 = rd_u32(chunk, 56, be);
            let uid = if version == 2 && uid32 != 0 { uid32 } else { uid16 };
            (
                uid,
                0,
                0,
                rd_u32(chunk, 8, be) as i64,
                comm_from(&chunk[36..36 + ACCT_COMM + 1]),
            )
        }
        _ => return None,
    };

    Some(AcctRecord { flag, version, uid, pid, ppid, btime, comm })
}

/// Parses Linux kernel Process Accounting binary files (pacct / psacct / acct).
pub fn parse_pacct_file(file_path: &Path, computer_name: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let data = match fs::read(file_path) {
        Ok(d) => d,
        Err(_) => return events,
    };

    for chunk in data.chunks_exact(ACCT_RECORD_SIZE) {
        if let Some(e) = parse_acct_record(chunk).and_then(|rec| record_event(&rec, computer_name)) {
            events.push(e);
        }
    }

    events
}

/// One timeline row for a decoded record (`None` when it has no time or no command).
pub fn record_event(rec: &AcctRecord, computer_name: &str) -> Option<Event> {
    if rec.btime == 0 || rec.comm.is_empty() {
        return None;
    }
    let iso_ts = epoch_to_iso(rec.btime, 0)?;
    let is_superuser = rec.flag & ASU != 0;
    let forked_only = rec.flag & AFORK != 0;
    let dumped_core = rec.flag & ACORE != 0;
    let killed_by_signal = rec.flag & AXSIG != 0;
    let details = format!(
        "Command: {}, UID: {}, SuperUser: {}, ForkNoExec: {}, CoreDump: {}, KilledBySignal: {}, AcctVersion: {}",
        rec.comm, rec.uid, is_superuser, forked_only, dumped_core, killed_by_signal, rec.version
    );
    let user_label = if rec.uid == 0 { "root".to_string() } else { rec.uid.to_string() };
    Some(Event {
        timestamp: iso_ts,
        computer: computer_name.to_string(),
        artifact: "linux:process:pacct".to_string(),
        event_id: 0,
        pid: rec.pid,
        subject_username: user_label.clone(),
        target_username: if is_superuser { "root".to_string() } else { user_label },
        processname: rec.comm.clone(),
        commandline: Some(details),
        parentprocessname: if rec.ppid > 0 { format!("PID: {}", rec.ppid) } else { "N/A".to_string() },
    })
}

/// Strict plausibility for a record found in raw bytes, where there is no file to vouch
/// for it: version 3 (or a legacy version with the byte-order flag only), a printable
/// command, a start time between 2000 and 2040, small ids.
pub fn carved_candidate(chunk: &[u8]) -> Option<AcctRecord> {
    if chunk.len() < ACCT_RECORD_SIZE {
        return None;
    }
    let flag = chunk[0];
    let version = chunk[1] & !ACCT_BYTEORDER;
    if flag & !(AFORK | ASU | ACORE | AXSIG | 0x04 | ACCT_BYTEORDER) != 0 || version != 3 {
        return None;
    }
    let rec = parse_acct_record(chunk)?;
    if !(946_684_800..2_208_988_800).contains(&rec.btime) {
        return None;
    }
    if rec.comm.is_empty() || rec.comm.len() > 16 || !rec.comm.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        return None;
    }
    if rec.pid == 0 || rec.pid >= 1 << 22 || rec.ppid >= 1 << 22 || rec.uid >= 1 << 24 {
        return None;
    }
    Some(rec)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a record with the real `struct acct_v3` layout.
    fn v3_record(comm: &str, flag: u8, uid: u32, pid: u32, ppid: u32, btime: u32) -> Vec<u8> {
        let mut r = vec![0u8; 64];
        r[0] = flag;
        r[1] = 3;
        r[8..12].copy_from_slice(&uid.to_le_bytes());
        r[16..20].copy_from_slice(&pid.to_le_bytes());
        r[20..24].copy_from_slice(&ppid.to_le_bytes());
        r[24..28].copy_from_slice(&btime.to_le_bytes());
        r[28..32].copy_from_slice(&1.5f32.to_le_bytes()); // etime
        r[32..34].copy_from_slice(&10u16.to_le_bytes()); // utime (comp_t) - must NOT be read as comm
        r[34..36].copy_from_slice(&5u16.to_le_bytes()); // stime
        r[36..38].copy_from_slice(&100u16.to_le_bytes()); // mem
        let c = comm.as_bytes();
        r[48..48 + c.len()].copy_from_slice(c);
        r
    }

    #[test]
    fn test_parse_real_layout_pacct_v3() {
        let mut data = v3_record("nc", 0x02, 0, 4242, 1, 1710766331);
        data.extend(v3_record("bash", 0x00, 1000, 4243, 4242, 1710766332));
        data.extend(v3_record("chmod", 0x10, 1000, 4244, 4243, 1710766333));

        let temp_file = std::env::temp_dir().join(format!("test_pacct_{}.bin", std::process::id()));
        fs::write(&temp_file, &data).unwrap();
        let events = parse_pacct_file(&temp_file, "TESTHOST");
        let _ = fs::remove_file(&temp_file);

        assert_eq!(events.len(), 3);
        assert_eq!(events[0].processname, "nc");
        assert_eq!(events[0].pid, 4242);
        assert_eq!(events[0].subject_username, "root");
        assert_eq!(events[0].timestamp, "2024-03-18T12:52:11.000000Z");
        assert_eq!(events[1].processname, "bash");
        assert_eq!(events[1].subject_username, "1000");
        assert_eq!(events[1].parentprocessname, "PID: 4242");
        assert_eq!(events[2].processname, "chmod");
        assert!(events[2].commandline.as_ref().unwrap().contains("KilledBySignal: true"));
    }

    #[test]
    fn test_parse_big_endian_v3() {
        let mut r = vec![0u8; 64];
        r[0] = 0x00;
        r[1] = 3 | ACCT_BYTEORDER;
        r[8..12].copy_from_slice(&1000u32.to_be_bytes());
        r[16..20].copy_from_slice(&77u32.to_be_bytes());
        r[24..28].copy_from_slice(&1710766331u32.to_be_bytes());
        r[48..50].copy_from_slice(b"ls");
        let rec = parse_acct_record(&r).unwrap();
        assert_eq!(rec.uid, 1000);
        assert_eq!(rec.pid, 77);
        assert_eq!(rec.btime, 1710766331);
        assert_eq!(rec.comm, "ls");
    }

    #[test]
    fn test_parse_legacy_v2() {
        let mut r = vec![0u8; 64];
        r[1] = 2;
        r[2..4].copy_from_slice(&1001u16.to_le_bytes()); // uid16
        r[8..12].copy_from_slice(&1710766331u32.to_le_bytes()); // btime
        r[36..40].copy_from_slice(b"wget");
        r[56..60].copy_from_slice(&70001u32.to_le_bytes()); // uid32 (v2)
        let rec = parse_acct_record(&r).unwrap();
        assert_eq!(rec.comm, "wget");
        assert_eq!(rec.uid, 70001);
        assert_eq!(rec.btime, 1710766331);

        r[1] = 1;
        let rec1 = parse_acct_record(&r).unwrap();
        assert_eq!(rec1.uid, 1001);
    }

    #[test]
    fn test_unknown_version_is_skipped() {
        let mut r = vec![0u8; 64];
        r[1] = 9;
        assert!(parse_acct_record(&r).is_none());
    }
}
