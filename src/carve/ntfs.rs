//! NTFS structures carved from raw bytes: `FILE` records (`$MFT` entries whose fixup array
//! proves them), `INDX` blocks (`$I30` directory indexes, with the deleted children left in
//! their slack) and `USN_RECORD_V2/V3` journal records. The validators are allymacb's; what
//! becomes a row follows caarea's execution rules.

use std::io::Cursor;

use mft::attribute::x30::FileNameAttr;

use crate::parsers::evtx::Event;
use crate::parsers::ntfs::usn::{classify, parse_record, UsnRecord};
use crate::parsers::ntfs::{extension, is_evidence_file, EXEC_EXTENSIONS};
use crate::utils::filetime_to_iso;

/// `Read + Seek` as a trait object, for readers handed to the carver by other readers.
pub trait ReadSeek: std::io::Read + std::io::Seek {}
impl<T: std::io::Read + std::io::Seek> ReadSeek for T {}

/// Runs `f` on the unnamed data stream of `name` in the root directory of the NTFS volume
/// that `reader` presents (volume-relative). The stream is read in place through its data
/// runs. `Ok(None)` when the file does not exist.
pub fn with_root_file<R: std::io::Read + std::io::Seek, T>(
    reader: &mut R,
    name: &str,
    f: impl FnOnce(&mut dyn ReadSeek, u64) -> T,
) -> Result<Option<T>, String> {
    let mut fs = ::ntfs::Ntfs::new(reader).map_err(|e| format!("cannot parse NTFS: {}", e))?;
    fs.read_upcase_table(reader).map_err(|e| e.to_string())?;
    let root = fs.root_directory(reader).map_err(|e| e.to_string())?;
    let index = root.directory_index(reader).map_err(|e| e.to_string())?;
    let mut found = None;
    let mut entries = index.entries();
    while let Some(Ok(entry)) = entries.next(reader) {
        if let Some(Ok(key)) = entry.key() {
            if key.name().to_string_lossy().eq_ignore_ascii_case(name) {
                found = Some(entry.file_reference());
                break;
            }
        }
    }
    let Some(file_ref) = found else { return Ok(None) };
    let file = file_ref.to_file(&fs, reader).map_err(|e| e.to_string())?;
    let Some(Ok(item)) = file.data(reader, "") else { return Ok(None) };
    let attr = item.to_attribute().map_err(|e| e.to_string())?;
    let value = attr.value(reader).map_err(|e| e.to_string())?;
    let size = value.len();
    let mut attached = value.attach(reader);
    Ok(Some(f(&mut attached, size)))
}

pub const FILE_MAGIC: &[u8; 4] = b"FILE";
pub const INDX_MAGIC: &[u8; 4] = b"INDX";
const VALID_ENTRY_SIZES: [u32; 2] = [1024, 4096];
const FILETIME_2000: u64 = 125_911_584_000_000_000;
const FILETIME_2040: u64 = 138_535_776_000_000_000;

/// Size of a valid `FILE` record at the start of `buf` (header geometry and fixups checked).
pub fn file_record_size(buf: &[u8]) -> Option<usize> {
    if buf.len() < 48 || &buf[0..4] != FILE_MAGIC {
        return None;
    }
    let usa_offset = u16::from_le_bytes([buf[4], buf[5]]) as usize;
    let usa_count = u16::from_le_bytes([buf[6], buf[7]]) as usize;
    let first_attr = u16::from_le_bytes([buf[20], buf[21]]) as usize;
    let used = u32::from_le_bytes(buf[24..28].try_into().unwrap()) as usize;
    let total = u32::from_le_bytes(buf[28..32].try_into().unwrap());
    if !VALID_ENTRY_SIZES.contains(&total) {
        return None;
    }
    let size = total as usize;
    if buf.len() < size || usa_count != size / 512 + 1 {
        return None;
    }
    if usa_offset < 0x2A || usa_offset + usa_count * 2 > first_attr || first_attr + 8 > size || used > size || used < first_attr {
        return None;
    }
    let usn = &buf[usa_offset..usa_offset + 2];
    for i in 1..usa_count {
        if &buf[i * 512 - 2..i * 512] != usn {
            return None;
        }
    }
    Some(size)
}

/// Names worth a row when the folder is unknown: forensic files always, executables and
/// scripts except the library and package types that churn with updates.
pub fn interesting_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if is_evidence_file(&lower) {
        return true;
    }
    let ext = extension(&lower);
    EXEC_EXTENSIONS.contains(&ext.as_str()) && !matches!(ext.as_str(), "dll" | "sys" | "ocx" | "cpl" | "msi" | "msp" | "py" | "pyw")
}

/// Rows for a `FILE` record found outside the live `$MFT` (an older copy of a record, a
/// record of a reused entry, or one from a volume that no longer exists).
pub fn file_record_events(raw: &[u8], computer: &str, source: &str) -> Vec<Event> {
    let Some(size) = file_record_size(raw) else { return Vec::new() };
    crate::parsers::ntfs::mft::standalone_record_events(&raw[..size], computer, source)
}

/// One parsed `$I30` entry.
pub struct IndxEntry {
    pub file_ref: u64,
    pub in_slack: bool,
    pub fname: FileNameAttr,
}

fn entry_header(block: &[u8], pos: usize) -> (usize, u32) {
    let len = u16::from_le_bytes([block[pos + 8], block[pos + 9]]) as usize;
    let flags = u32::from_le_bytes(block[pos + 12..pos + 16].try_into().unwrap_or([0; 4]));
    (len, flags)
}

fn try_entry(block: &[u8], pos: usize, strict: bool) -> Option<IndxEntry> {
    if pos + 0x58 > block.len() {
        return None;
    }
    let file_ref = u64::from_le_bytes(block[pos..pos + 8].try_into().ok()?);
    let (len, flags) = entry_header(block, pos);
    let fn_len = u16::from_le_bytes([block[pos + 10], block[pos + 11]]) as usize;
    let fn_start = pos + 16;
    if fn_len < 0x44 || fn_start + fn_len > block.len() || len < 16 + fn_len {
        return None;
    }
    let name_len = block[fn_start + 0x40] as usize;
    let namespace = block[fn_start + 0x41];
    if name_len == 0 || namespace > 3 || fn_len != 0x42 + 2 * name_len {
        return None;
    }
    if strict {
        let expected = (16 + fn_len + 7) & !7;
        let expected = if flags & 0x01 != 0 { expected + 8 } else { expected };
        if len != expected || flags & !0x03 != 0 {
            return None;
        }
        for i in 0..4 {
            let t = u64::from_le_bytes(block[fn_start + 8 + i * 8..fn_start + 16 + i * 8].try_into().ok()?);
            if t >= 1 << 63 || (t != 0 && !(FILETIME_2000..FILETIME_2040).contains(&t)) {
                return None;
            }
        }
    }
    let fname = FileNameAttr::from_stream(&mut Cursor::new(&block[fn_start..fn_start + fn_len])).ok()?;
    if fname.name.chars().any(|c| c.is_control() || c == '\\' || c == '/') {
        return None;
    }
    Some(IndxEntry { file_ref, in_slack: strict, fname })
}

/// Validates an `INDX` block at the start of `buf`, applies its fixups and returns its size
/// with every entry of the live chain and of the slack.
pub fn parse_indx_block(buf: &[u8]) -> Option<(usize, Vec<IndxEntry>)> {
    if buf.len() < 0x58 || &buf[0..4] != INDX_MAGIC {
        return None;
    }
    let usa_offset = u16::from_le_bytes([buf[4], buf[5]]) as usize;
    let usa_count = u16::from_le_bytes([buf[6], buf[7]]) as usize;
    if !(3..=129).contains(&usa_count) {
        return None;
    }
    let size = (usa_count - 1) * 512;
    if buf.len() < size || usa_offset < 0x28 || usa_offset + usa_count * 2 > size {
        return None;
    }
    let entries_offset = u32::from_le_bytes(buf[24..28].try_into().ok()?) as usize;
    let index_size = u32::from_le_bytes(buf[28..32].try_into().ok()?) as usize;
    let alloc_size = u32::from_le_bytes(buf[32..36].try_into().ok()?) as usize;
    if entries_offset < 0x10 || 24 + alloc_size > size || index_size > alloc_size || entries_offset > index_size {
        return None;
    }
    if usa_offset + usa_count * 2 > 24 + entries_offset {
        return None;
    }
    let mut block = buf[..size].to_vec();
    let usn = [block[usa_offset], block[usa_offset + 1]];
    for i in 1..usa_count {
        let end = i * 512;
        if block[end - 2..end] != usn {
            return None;
        }
        let fix = usa_offset + i * 2;
        block[end - 2] = block[fix];
        block[end - 1] = block[fix + 1];
    }
    let mut out = Vec::new();
    let live_end = 24 + index_size;
    let block_end = 24 + alloc_size;
    let mut pos = 24 + entries_offset;
    while pos + 16 <= live_end {
        let (len, flags) = entry_header(&block, pos);
        if flags & 0x02 != 0 || len < 16 || !len.is_multiple_of(8) || pos + len > live_end {
            break;
        }
        if let Some(e) = try_entry(&block, pos, false) {
            out.push(e);
        }
        pos += len;
    }
    let mut pos = (live_end + 7) & !7;
    while pos + 0x58 <= block_end {
        match try_entry(&block, pos, true) {
            Some(e) => {
                let (len, _) = entry_header(&block, pos);
                out.push(e);
                pos += len.max(8);
            }
            None => pos += 8,
        }
    }
    Some((size, out))
}

/// Rows for the slack entries of an `INDX` block: children a directory no longer lists.
pub fn indx_events(entries: &[IndxEntry], computer: &str, source: &str) -> Vec<Event> {
    let mut out = Vec::new();
    for e in entries.iter().filter(|e| e.in_slack) {
        if !interesting_name(&e.fname.name) {
            continue;
        }
        let created = e.fname.created.as_second();
        let nanos = e.fname.created.subsec_nanosecond().max(0) as u32;
        let Some(ts) = chrono::DateTime::<chrono::Utc>::from_timestamp(created, nanos).map(|d| crate::utils::iso_utc(&d)) else { continue };
        if created < 946_684_800 {
            continue;
        }
        let modified = chrono::DateTime::<chrono::Utc>::from_timestamp(e.fname.modified.as_second(), e.fname.modified.subsec_nanosecond().max(0) as u32)
            .map(|d| crate::utils::iso_utc(&d))
            .unwrap_or_default();
        out.push(Event {
            timestamp: ts,
            computer: computer.to_string(),
            artifact: "ntfs:i30:deleted".to_string(),
            event_id: 0,
            pid: 0,
            subject_username: String::new(),
            target_username: String::new(),
            processname: format!("[CARVED]\\{}", e.fname.name),
            commandline: Some(format!(
                "Directory index entry in slack (child deleted or renamed): {} size {} modified {} MFT #{}",
                e.fname.name,
                e.fname.logical_size,
                modified,
                e.file_ref & 0x0000_FFFF_FFFF_FFFF
            )),
            parentprocessname: source.to_string(),
        });
    }
    out
}

/// A USN record at the start of `buf` that passes the structural checks a carved record
/// must pass (no journal context to lean on).
pub fn usn_candidate(buf: &[u8]) -> Option<UsnRecord> {
    if buf.len() < 60 {
        return None;
    }
    let length = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
    if !(60..=1100).contains(&length) || !length.is_multiple_of(8) || length > buf.len() {
        return None;
    }
    let major = u16::from_le_bytes([buf[4], buf[5]]);
    let minor = u16::from_le_bytes([buf[6], buf[7]]);
    if !(major == 2 || major == 3) || minor != 0 {
        return None;
    }
    let rec = parse_record(buf)?;
    if rec.name.is_empty() || rec.reason == 0 || rec.reason & !0x81FF_FFFF != 0 {
        return None;
    }
    if !(FILETIME_2000..FILETIME_2040).contains(&rec.filetime) {
        return None;
    }
    if rec.name.chars().any(|c| c.is_control() || c == '\\' || c == '/') {
        return None;
    }
    Some(rec)
}

pub fn usn_events(rec: &UsnRecord, computer: &str, source: &str) -> Option<Event> {
    let ts = filetime_to_iso(rec.filetime)?;
    let (kind, description) = classify(rec, false, "")?;
    let exe = if kind.starts_with("prefetch") { crate::parsers::ntfs::usn::prefetch_executable(&rec.name) } else { format!("[CARVED]\\{}", rec.name) };
    Some(Event {
        timestamp: ts,
        computer: computer.to_string(),
        artifact: format!("ntfs:usn:{}", kind),
        event_id: 0,
        pid: 0,
        subject_username: String::new(),
        target_username: String::new(),
        processname: exe,
        commandline: Some(format!("{} | USN {} | MFT #{}", description, crate::parsers::ntfs::usn::decode_reason(rec.reason), rec.entry)),
        parentprocessname: source.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_record_geometry_and_fixups() {
        let mut r = vec![0u8; 1024];
        r[0..4].copy_from_slice(b"FILE");
        r[4..6].copy_from_slice(&48u16.to_le_bytes());
        r[6..8].copy_from_slice(&3u16.to_le_bytes());
        r[20..22].copy_from_slice(&56u16.to_le_bytes());
        r[24..28].copy_from_slice(&100u32.to_le_bytes());
        r[28..32].copy_from_slice(&1024u32.to_le_bytes());
        r[48..50].copy_from_slice(&7u16.to_le_bytes());
        assert_eq!(file_record_size(&r), None);
        r[510..512].copy_from_slice(&7u16.to_le_bytes());
        r[1022..1024].copy_from_slice(&7u16.to_le_bytes());
        assert_eq!(file_record_size(&r), Some(1024));
        assert!(interesting_name("evil.exe"));
        assert!(!interesting_name("kernel32.dll"));
        assert!(interesting_name("CMD.EXE-D269B812.pf"));
        assert!(parse_indx_block(&[0u8; 4096]).is_none());
    }
}
