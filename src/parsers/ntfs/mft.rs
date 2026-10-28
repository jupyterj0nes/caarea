//! `$MFT` records as execution evidence. The record walk, the path resolver (cycle-safe,
//! sequence-checked, so children of a deleted directory still resolve) and the attribute
//! collection follow allymacb's parser; the selection of what becomes a row is caarea's.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use mft::attribute::header::ResidentialHeader;
use mft::attribute::x10::StandardInfoAttr;
use mft::attribute::x30::{FileNameAttr, FileNamespace};
use mft::attribute::{MftAttributeContent, MftAttributeType};
use mft::entry::MftEntry;
use mft::MftParser;

use super::{extension, is_evidence_file, is_system_path, EXEC_EXTENSIONS, SCRIPT_EXTENSIONS};
use crate::parsers::evtx::Event;
use crate::provenance::{Origin, Provenance};
use crate::utils::iso_utc;

pub const ROOT_RECORD: u64 = 5;
const MAX_PATH_DEPTH: usize = 512;
const VALID_ENTRY_SIZES: [u32; 2] = [1024, 4096];
const RECOVERY_SCAN_LIMIT: u64 = 4 << 20;
/// FILETIME epoch as Unix seconds: a zero FILETIME means "not set".
const FILETIME_ZERO_SECS: i64 = -11_644_473_600;
const QUOTED_CONTENT: usize = 300;

/// Seconds + nanoseconds of an NTFS timestamp to canonical UTC; `None` for unset.
fn iso(secs: i64, nanos: i32) -> Option<String> {
    if secs <= FILETIME_ZERO_SECS {
        return None;
    }
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, nanos.max(0) as u32).map(|dt| iso_utc(&dt))
}

/// Reader adapter that hides the first `skip` bytes of the stream (damaged leading records).
struct SkipReader<R> {
    inner: R,
    skip: u64,
}

impl<R: Read + Seek> Read for SkipReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<R: Read + Seek> Seek for SkipReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let actual = match pos {
            SeekFrom::Start(p) => self.inner.seek(SeekFrom::Start(self.skip + p))?,
            other => self.inner.seek(other)?,
        };
        Ok(actual.saturating_sub(self.skip))
    }
}

fn header_entry_size(buf: &[u8]) -> Option<u32> {
    if buf.len() < 32 || (&buf[0..4] != b"FILE" && &buf[0..4] != b"BAAD") {
        return None;
    }
    let size = u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]);
    VALID_ENTRY_SIZES.contains(&size).then_some(size)
}

/// `(entry size, records skipped)`; the `mft` crate divides by the size of the first record,
/// so a damaged first record is skipped here.
fn detect_entry_layout<R: Read + Seek>(reader: &mut R, stream_len: u64) -> Result<(u32, u64), String> {
    let mut head = [0u8; 32];
    reader.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let n = reader.read(&mut head).map_err(|e| e.to_string())?;
    if let Some(size) = header_entry_size(&head[..n]) {
        return Ok((size, 0));
    }
    let limit = stream_len.min(RECOVERY_SCAN_LIMIT);
    let mut off: u64 = 1024;
    while off + 32 <= limit {
        reader.seek(SeekFrom::Start(off)).map_err(|e| e.to_string())?;
        let n = reader.read(&mut head).map_err(|e| e.to_string())?;
        if let Some(size) = header_entry_size(&head[..n]) {
            if off.is_multiple_of(u64::from(size)) {
                return Ok((size, off / u64::from(size)));
            }
        }
        off += 1024;
    }
    Err(format!("no valid FILE record in the first {} bytes: not an $MFT or too damaged", limit))
}

struct CachedDir {
    path: String,
    seq: u16,
    allocated: bool,
}

enum Resolved {
    Dir(String),
    Orphan,
    Cycle,
}

/// A parent reference is valid when its sequence matches the record header; a freed record
/// has its sequence bumped by one, so children of a deleted directory still resolve.
fn sequence_matches(expected: u16, header_seq: u16, allocated: bool) -> bool {
    expected == 0 || header_seq == expected || (!allocated && header_seq == expected.wrapping_add(1))
}

struct PathResolver {
    cache: HashMap<u64, CachedDir>,
    skipped: u64,
}

impl PathResolver {
    fn new(skipped: u64) -> Self {
        let mut cache = HashMap::new();
        cache.insert(ROOT_RECORD, CachedDir { path: String::new(), seq: 0, allocated: true });
        PathResolver { cache, skipped }
    }

    fn get_entry<R: Read + Seek>(&self, parser: &mut MftParser<R>, record: u64) -> Option<MftEntry> {
        let idx = record.checked_sub(self.skipped)?;
        parser.get_entry(idx).ok()
    }

    fn cached(&self, record: u64, expected_seq: u16) -> Option<Resolved> {
        let c = self.cache.get(&record)?;
        if record == ROOT_RECORD || sequence_matches(expected_seq, c.seq, c.allocated) {
            Some(Resolved::Dir(c.path.clone()))
        } else {
            Some(Resolved::Orphan)
        }
    }

    fn resolve_dir<R: Read + Seek>(&mut self, parser: &mut MftParser<R>, dir_record: u64, seq: u16) -> Resolved {
        if let Some(r) = self.cached(dir_record, seq) {
            return r;
        }
        let mut chain: Vec<(u64, String, u16, bool)> = Vec::new();
        let mut visited: HashSet<u64> = HashSet::new();
        let mut cur = dir_record;
        let mut cur_seq = seq;
        let base: Resolved = loop {
            if let Some(r) = self.cached(cur, cur_seq) {
                break r;
            }
            if !visited.insert(cur) || chain.len() >= MAX_PATH_DEPTH {
                break Resolved::Cycle;
            }
            let Some(entry) = self.get_entry(parser, cur) else { break Resolved::Orphan };
            let hdr_seq = entry.header.sequence;
            let allocated = entry.is_allocated();
            if !sequence_matches(cur_seq, hdr_seq, allocated) || !entry.is_dir() {
                break Resolved::Orphan;
            }
            let Some(fname) = self.best_name_for_entry(parser, &entry, cur) else { break Resolved::Orphan };
            let parent = fname.parent.entry;
            let parent_seq = fname.parent.sequence;
            chain.push((cur, fname.name, hdr_seq, allocated));
            if parent == cur {
                break Resolved::Orphan;
            }
            cur = parent;
            cur_seq = parent_seq;
        };
        let mut acc = match &base {
            Resolved::Dir(p) => p.clone(),
            Resolved::Orphan => "[ORPHAN]".to_string(),
            Resolved::Cycle => "[CYCLE]".to_string(),
        };
        for (rec, name, hdr_seq, allocated) in chain.iter().rev() {
            acc = if acc.is_empty() { name.clone() } else { format!("{}\\{}", acc, name) };
            self.cache.insert(*rec, CachedDir { path: acc.clone(), seq: *hdr_seq, allocated: *allocated });
        }
        if chain.is_empty() {
            base
        } else {
            Resolved::Dir(acc)
        }
    }

    fn best_name_for_entry<R: Read + Seek>(&self, parser: &mut MftParser<R>, entry: &MftEntry, record: u64) -> Option<FileNameAttr> {
        let mut acc = RecordAttrs::default();
        scan_record(entry, false, &mut acc);
        for ext_rec in extension_records(entry, record) {
            if let Some(ext) = self.get_entry(parser, ext_rec) {
                if ext.header.base_reference.entry == record {
                    scan_record(&ext, false, &mut acc);
                }
            }
        }
        best_name(&acc.fn_attrs)
    }

    /// Volume-relative path of `entry`; directories are cached for their children.
    fn resolve<R: Read + Seek>(&mut self, parser: &mut MftParser<R>, entry: &MftEntry, record: u64, fname: &FileNameAttr) -> String {
        if record == ROOT_RECORD {
            return String::new();
        }
        let dir = match self.resolve_dir(parser, fname.parent.entry, fname.parent.sequence) {
            Resolved::Dir(d) => d,
            Resolved::Orphan => "[ORPHAN]".to_string(),
            Resolved::Cycle => "[CYCLE]".to_string(),
        };
        let full = if dir.is_empty() { fname.name.clone() } else { format!("{}\\{}", dir, fname.name) };
        if entry.is_dir() {
            self.cache.insert(record, CachedDir { path: full.clone(), seq: entry.header.sequence, allocated: entry.is_allocated() });
        }
        full
    }
}

#[derive(Default)]
struct RecordAttrs {
    std_info: Option<StandardInfoAttr>,
    fn_attrs: Vec<FileNameAttr>,
    data_size: Option<u64>,
    resident: Option<Vec<u8>>,
}

fn scan_record(rec: &MftEntry, want_resident: bool, acc: &mut RecordAttrs) {
    for attr in rec.iter_attributes().flatten() {
        match &attr.data {
            MftAttributeContent::AttrX10(info) if acc.std_info.is_none() => {
                acc.std_info = Some(info.clone());
            }
            MftAttributeContent::AttrX30(f) => acc.fn_attrs.push(f.clone()),
            MftAttributeContent::AttrX80(data) if attr.header.name.is_empty() => {
                let bytes = data.data();
                if acc.data_size.is_none() {
                    acc.data_size = Some(bytes.len() as u64);
                }
                if want_resident && acc.resident.is_none() && !bytes.is_empty() {
                    acc.resident = Some(bytes.to_vec());
                }
            }
            MftAttributeContent::DataRun(_) if attr.header.type_code == MftAttributeType::DATA => {
                if let ResidentialHeader::NonResident(nr) = &attr.header.residential_header {
                    if nr.vnc_first == 0 && attr.header.name.is_empty() && acc.data_size.is_none() {
                        acc.data_size = Some(nr.file_size);
                    }
                }
            }
            _ => {}
        }
    }
}

fn extension_records(rec: &MftEntry, base_id: u64) -> Vec<u64> {
    let mut out: Vec<u64> = Vec::new();
    for attr in rec.iter_attributes().flatten() {
        if let MftAttributeContent::AttrX20(list) = &attr.data {
            for e in &list.entries {
                let r = e.segment_reference.entry;
                if r != base_id && !out.contains(&r) {
                    out.push(r);
                }
            }
        }
    }
    out
}

fn best_name(fns: &[FileNameAttr]) -> Option<FileNameAttr> {
    fns.iter()
        .find(|a| matches!(a.namespace, FileNamespace::Win32 | FileNamespace::Win32AndDos))
        .or_else(|| fns.iter().find(|a| a.namespace == FileNamespace::POSIX))
        .or_else(|| fns.first())
        .cloned()
}

/// Printable excerpt of a resident script (UTF-16 or 8-bit), one line.
fn quote_content(bytes: &[u8]) -> String {
    let text = crate::parsers::windows::text::decode_text(bytes);
    let mut out = String::new();
    for ch in text.chars() {
        let c = if ch.is_control() { ' ' } else { ch };
        if !(c == ' ' && out.ends_with(' ')) {
            out.push(c);
        }
        if out.len() >= QUOTED_CONTENT {
            out.push('…');
            break;
        }
    }
    out.trim().to_string()
}

pub struct MftResult {
    pub events: Vec<Event>,
    /// Directory record number -> volume-relative path, for the USN journal.
    pub dirs: HashMap<u64, String>,
    pub records: u64,
    pub deleted_rows: usize,
}

/// Does this record deserve a row? Executables and scripts outside the system folders,
/// forensic files (Prefetch, logs, hives, histories) anywhere.
fn is_interesting(path_lower: &str, name_lower: &str) -> bool {
    if is_evidence_file(name_lower) {
        return true;
    }
    let ext = extension(name_lower);
    EXEC_EXTENSIONS.contains(&ext.as_str()) && !is_system_path(path_lower) && !super::is_package_noise(path_lower)
}

/// Parses an `$MFT` copy and returns the execution rows plus the directory map.
pub fn parse_mft_file(path: &Path, computer: &str) -> Result<MftResult, String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(file);
    let stream_len = reader.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
    let (entry_size, skipped) = detect_entry_layout(&mut reader, stream_len)?;
    let skip_bytes = skipped * u64::from(entry_size);
    let remaining = stream_len.saturating_sub(skip_bytes);
    let mut skipping = SkipReader { inner: reader, skip: skip_bytes };
    skipping.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut parser = MftParser::from_read_seek(skipping, Some(remaining)).map_err(|e| format!("cannot open $MFT: {}", e))?;
    let source = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "$MFT".to_string());

    let count = parser.get_entry_count();
    let mut resolver = PathResolver::new(skipped);
    let mut events = Vec::new();
    let mut deleted_rows = 0usize;

    for idx in 0..count {
        let Ok(entry) = parser.get_entry(idx) else { continue };
        if entry.header.base_reference.entry != 0 {
            continue; // extension record, covered through its base
        }
        let record = entry.header.record_number + skipped;
        let is_dir = entry.is_dir();
        let allocated = entry.is_allocated();

        let mut acc = RecordAttrs::default();
        scan_record(&entry, true, &mut acc);
        for ext_rec in extension_records(&entry, record) {
            if let Some(ext) = resolver.get_entry(&mut parser, ext_rec) {
                if ext.header.base_reference.entry == record {
                    scan_record(&ext, true, &mut acc);
                }
            }
        }
        let Some(best) = best_name(&acc.fn_attrs) else { continue };
        let rel = resolver.resolve(&mut parser, &entry, record, &best);
        if is_dir {
            continue; // directories only feed the resolver
        }
        let rel_lower = rel.to_ascii_lowercase();
        let name_lower = best.name.to_ascii_lowercase();
        if !is_interesting(&rel_lower, &name_lower) {
            continue;
        }
        let full = format!("C:\\{}", rel);
        let size = acc.data_size.unwrap_or(best.logical_size);
        let Some(si) = acc.std_info.as_ref() else { continue };
        let created = iso(si.created.as_second(), si.created.subsec_nanosecond());
        let modified = iso(si.modified.as_second(), si.modified.subsec_nanosecond());
        let fn_created = iso(best.created.as_second(), best.created.subsec_nanosecond());

        let mut notes = Vec::new();
        notes.push(format!("size {}", size));
        notes.push(format!("MFT #{} seq {}", record, entry.header.sequence));
        if let (Some(sc), Some(fc)) = (&created, &fn_created) {
            if sc < fc && si.created.as_second() + 2 < best.created.as_second() {
                notes.push(format!("$SI created before $FN created ({}): copied with old times or timestomped", fc));
            }
        }
        if si.created.subsec_nanosecond() == 0 && si.modified.subsec_nanosecond() == 0 && size > 0 {
            notes.push("zeroed sub-second times".to_string());
        }
        if let Some(bytes) = acc.resident.as_ref() {
            if SCRIPT_EXTENSIONS.contains(&extension(&name_lower).as_str()) {
                let q = quote_content(bytes);
                if !q.is_empty() {
                    notes.push(format!("content: {}", q));
                }
            }
        }
        let prov = if allocated { Provenance::live() } else { Provenance::new(Origin::Deleted, "") };
        let mut push = |ts: String, kind: &str| {
            let artifact = prov.apply(&format!("ntfs:mft:{}", kind));
            if !allocated {
                deleted_rows += 1;
            }
            events.push(Event {
                timestamp: ts,
                computer: computer.to_string(),
                artifact,
                event_id: 0,
                pid: 0,
                subject_username: String::new(),
                target_username: String::new(),
                processname: full.clone(),
                commandline: Some(format!(
                    "File {}{}: {}",
                    kind,
                    if allocated { "" } else { " (record freed, file deleted)" },
                    notes.join("; ")
                )),
                parentprocessname: source.clone(),
            });
        };
        if let Some(c) = created.clone() {
            push(c, "created");
        }
        if let Some(m) = modified {
            let differs = match &created {
                Some(c) => (si.modified.as_second() - si.created.as_second()).abs() > 2 && &m != c,
                None => true,
            };
            if differs {
                push(m, "modified");
            }
        }
    }

    let dirs = resolver.cache.into_iter().map(|(k, v)| (k, v.path)).collect();
    Ok(MftResult { events, dirs, records: count, deleted_rows })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interesting_selection() {
        assert!(is_interesting("users\\bob\\downloads\\a.exe", "a.exe"));
        assert!(!is_interesting("windows\\system32\\cmd.exe", "cmd.exe"));
        assert!(is_interesting("windows\\prefetch\\cmd.exe-aaaaaaaa.pf", "cmd.exe-aaaaaaaa.pf"));
        assert!(is_interesting("windows\\system32\\winevt\\logs\\security.evtx", "security.evtx"));
        assert!(!is_interesting("users\\bob\\notes.txt", "notes.txt"));
        assert!(is_interesting("windows\\temp\\x.ps1", "x.ps1"));
    }

    #[test]
    fn quotes_scripts_compactly() {
        let q = quote_content(b"@echo off\r\n\r\npowershell -enc AAAA\r\n");
        assert_eq!(q, "@echo off powershell -enc AAAA");
        assert!(iso(FILETIME_ZERO_SECS, 0).is_none());
        assert_eq!(iso(1710766331, 0).as_deref(), Some("2024-03-18T12:52:11.000000Z"));
    }
}
