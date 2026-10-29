//! EVTX carving (masstin's design): every 64 KB `ElfChnk` chunk is self-contained, so chunks
//! found in unallocated space are validated by parsing them, grouped by provider and glued
//! behind a synthetic `ElfFile` header into files the normal EVTX pipeline reads. Records
//! outside any chunk (`**\0\0` orphans) cannot be rendered without their chunk's templates,
//! but their time and record id are still a trace of a log that was cleared.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const CHUNK_MAGIC: &[u8; 8] = b"ElfChnk\0";
pub const RECORD_MAGIC: &[u8; 4] = b"\x2a\x2a\x00\x00";
pub const CHUNK_SIZE: usize = 65536;
/// FILETIME bounds for plausible records: 2000-01-01 .. 2040-01-01.
const FT_MIN: u64 = 125_911_584_000_000_000;
const FT_MAX: u64 = 138_535_776_000_000_000;

/// Is this a chunk worth keeping? Header magic plus the header and data CRC32s that every
/// chunk carries. No record is parsed here: parsing a corrupt chunk can ask the allocator
/// for gigabytes and that aborts the process, so parsing only ever happens in a child.
pub fn chunk_checksums_ok(chunk: &[u8]) -> bool {
    if chunk.len() != CHUNK_SIZE || !chunk.starts_with(CHUNK_MAGIC) {
        return false;
    }
    let free_space = u32::from_le_bytes(chunk[48..52].try_into().unwrap()) as usize;
    if !(512..=CHUNK_SIZE).contains(&free_space) {
        return false;
    }
    evtx::EvtxChunkData::new(chunk.to_vec(), true).is_ok()
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// Writes a synthetic EVTX: 4096-byte `ElfFile` header followed by the chunks.
pub fn write_synthetic_evtx(path: &Path, chunks: &[Vec<u8>]) -> Result<(), String> {
    let mut header = [0u8; 4096];
    header[0..8].copy_from_slice(b"ElfFile\0");
    let last_chunk = chunks.len().saturating_sub(1) as u64;
    header[16..24].copy_from_slice(&last_chunk.to_le_bytes());
    header[32..36].copy_from_slice(&128u32.to_le_bytes());
    header[36..38].copy_from_slice(&1u16.to_le_bytes());
    header[38..40].copy_from_slice(&3u16.to_le_bytes());
    header[40..42].copy_from_slice(&4096u16.to_le_bytes());
    header[42..44].copy_from_slice(&(chunks.len() as u16).to_le_bytes());
    let crc = crc32_ieee(&header[0..120]);
    header[124..128].copy_from_slice(&crc.to_le_bytes());
    let mut out = Vec::with_capacity(4096 + chunks.len() * CHUNK_SIZE);
    out.extend_from_slice(&header);
    for c in chunks {
        if c.len() == CHUNK_SIZE {
            out.extend_from_slice(c);
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, out).map_err(|e| e.to_string())
}

/// Hidden argument the binary accepts to parse one EVTX file in a child process.
pub const VALIDATE_ARG: &str = "--internal-validate-evtx";
/// Time budget for validating one synthetic file in a child process.
pub const VALIDATE_TIMEOUT: Duration = Duration::from_secs(60);

/// Parses an EVTX file completely (what the pipeline will do later). Used inside the child
/// process: a corrupt chunk can make the parser ask for gigabytes, and an allocation failure
/// aborts the whole process, so this never runs in the main one for carved data.
pub fn parse_fully(path: &Path) -> Result<usize, String> {
    let mut parser = evtx::EvtxParser::from_path(path).map_err(|e| e.to_string())?;
    let mut count = 0usize;
    for record in parser.records_json() {
        if record.is_ok() {
            count += 1;
        }
    }
    Ok(count)
}

/// Runs `caarea --internal-validate-evtx <path>` with a time budget. `true` when the file
/// parses to completion without crashing the child.
pub fn validate_in_child(path: &Path) -> bool {
    let Ok(exe) = std::env::current_exe() else { return false };
    let Ok(mut child) = std::process::Command::new(exe)
        .arg(VALIDATE_ARG)
        .arg(path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        return false;
    };
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => {
                if start.elapsed() > VALIDATE_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return false,
        }
    }
}

/// Chunks collected during a scan, grouped by provider, with the offset of the first one.
#[derive(Default)]
pub struct ChunkGroups {
    pub groups: BTreeMap<String, (u64, Vec<Vec<u8>>)>,
    pub seen_hashes: std::collections::HashSet<u64>,
}

impl ChunkGroups {
    pub fn add(&mut self, provider: String, offset: u64, chunk: Vec<u8>) -> bool {
        let hash = super::hive::content_hash(&chunk);
        if !self.seen_hashes.insert(hash) {
            return false;
        }
        let entry = self.groups.entry(provider).or_insert_with(|| (offset, Vec::new()));
        entry.1.push(chunk);
        true
    }

    /// Writes one synthetic file per provider under `out_dir/evtx_<provider>/`, validated
    /// in a child process. A file the child cannot parse is rebuilt from the chunks that
    /// pass on their own; the rest are dropped. Returns `(directory, first offset, chunks
    /// kept, chunks dropped)` per file.
    pub fn write_all(&self, out_dir: &Path) -> Vec<(PathBuf, u64, usize, usize)> {
        let mut out = Vec::new();
        for (provider, (offset, chunks)) in &self.groups {
            let safe: String = provider.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' }).collect();
            let dir = out_dir.join(format!("evtx_{}", safe));
            let path = dir.join(format!("{}.evtx", safe));
            if write_synthetic_evtx(&path, chunks).is_err() {
                continue;
            }
            if validate_in_child(&path) {
                out.push((dir, *offset, chunks.len(), 0));
                continue;
            }
            // salvage by bisection: a bad chunk costs log2(n) child runs, not n
            let probe = dir.join("probe.evtx");
            let mut good: Vec<Vec<u8>> = Vec::new();
            let mut stack: Vec<&[Vec<u8>]> = vec![chunks.as_slice()];
            while let Some(part) = stack.pop() {
                if part.is_empty() {
                    continue;
                }
                if write_synthetic_evtx(&probe, part).is_ok() && validate_in_child(&probe) {
                    good.extend(part.iter().cloned());
                } else if part.len() > 1 {
                    let (a, b) = part.split_at(part.len() / 2);
                    stack.push(b);
                    stack.push(a);
                }
            }
            let _ = std::fs::remove_file(&probe);
            let dropped = chunks.len() - good.len();
            if good.is_empty() || write_synthetic_evtx(&path, &good).is_err() {
                let _ = std::fs::remove_dir_all(&dir);
                continue;
            }
            out.push((dir, *offset, good.len(), dropped));
        }
        out
    }
}

/// Hashes of every chunk of every EVTX file under `dir` (the logs the file-system pass
/// already extracted), so the carver can tell a live chunk from a lost one.
pub fn chunk_hashes_under(dir: &Path) -> std::collections::HashSet<u64> {
    let mut out = std::collections::HashSet::new();
    for entry in walkdir::WalkDir::new(dir).into_iter().flatten() {
        if !entry.file_type().is_file() || !entry.file_name().to_string_lossy().to_ascii_lowercase().ends_with(".evtx") {
            continue;
        }
        let Ok(bytes) = std::fs::read(entry.path()) else { continue };
        if !bytes.starts_with(b"ElfFile") {
            continue;
        }
        let mut pos = 4096;
        while pos + CHUNK_SIZE <= bytes.len() {
            if bytes[pos..].starts_with(CHUNK_MAGIC) {
                out.insert(super::hive::content_hash(&bytes[pos..pos + CHUNK_SIZE]));
            }
            pos += CHUNK_SIZE;
        }
    }
    out
}

/// An orphan record header outside any chunk: `(record id, FILETIME, size)`.
pub fn orphan_record(buf: &[u8]) -> Option<(u64, u64, u32)> {
    if buf.len() < 28 || !buf.starts_with(RECORD_MAGIC) {
        return None;
    }
    let size = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    if !(28..=65024).contains(&size) || size as usize > buf.len() {
        return None;
    }
    let trail = size as usize - 4;
    if u32::from_le_bytes(buf[trail..trail + 4].try_into().unwrap()) != size {
        return None;
    }
    if buf[24] != 0x0F {
        return None;
    }
    let ft = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    if !(FT_MIN..FT_MAX).contains(&ft) {
        return None;
    }
    let id = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    Some((id, ft, size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_header_and_orphan_validation() {
        let dir = std::env::temp_dir().join(format!("caarea_evtxc_{}", std::process::id()));
        let path = dir.join("x.evtx");
        write_synthetic_evtx(&path, &[vec![0u8; CHUNK_SIZE]]).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 4096 + CHUNK_SIZE);
        assert_eq!(&bytes[..8], b"ElfFile\0");
        assert_eq!(u16::from_le_bytes([bytes[42], bytes[43]]), 1);
        let _ = std::fs::remove_dir_all(&dir);

        let mut rec = vec![0u8; 64];
        rec[0..4].copy_from_slice(RECORD_MAGIC);
        rec[4..8].copy_from_slice(&64u32.to_le_bytes());
        rec[8..16].copy_from_slice(&4242u64.to_le_bytes());
        rec[16..24].copy_from_slice(&133_552_399_310_000_000u64.to_le_bytes());
        rec[24] = 0x0F;
        rec[60..64].copy_from_slice(&64u32.to_le_bytes());
        assert_eq!(orphan_record(&rec), Some((4242, 133_552_399_310_000_000, 64)));
        rec[60] = 0;
        assert!(orphan_record(&rec).is_none());
        assert!(!chunk_checksums_ok(&vec![0u8; CHUNK_SIZE]));
        let mut fake = vec![0u8; CHUNK_SIZE];
        fake[..8].copy_from_slice(CHUNK_MAGIC);
        assert!(!chunk_checksums_ok(&fake), "a chunk with zeroed checksums must be rejected");
    }
}
