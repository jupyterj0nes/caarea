//! EVTX carving (masstin's design): every 64 KB `ElfChnk` chunk is self-contained, so chunks
//! found in unallocated space are validated by parsing them, grouped by provider and glued
//! behind a synthetic `ElfFile` header into files the normal EVTX pipeline reads. Records
//! outside any chunk (`**\0\0` orphans) cannot be rendered without their chunk's templates,
//! but their time and record id are still a trace of a log that was cleared.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

pub const CHUNK_MAGIC: &[u8; 8] = b"ElfChnk\0";
pub const RECORD_MAGIC: &[u8; 4] = b"\x2a\x2a\x00\x00";
pub const CHUNK_SIZE: usize = 65536;
/// Time budget for parsing one candidate chunk: corrupt BinXML can spin the parser.
pub const PEEK_TIMEOUT: Duration = Duration::from_secs(3);
/// FILETIME bounds for plausible records: 2000-01-01 .. 2040-01-01.
const FT_MIN: u64 = 125_911_584_000_000_000;
const FT_MAX: u64 = 138_535_776_000_000_000;

/// Parses a candidate chunk on a helper thread and returns the provider of its first record
/// (`Some("Unknown")` when the chunk parses but no provider is found). `None` rejects it.
pub fn peek_chunk_provider(chunk: Vec<u8>) -> Option<String> {
    if chunk.len() != CHUNK_SIZE || !chunk.starts_with(CHUNK_MAGIC) {
        return None;
    }
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result = std::panic::catch_unwind(move || {
            let mut data = evtx::EvtxChunkData::new(chunk, false).ok()?;
            let settings = std::sync::Arc::new(evtx::ParserSettings::default());
            let mut parsed = data.parse(settings).ok()?;
            let mut provider: Option<String> = None;
            let mut records = 0usize;
            for record in parsed.iter().flatten() {
                records += 1;
                if provider.is_none() {
                    if let Ok(xml) = record.into_xml() {
                        if let Some(start) = xml.data.find("Provider Name=\"") {
                            let after = &xml.data[start + 15..];
                            if let Some(end) = after.find('"') {
                                provider = Some(after[..end].to_string());
                            }
                        }
                    }
                }
                if records >= 3 {
                    break;
                }
            }
            if records == 0 {
                return None;
            }
            Some(provider.unwrap_or_else(|| "Unknown".to_string()))
        })
        .unwrap_or(None);
        let _ = tx.send(result);
    });
    rx.recv_timeout(PEEK_TIMEOUT).ok().flatten()
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

    /// Writes one synthetic file per provider under `out_dir/evtx_<provider>/`.
    /// Returns `(directory, first offset, chunks)` per file.
    pub fn write_all(&self, out_dir: &Path) -> Vec<(PathBuf, u64, usize)> {
        let mut out = Vec::new();
        for (provider, (offset, chunks)) in &self.groups {
            let safe: String = provider.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' }).collect();
            let dir = out_dir.join(format!("evtx_{}", safe));
            let path = dir.join(format!("{}.evtx", safe));
            if write_synthetic_evtx(&path, chunks).is_ok() {
                out.push((dir, *offset, chunks.len()));
            }
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
        assert!(peek_chunk_provider(vec![0u8; CHUNK_SIZE]).is_none());
    }
}
