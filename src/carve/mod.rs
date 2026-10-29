//! Carving engine: read raw bytes (disk images, live volumes, pagefiles, memory dumps, any
//! blob) and find self-describing structures that no file system points to any more.
//!
//! The block scanner ([`scan`]) and the guarded block sources ([`source`]) are the design
//! shared by masstin's EVTX carver, faramir's registry carver and allymacb's NTFS carver:
//! 4 MB blocks, sector-aligned signatures, a carry-over tail so a structure split between two
//! reads is seen whole, and reads that cannot hang the run. Validators live in one module per
//! structure and only accept what proves itself: hive bin chains and root key, EVTX chunks
//! that parse, NTFS fixup arrays, journal records with coherent lengths and times.
//!
//! Carving is opt-in (`--carve`). Whole hives and EVTX chunks are written to the staging
//! folder and go through the normal parsers; small structures (MFT records, index entries,
//! journal records, Prefetch files, orphan event records) become rows directly. Every row
//! carries the `carved` origin with the byte offset and, inside a pagefile or a blob, the
//! container's name.

pub mod evtx;
pub mod hive;
pub mod ntfs;
pub mod scan;
pub mod source;

pub use scan::{scan_signatures, HitAction, ScanConfig, ScanStats};
pub use source::{BlockError, BlockSource, DirectSource, GuardedSource, MemorySource};

use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};

use crate::parsers::evtx::Event;
use crate::parsers::windows::prefetch;
use crate::provenance::Provenance;
use crate::utils::filetime_to_iso;

/// Time budget for one block read on an EWF image before the reader is abandoned.
pub const EWF_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Bytes after a signature handed to the validators (prefetch files are the largest).
const WINDOW: usize = 256 << 10;

/// Opens a disk image, a live volume or a plain file as a block source.
pub fn open_source(path: &Path) -> Result<Box<dyn BlockSource>, String> {
    let label = path.display().to_string();
    let lower = label.to_lowercase();
    let fail = |e: String| format!("{label}: {e}");
    if crate::ingest::live::is_live_volume(&label) {
        let (reader, size) = crate::ingest::live::open_live_volume(&label)?;
        return Ok(Box::new(DirectSource::new(reader, size, label)));
    }
    if lower.ends_with(".e01") || lower.ends_with(".ex01") {
        let reader = ewf::EwfReader::open(path).map_err(|e| fail(e.to_string()))?;
        let size = reader.total_size();
        let reopen_path = path.to_path_buf();
        let src = GuardedSource::new(reader, size, label.clone(), EWF_READ_TIMEOUT, move || {
            ewf::EwfReader::open(&reopen_path).map_err(|e| e.to_string())
        });
        return Ok(Box::new(src));
    }
    if lower.ends_with(".vmdk") {
        let reader = crate::ingest::vmdk::VmdkReader::open(&label).map_err(fail)?;
        let size = reader.total_size();
        return Ok(Box::new(DirectSource::new(reader, size, label)));
    }
    if lower.ends_with(".vhd") || lower.ends_with(".vhdx") {
        let (reader, size) = crate::ingest::vhd::open_virtual_disk(&label).map_err(fail)?;
        return Ok(Box::new(DirectSource::new(reader, size, label)));
    }
    let file = std::fs::File::open(path).map_err(|e| fail(e.to_string()))?;
    let size = file.metadata().map_err(|e| fail(e.to_string()))?.len();
    if size == 0 {
        return Err(fail("empty file".to_string()));
    }
    Ok(Box::new(DirectSource::new(std::io::BufReader::new(file), size, label)))
}

/// `Read + Seek` over a block source, for the NTFS reader used to reach pagefiles.
struct SourceReader<'a> {
    src: &'a mut dyn BlockSource,
    pos: u64,
    base: u64,
}

impl Read for SourceReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let data = self.src.read_block(self.base + self.pos, buf.len()).map_err(|e| std::io::Error::other(e.to_string()))?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for SourceReader<'_> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let size = self.src.size().saturating_sub(self.base);
        let new = match pos {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(d) => size as i128 + d as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if new < 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "seek before start"));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

#[derive(Debug, Default, Clone)]
pub struct CarveStats {
    pub bytes_read: u64,
    pub signatures: usize,
    pub hives: usize,
    pub hives_known: usize,
    pub hives_duplicate: usize,
    pub hives_rejected: usize,
    pub evtx_chunks: usize,
    pub evtx_files: usize,
    pub orphan_records: usize,
    pub file_records: usize,
    pub indx_entries: usize,
    pub usn_records: usize,
    pub prefetch: usize,
    pub read_errors: usize,
    pub stalls: usize,
}

/// What one carving pass produced: directories with synthetic files for the normal parsers,
/// rows produced directly, and a one-line summary.
#[derive(Default)]
pub struct CarveOutput {
    pub dirs: Vec<(PathBuf, Provenance)>,
    pub events: Vec<Event>,
    pub stats: CarveStats,
}

impl CarveOutput {
    pub fn summary(&self) -> String {
        let s = &self.stats;
        let mut parts = Vec::new();
        if s.hives > 0 || s.hives_known > 0 || s.hives_duplicate > 0 {
            parts.push(format!("{} hive(s) carved ({} identical to extracted, {} duplicate)", s.hives, s.hives_known, s.hives_duplicate));
        }
        if s.evtx_chunks > 0 {
            parts.push(format!("{} EVTX chunk(s) in {} synthetic file(s)", s.evtx_chunks, s.evtx_files));
        }
        if s.orphan_records > 0 {
            parts.push(format!("{} orphan event record(s)", s.orphan_records));
        }
        if s.file_records > 0 || s.indx_entries > 0 || s.usn_records > 0 {
            parts.push(format!("{} MFT record(s), {} index entries, {} journal records", s.file_records, s.indx_entries, s.usn_records));
        }
        if s.prefetch > 0 {
            parts.push(format!("{} prefetch file(s)", s.prefetch));
        }
        if s.read_errors > 0 || s.stalls > 0 {
            parts.push(format!("{} read error(s), {} stall(s)", s.read_errors, s.stalls));
        }
        if parts.is_empty() {
            parts.push("nothing recovered".to_string());
        }
        format!("{} ({} MB scanned, {} signature(s))", parts.join("; "), s.bytes_read >> 20, s.signatures)
    }
}

const SIGNATURES: [&[u8]; 9] = [
    hive::REGF_MAGIC,
    evtx::CHUNK_MAGIC,
    ntfs::FILE_MAGIC,
    ntfs::INDX_MAGIC,
    prefetch::MAM_MAGIC,
    b"\x1e\0\0\0SCCA",
    b"\x1a\0\0\0SCCA",
    b"\x17\0\0\0SCCA",
    b"\x11\0\0\0SCCA",
];

fn progress_bar(size: u64, silent: bool, label: &str) -> ProgressBar {
    if silent {
        return ProgressBar::hidden();
    }
    let pb = ProgressBar::new(size);
    pb.set_style(
        ProgressStyle::with_template("  🔪 [{bar:30.cyan/blue}] {bytes}/{total_bytes} ({eta}) {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("=> "),
    );
    pb.set_message(label.to_string());
    pb
}

/// Scans one source end to end. `known` holds fingerprints of hives already extracted by
/// the file-system pass; `container` names a pagefile or blob (None for the disk itself).
pub fn carve_source(
    src: &mut dyn BlockSource,
    out_dir: &Path,
    known: &HashSet<String>,
    known_chunks: &HashSet<u64>,
    container: Option<&str>,
    computer: &str,
    silent: bool,
) -> CarveOutput {
    let label = src.label().to_string();
    let source_name = container.map(|c| c.to_string()).unwrap_or_else(|| Path::new(&label).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or(label.clone()));
    let mut out = CarveOutput::default();
    let mut seen_hives: HashSet<String> = HashSet::new();
    let mut groups = evtx::ChunkGroups { seen_hashes: known_chunks.clone(), ..Default::default() };
    // ranges of chunks accepted so far: records inside them are not orphans
    let chunk_ranges: std::cell::RefCell<Vec<(u64, u64)>> = std::cell::RefCell::new(Vec::new());
    let in_container = container.is_some();
    let pb = progress_bar(src.size(), silent, &source_name);
    let cfg = ScanConfig { window: WINDOW, ..Default::default() };

    let stats = &mut out.stats;
    let events = &mut out.events;
    let dirs = &mut out.dirs;
    let tag = |offset: u64| Provenance::carved(offset, container);

    let mut on_hit = |src: &mut dyn BlockSource, offset: u64, window: &[u8], which: usize| -> HitAction {
        match which {
            0 => {
                let header = match hive::validate_base_block(window) {
                    Ok(h) => h,
                    Err(_) => {
                        stats.hives_rejected += 1;
                        return HitAction::Continue;
                    }
                };
                let raw = match hive::read_hive(src, offset, &header) {
                    Ok(r) => r,
                    Err(_) => {
                        stats.hives_rejected += 1;
                        return HitAction::Continue;
                    }
                };
                let resume = offset + raw.recovered_len as u64;
                let fp = hive::fingerprint(&header, raw.content_hash);
                if known.contains(&fp) {
                    stats.hives_known += 1;
                    return HitAction::SkipTo(resume);
                }
                if !seen_hives.insert(fp) {
                    stats.hives_duplicate += 1;
                    return HitAction::SkipTo(resume);
                }
                let dir = out_dir.join(format!("hive_{:012x}", offset));
                if hive::write_carved(&dir, &header, &raw).is_ok() {
                    stats.hives += 1;
                    let mut prov = tag(offset);
                    prov.detail = format!("{} {}{}", prov.detail, header.file_name(), if raw.complete { "" } else { " truncated" });
                    dirs.push((dir, prov));
                    pb.set_message(format!("{}: {} hive(s)", source_name, stats.hives));
                }
                HitAction::SkipTo(resume)
            }
            1 => {
                if window.len() < evtx::CHUNK_SIZE {
                    return HitAction::Continue;
                }
                let chunk = window[..evtx::CHUNK_SIZE].to_vec();
                // a chunk identical to one of an extracted EVTX is the live log itself
                if known_chunks.contains(&hive::content_hash(&chunk)) {
                    chunk_ranges.borrow_mut().push((offset, offset + evtx::CHUNK_SIZE as u64));
                    return HitAction::SkipTo(offset + evtx::CHUNK_SIZE as u64);
                }
                match evtx::peek_chunk_provider(chunk.clone()) {
                    Some(provider) => {
                        chunk_ranges.borrow_mut().push((offset, offset + evtx::CHUNK_SIZE as u64));
                        if groups.add(provider, offset, chunk) {
                            stats.evtx_chunks += 1;
                            pb.set_message(format!("{}: {} EVTX chunk(s)", source_name, stats.evtx_chunks));
                        }
                        HitAction::SkipTo(offset + evtx::CHUNK_SIZE as u64)
                    }
                    None => HitAction::Continue,
                }
            }
            2 => match ntfs::file_record_size(window) {
                Some(size) => {
                    // on the disk itself an allocated record is the live $MFT (already parsed);
                    // only freed records, or any record inside a pagefile or blob, are news
                    let allocated = window[22] & 0x01 != 0;
                    if allocated && !in_container {
                        return HitAction::SkipTo(offset + size as u64);
                    }
                    let rows = ntfs::file_record_events(&window[..size], computer, &source_name);
                    if !rows.is_empty() {
                        stats.file_records += 1;
                        let prov = tag(offset);
                        events.extend(rows.into_iter().map(|mut e| {
                            e.artifact = prov.apply(&e.artifact);
                            e
                        }));
                    }
                    HitAction::SkipTo(offset + size as u64)
                }
                None => HitAction::Continue,
            },
            3 => match ntfs::parse_indx_block(window) {
                Some((size, entries)) => {
                    let rows = ntfs::indx_events(&entries, computer, &source_name);
                    stats.indx_entries += rows.len();
                    let prov = tag(offset);
                    events.extend(rows.into_iter().map(|mut e| {
                        e.artifact = prov.apply(&e.artifact);
                        e
                    }));
                    HitAction::SkipTo(offset + size as u64)
                }
                None => HitAction::Continue,
            },
            _ => {
                let parsed = std::panic::catch_unwind(|| prefetch::parse(window)).ok().and_then(|r| r.ok());
                match parsed {
                    Some(pf) if !pf.last_runs.is_empty() && !pf.executable.is_empty() => {
                        stats.prefetch += 1;
                        let prov = tag(offset);
                        let name = format!("{}-carved.pf", pf.executable);
                        events.extend(prefetch::events_for(&pf, &name, computer).into_iter().map(|mut e| {
                            e.artifact = prov.apply(&e.artifact);
                            e.parentprocessname = format!("{} [{}]", name, source_name);
                            e
                        }));
                        HitAction::SkipTo(offset + 512)
                    }
                    _ => HitAction::Continue,
                }
            }
        }
    };

    // 8-byte aligned structures without a sector-aligned signature: USN records and orphan
    // EVTX records. Checked per block (a record cut by a block boundary is missed).
    let mut block_events: Vec<Event> = Vec::new();
    let mut orphan_count = 0usize;
    let mut usn_count = 0usize;
    let mut on_block = |base: u64, block: &[u8]| {
        let mut pos = 0usize;
        while pos + 60 <= block.len() {
            let b = &block[pos..];
            if b[0] == 0x2a && b[1] == 0x2a && b[2] == 0 && b[3] == 0 {
                let abs = base + pos as u64;
                if chunk_ranges.borrow().iter().any(|&(s, e)| abs >= s && abs < e) {
                    pos += 8;
                    continue;
                }
                if let Some((id, ft, size)) = evtx::orphan_record(b) {
                    if let Some(ts) = filetime_to_iso(ft) {
                        orphan_count += 1;
                        block_events.push(Event {
                            timestamp: ts,
                            computer: computer.to_string(),
                            artifact: tag(base + pos as u64).apply("evtx:orphan_record"),
                            event_id: 0,
                            pid: 0,
                            subject_username: String::new(),
                            target_username: String::new(),
                            processname: "orphan EVTX record".to_string(),
                            commandline: Some(format!("Event record {} ({} bytes) outside any chunk: content not renderable, the log it belonged to was cleared or deleted", id, size)),
                            parentprocessname: source_name.clone(),
                        });
                        pos += (size as usize).max(8) & !7;
                        continue;
                    }
                }
            } else if (b[4] == 2 || b[4] == 3) && b[5] == 0 && b[6] == 0 && b[7] == 0 {
                if let Some(rec) = ntfs::usn_candidate(b) {
                    let len = rec.length;
                    if let Some(mut e) = ntfs::usn_events(&rec, computer, &source_name) {
                        e.artifact = tag(base + pos as u64).apply(&e.artifact);
                        block_events.push(e);
                        usn_count += 1;
                    }
                    pos += len.max(8);
                    continue;
                }
            }
            pos += 8;
        }
    };

    let mut on_progress = |offset: u64, _size: u64| pb.set_position(offset);
    let scan_stats = scan::scan_many(src, &cfg, &SIGNATURES, &mut on_hit, &mut on_progress, Some(&mut on_block));
    pb.finish_and_clear();

    events.extend(block_events);
    stats.orphan_records = orphan_count;
    stats.usn_records = usn_count;
    stats.bytes_read = scan_stats.bytes_read;
    stats.signatures = scan_stats.signatures;
    stats.read_errors = scan_stats.read_errors;
    stats.stalls = scan_stats.stalls.max(src.stalls());

    for (dir, first_offset, chunks) in groups.write_all(out_dir) {
        let mut prov = Provenance::carved(first_offset, container);
        prov.detail = format!("{} {} chunk(s)", prov.detail, chunks);
        dirs.push((dir, prov));
        stats.evtx_files += 1;
    }
    out
}

/// Carves a disk image or live volume: the whole device first, then the pagefile, swapfile
/// and hiberfil of every NTFS partition (allocated files the file-system pass never parses).
pub fn carve_image(image_path: &Path, out_dir: &Path, extracted_root: Option<&Path>, computer: &str, silent: bool) -> Result<CarveOutput, String> {
    let mut src = open_source(image_path)?;
    let known = extracted_root.map(hive::fingerprints_under).unwrap_or_default();
    let known_chunks = extracted_root.map(evtx::chunk_hashes_under).unwrap_or_default();
    let mut out = carve_source(&mut *src, out_dir, &known, &known_chunks, None, computer, silent);

    // containers inside NTFS partitions
    let size = src.size();
    let partitions = {
        let mut reader = SourceReader { src: &mut *src, pos: 0, base: 0 };
        crate::ingest::image::find_ntfs_partitions(&mut reader, size).unwrap_or_default()
    };
    for (idx, part_offset) in partitions.into_iter().enumerate() {
        for name in ["pagefile.sys", "swapfile.sys", "hiberfil.sys"] {
            let container_dir = out_dir.join(format!("partition_{}_{}", idx, name.replace('.', "_")));
            match carve_ntfs_file(&mut *src, part_offset, name, &container_dir, &known, &known_chunks, computer, silent) {
                Ok(Some(o)) => {
                    out.dirs.extend(o.dirs);
                    out.events.extend(o.events);
                    let s = &o.stats;
                    out.stats.hives += s.hives;
                    out.stats.evtx_chunks += s.evtx_chunks;
                    out.stats.evtx_files += s.evtx_files;
                    out.stats.orphan_records += s.orphan_records;
                    out.stats.file_records += s.file_records;
                    out.stats.indx_entries += s.indx_entries;
                    out.stats.usn_records += s.usn_records;
                    out.stats.prefetch += s.prefetch;
                    out.stats.bytes_read += s.bytes_read;
                }
                Ok(None) => {}
                Err(e) => {
                    if !silent {
                        println!("  ⚠️ {} on partition {}: {}", name, idx + 1, e);
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Carves one file of an NTFS partition in place (its data runs are read through the NTFS
/// reader, nothing is extracted). `Ok(None)` when the file does not exist.
#[allow(clippy::too_many_arguments)]
fn carve_ntfs_file(
    src: &mut dyn BlockSource,
    part_offset: u64,
    name: &str,
    out_dir: &Path,
    known: &HashSet<String>,
    known_chunks: &HashSet<u64>,
    computer: &str,
    silent: bool,
) -> Result<Option<CarveOutput>, String> {
    let mut reader = SourceReader { src, pos: 0, base: part_offset };
    let out = ntfs::with_root_file(&mut reader, name, |data, size| {
        if size == 0 {
            return None;
        }
        let mut container = DirectSource::new(data, size, name.to_string());
        Some(carve_source(&mut container, out_dir, known, known_chunks, Some(name), computer, silent))
    })?;
    Ok(out.flatten())
}

/// Carves a plain file (pagefile.sys copied out, memory dump, unallocated-space dump).
pub fn carve_blob(path: &Path, out_dir: &Path, computer: &str, silent: bool) -> Result<CarveOutput, String> {
    let mut src = open_source(path)?;
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "blob".to_string());
    Ok(carve_source(&mut *src, out_dir, &HashSet::new(), &HashSet::new(), Some(&name), computer, silent))
}
