//! Carving engine: read raw bytes (disk images, pagefiles, memory dumps, any blob) and find
//! self-describing structures that no file system points to any more.
//!
//! The block scanner ([`scan`]) and the guarded block sources ([`source`]) are the design
//! shared by masstin's EVTX carver, faramir's registry carver and allymacb's NTFS carver,
//! ported here so the four tools behave the same way: 4 MB blocks, sector-aligned
//! signatures, a carry-over tail so a structure split between two reads is seen whole, and
//! reads that cannot hang the run. Validators for each structure live in their own modules
//! and only ever accept what proves itself (bin chains, fixup arrays, parsed records).
//!
//! Carving is opt-in (`--carve`); recovered rows carry the `carved` provenance.

#![allow(dead_code)]

pub mod scan;
pub mod source;

pub use scan::{scan_signatures, HitAction, ScanConfig, ScanStats};
pub use source::{BlockError, BlockSource, DirectSource, GuardedSource, MemorySource};

use std::path::Path;
use std::time::Duration;

/// Time budget for one block read on an EWF image before the reader is abandoned.
pub const EWF_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Opens a disk image or plain file as a block source, by extension: E01/Ex01 through a
/// guarded reader (a damaged segment can spin the decoder forever), VMDK and VHD/VHDX
/// through their virtual-disk readers, anything else as a raw file.
pub fn open_source(path: &Path) -> Result<Box<dyn BlockSource>, String> {
    let label = path.display().to_string();
    let lower = label.to_lowercase();
    let fail = |e: String| format!("{label}: {e}");
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
