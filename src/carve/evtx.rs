//! EVTX carving (masstin's design, engine in `blockcarve::evtx`): chunks accepted on their
//! checksums are grouped and written as synthetic files, then validated in a child process
//! because parsing a corrupt chunk can ask the allocator for gigabytes and abort the whole
//! run. Records outside any chunk (`**\0\0` orphans) cannot be rendered without their
//! chunk's templates, but their time and record id are still a trace of a cleared log.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub use blockcarve::evtx::{chunk_checksums_ok, chunk_hashes_under, orphan_record, write_synthetic_evtx, CHUNK_MAGIC, CHUNK_SIZE, RECORD_MAGIC};

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

/// Chunks collected during a scan, grouped by key, deduplicated by content.
#[derive(Default)]
pub struct ChunkGroups {
    inner: blockcarve::evtx::ChunkGroups,
}

impl ChunkGroups {
    /// Chunks of the logs the file-system pass already extracted are never collected.
    pub fn with_known(known: &HashSet<u64>) -> Self {
        ChunkGroups { inner: blockcarve::evtx::ChunkGroups { seen_hashes: known.clone(), ..Default::default() } }
    }

    pub fn add(&mut self, key: String, offset: u64, chunk: Vec<u8>) -> bool {
        self.inner.add(key, offset, chunk)
    }

    /// Writes one synthetic file per group under `out_dir/evtx_<key>/`, validated in a child
    /// process with bisection salvage. Returns `(directory, first offset, chunks kept, chunks
    /// dropped)` per file.
    pub fn write_all(&self, out_dir: &Path) -> Vec<(PathBuf, u64, usize, usize)> {
        let path_for = |key: &str| {
            let safe: String = key.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' }).collect();
            out_dir.join(format!("evtx_{}", safe)).join(format!("{}.evtx", safe))
        };
        self.inner
            .write_all(&path_for, &mut validate_in_child)
            .into_iter()
            .map(|w| (w.path.parent().map(Path::to_path_buf).unwrap_or_else(|| out_dir.to_path_buf()), w.first_offset, w.chunks_kept, w.chunks_dropped))
            .collect()
    }
}
