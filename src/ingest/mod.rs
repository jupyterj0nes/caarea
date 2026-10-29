pub mod archive;
pub mod image;
pub mod linux_image;
pub mod live;
pub mod triage;
pub mod vhd;
pub mod vmdk;

use chrono::Local;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::ingest::archive::{inspect_triage_archive, is_supported_archive, unpack_archive_recursive};
use crate::ingest::image::{is_supported_image, unpack_disk_image};
use crate::provenance::Provenance;

/// Logs a message with Caarea branding and a human-readable timestamp
fn log_message(silent: bool, message: &str) {
    if !silent {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        println!("[CAAREA {}] {}", timestamp, message);
    }
}

/// Holds the discovered evidence targets and managed temporary extraction folders
pub struct EvidenceWorkspace {
    pub directories: Vec<String>,
    pub files: Vec<String>,
    /// Hostname hints learnt during ingestion (triage package names), keyed by extracted directory
    pub hostnames: HashMap<String, String>,
    /// Provenance of directories that are not the live evidence (Volume Shadow Copies,
    /// recovered or carved material), keyed by extracted directory
    pub origins: HashMap<String, Provenance>,
    /// Rows produced during ingestion itself (carved structures that are not files)
    pub events: Vec<crate::parsers::evtx::Event>,
    temp_dir: Option<PathBuf>,
}

impl EvidenceWorkspace {
    /// Hostname hint for a directory, if ingestion learnt one
    pub fn hostname_hint(&self, dir: &str) -> Option<&str> {
        self.hostnames.get(dir).map(|s| s.as_str())
    }

    /// Provenance of a directory (shadow copy, recovered, carved), if it is not live evidence
    pub fn origin(&self, dir: &str) -> Option<&Provenance> {
        self.origins.get(dir)
    }
}

impl EvidenceWorkspace {
    /// Cleans up any temporary staging directory created during extraction
    pub fn cleanup(&mut self) {
        if let Some(ref dir) = self.temp_dir {
            if dir.exists() {
                let _ = fs::remove_dir_all(dir);
            }
        }
        self.temp_dir = None;
    }
}

impl Drop for EvidenceWorkspace {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Prepares and expands evidence targets by unpacking forensic archives, triage collections, and disk images
pub fn prepare_evidence(
    raw_dirs: Option<&[String]>,
    raw_files: Option<&[String]>,
    silent: bool,
    stage_dir: Option<&Path>,
    carve: bool,
) -> Result<EvidenceWorkspace, Box<dyn std::error::Error>> {
    let mut directories = Vec::new();
    let mut files = Vec::new();
    let mut hostnames: HashMap<String, String> = HashMap::new();
    let mut origins: HashMap<String, Provenance> = HashMap::new();
    let mut events: Vec<crate::parsers::evtx::Event> = Vec::new();
    let mut archives_to_extract = Vec::new();
    let mut images_to_extract = Vec::new();
    let mut blobs_to_carve: Vec<PathBuf> = Vec::new();

    // 1. Inspect direct files
    if let Some(file_list) = raw_files {
        for f in file_list {
            let path = Path::new(f);
            if live::is_live_volume(f) {
                images_to_extract.push(path.to_path_buf());
            } else if path.exists() {
                if is_supported_image(path) {
                    images_to_extract.push(path.to_path_buf());
                } else if is_supported_archive(path) {
                    archives_to_extract.push(path.to_path_buf());
                } else if carve && !is_known_artifact(path) {
                    // pagefile, memory dump, unallocated dump: nothing to parse, carve it
                    blobs_to_carve.push(path.to_path_buf());
                } else {
                    files.push(f.clone());
                }
            }
        }
    }

    // 2. Inspect directories
    if let Some(dir_list) = raw_dirs {
        for d in dir_list {
            let path = Path::new(d);
            if path.exists() {
                directories.push(d.clone());

                // Scan directory for archive packages and disk images
                for entry in WalkDir::new(path).into_iter().flatten() {
                    let p = entry.path();
                    if p.is_file() {
                        if is_supported_image(p) {
                            if !images_to_extract.contains(&p.to_path_buf()) {
                                images_to_extract.push(p.to_path_buf());
                            }
                        } else if is_supported_archive(p)
                            && !archives_to_extract.contains(&p.to_path_buf()) {
                                archives_to_extract.push(p.to_path_buf());
                            }
                    }
                }
            }
        }
    }

    // 3. Staging directory setup if archives or images need extraction
    let mut temp_staging_dir: Option<PathBuf> = None;

    if !archives_to_extract.is_empty() || !images_to_extract.is_empty() || !blobs_to_carve.is_empty() {
        let staging = match stage_dir {
            Some(dir) => {
                fs::create_dir_all(dir)?;
                log_message(silent, &format!("📁 Extracted artifacts are kept in {}", dir.display()));
                dir.to_path_buf()
            }
            None => {
                let unique_id = format!("caarea_ingest_{}_{}", std::process::id(), chrono::Utc::now().timestamp_millis());
                let staging = env::temp_dir().join(unique_id);
                fs::create_dir_all(&staging)?;
                temp_staging_dir = Some(staging.clone());
                staging
            }
        };

        // Process forensic disk images
        if !images_to_extract.is_empty() {
            log_message(
                silent,
                &format!("💿 Discovered {} forensic disk image(s). Parsing NTFS & VSS...", images_to_extract.len()),
            );

            for img in images_to_extract {
                let mut extracted_root: Option<PathBuf> = None;
                let mut computer = "Unknown".to_string();
                match unpack_disk_image(&img, &staging, silent) {
                    Ok(extraction) => {
                        extracted_root = extraction.live_dir.parent().map(|p| p.to_path_buf());
                        computer = crate::parsers::windows::detect_hostname(&extraction.live_dir, None);
                        directories.push(extraction.live_dir.to_string_lossy().to_string());
                        for (dir, tag) in extraction.shadow_dirs {
                            let d = dir.to_string_lossy().to_string();
                            origins.insert(d.clone(), tag);
                            directories.push(d);
                        }
                    }
                    Err(e) => {
                        log_message(
                            silent,
                            &format!("⚠️ Warning: Failed to extract artifacts from disk image {}: {}", img.display(), e),
                        );
                    }
                }
                if carve {
                    let out_dir = extracted_root
                        .clone()
                        .unwrap_or_else(|| staging.join(img.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "image".to_string())))
                        .join("carved");
                    log_message(silent, &format!("🔪 Carving raw bytes of {}", img.display()));
                    match crate::carve::carve_image(&img, &out_dir, extracted_root.as_deref(), &computer, silent) {
                        Ok(out) => {
                            log_message(silent, &format!("  └─ {}", out.summary()));
                            for (dir, prov) in out.dirs {
                                let d = dir.to_string_lossy().to_string();
                                origins.insert(d.clone(), prov);
                                directories.push(d);
                            }
                            events.extend(out.events);
                        }
                        Err(e) => log_message(silent, &format!("  ⚠️ Carving failed: {}", e)),
                    }
                }
            }
        }

        // Plain files carved as blobs (pagefile, memory dump, unallocated dump)
        for blob in &blobs_to_carve {
            let name = blob.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "blob".to_string());
            let out_dir = staging.join(format!("blob_{}", name.replace(['.', ' '], "_"))).join("carved");
            log_message(silent, &format!("🔪 Carving {} as a raw blob", blob.display()));
            match crate::carve::carve_blob(blob, &out_dir, "Unknown", silent) {
                Ok(out) => {
                    log_message(silent, &format!("  └─ {}", out.summary()));
                    for (dir, prov) in out.dirs {
                        let d = dir.to_string_lossy().to_string();
                        origins.insert(d.clone(), prov);
                        directories.push(d);
                    }
                    events.extend(out.events);
                }
                Err(e) => log_message(silent, &format!("  ⚠️ Carving failed: {}", e)),
            }
        }

        // Process forensic archives and triages
        if !archives_to_extract.is_empty() {
            log_message(
                silent,
                &format!("📦 Discovered {} forensic archive(s) / triage packages. Staging artifacts...", archives_to_extract.len()),
            );

            let pb = if !silent && archives_to_extract.len() > 1 {
                let p = ProgressBar::new(archives_to_extract.len() as u64);
                p.set_style(
                    ProgressStyle::default_bar()
                        .template("[{elapsed_precise}] {bar:40.green/blue} {pos}/{len} Staging forensic archives: {msg}")
                        .unwrap(),
                );
                Some(p)
            } else {
                None
            };

            for archive in &archives_to_extract {
                let name = archive.file_name().unwrap_or_default().to_string_lossy();
                if let Some(ref p) = pb {
                    p.set_message(name.to_string());
                }

                let mut triage_host: Option<String> = None;
                if let Some(info) = inspect_triage_archive(archive) {
                    let host_str = info
                        .hostname
                        .as_deref()
                        .map(|h| format!(" [host: {}]", h))
                        .unwrap_or_default();

                    log_message(
                        silent,
                        &format!(
                            "  ├─ Triage detected: [{}] {}{}",
                            info.kind.label(),
                            name,
                            host_str
                        ),
                    );
                    triage_host = info.hostname;
                }

                match unpack_archive_recursive(archive, &staging, silent) {
                    Ok(extracted_paths) => {
                        for p in extracted_paths {
                            let dir = p.to_string_lossy().to_string();
                            if let Some(ref h) = triage_host {
                                hostnames.insert(dir.clone(), h.clone());
                            }
                            directories.push(dir);
                        }
                    }
                    Err(e) => {
                        log_message(
                            silent,
                            &format!("⚠️ Warning: Failed to extract archive {}: {}", archive.display(), e),
                        );
                    }
                }

                if let Some(ref p) = pb {
                    p.inc(1);
                }
            }

            if let Some(p) = pb {
                p.finish_with_message("Staging complete");
            }
        }
    }

    Ok(EvidenceWorkspace {
        directories,
        files,
        hostnames,
        origins,
        events,
        temp_dir: temp_staging_dir,
    })
}

/// Is a `-f` file something a parser understands (by name or by header)? Anything else is a
/// blob when `--carve` is on.
fn is_known_artifact(path: &Path) -> bool {
    use std::io::Read;
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    if archive::is_relevant_artifact(&name) || crate::parsers::ntfs::is_mft_name(&name) || crate::parsers::ntfs::is_usn_name(&name) {
        return true;
    }
    let mut head = [0u8; 8];
    let n = fs::File::open(path).and_then(|mut f| f.read(&mut head)).unwrap_or(0);
    let head = &head[..n];
    head.starts_with(b"regf") || head.starts_with(b"ElfFile") || crate::parsers::windows::prefetch::is_prefetch(head)
}
