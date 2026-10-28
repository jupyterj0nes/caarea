use chrono::Local;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use vshadow::VssVolume;

use crate::utils::filetime_to_iso;

const NTFS_SIGNATURE: &[u8] = b"NTFS    ";
const BITLOCKER_SIGNATURE: &[u8] = b"-FVE-FS-";

/// Paths to essential forensic execution and registry artifacts inside Windows NTFS
const EVTX_LOGS_PATH: &[&str] = &["Windows", "System32", "winevt", "Logs"];
const REG_CONFIG_PATH: &[&str] = &["Windows", "System32", "config"];
const AMCACHE_PATH: &[&str] = &["Windows", "AppCompat", "Programs"];
const USRCLASS_PATH: &[&str] = &["AppData", "Local", "Microsoft", "Windows"];

/// GPT partition type GUID for Microsoft Basic Data (includes NTFS)
const GPT_BASIC_DATA_GUID: [u8; 16] = [
    0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
    0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
];

/// Logs a message with Caarea branding and a human-readable timestamp
fn log_message(silent: bool, message: &str) {
    if !silent {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        println!("[CAAREA {}] {}", timestamp, message);
    }
}

/// Checks if a file path is a supported forensic disk image
pub fn is_supported_image(path: &Path) -> bool {
    let filename = match path.file_name() {
        Some(n) => n.to_string_lossy().to_lowercase(),
        None => return false,
    };

    // Keep primary .E01 / .Ex01 descriptor and skip split segments (.E02, .E03, etc.)
    if filename.ends_with(".e01") || filename.ends_with(".ex01") {
        return true;
    }

    if filename.ends_with(".dd") || filename.ends_with(".raw") || filename.ends_with(".img") || filename.ends_with(".001") {
        return true;
    }

    false
}

/// Wrapper that adds a byte offset to all Read/Seek operations, enabling partition-level I/O
struct OffsetReader<'a, R: Read + Seek> {
    inner: &'a mut R,
    offset: u64,
}

impl<'a, R: Read + Seek> OffsetReader<'a, R> {
    fn new(inner: &'a mut R, offset: u64) -> Self {
        Self { inner, offset }
    }
}

impl<'a, R: Read + Seek> Read for OffsetReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<'a, R: Read + Seek> Seek for OffsetReader<'a, R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(p) => {
                let actual = self.inner.seek(SeekFrom::Start(self.offset + p))?;
                Ok(actual.saturating_sub(self.offset))
            }
            SeekFrom::Current(p) => {
                let actual = self.inner.seek(SeekFrom::Current(p))?;
                Ok(actual.saturating_sub(self.offset))
            }
            SeekFrom::End(p) => {
                let actual = self.inner.seek(SeekFrom::End(p))?;
                Ok(actual.saturating_sub(self.offset))
            }
        }
    }
}

/// Verifies whether the first bytes at a partition offset match the NTFS boot sector signature
fn verify_ntfs_signature<R: Read + Seek>(reader: &mut R, offset: u64) -> bool {
    if reader.seek(SeekFrom::Start(offset + 3)).is_err() {
        return false;
    }
    let mut sig = [0u8; 8];
    if reader.read_exact(&mut sig).is_err() {
        return false;
    }
    sig == NTFS_SIGNATURE
}

/// Verifies whether a partition is BitLocker encrypted
fn verify_bitlocker_signature<R: Read + Seek>(reader: &mut R, offset: u64) -> bool {
    if reader.seek(SeekFrom::Start(offset + 3)).is_err() {
        return false;
    }
    let mut sig = [0u8; 8];
    if reader.read_exact(&mut sig).is_err() {
        return false;
    }
    sig == BITLOCKER_SIGNATURE
}

/// Locates NTFS partitions by parsing MBR, GPT, and checking common volume offsets
fn find_ntfs_partitions<R: Read + Seek>(reader: &mut R, image_size: u64) -> Result<Vec<u64>, String> {
    let mut partitions = Vec::new();

    if reader.seek(SeekFrom::Start(0)).is_err() {
        return Ok(partitions);
    }

    let mut mbr_buf = [0u8; 512];
    if reader.read_exact(&mut mbr_buf).is_ok() && mbr_buf[510] == 0x55 && mbr_buf[511] == 0xAA {
        let part0_type = mbr_buf[446 + 4];

        if part0_type == 0xEE {
            // GPT disk: parse GPT header and partition array
            if reader.seek(SeekFrom::Start(512)).is_ok() {
                let mut gpt_header = [0u8; 92];
                if reader.read_exact(&mut gpt_header).is_ok() && &gpt_header[0..8] == b"EFI PART" {
                    let part_entry_lba = u64::from_le_bytes(gpt_header[72..80].try_into().unwrap_or([0; 8]));
                    let num_parts = u32::from_le_bytes(gpt_header[80..84].try_into().unwrap_or([0; 4]));
                    let part_size = u32::from_le_bytes(gpt_header[84..88].try_into().unwrap_or([0; 4])) as usize;

                    let part_table_offset = part_entry_lba * 512;
                    if reader.seek(SeekFrom::Start(part_table_offset)).is_ok() {
                        for i in 0..num_parts.min(128) {
                            let entry_offset = part_table_offset + (i as u64 * part_size as u64);
                            if reader.seek(SeekFrom::Start(entry_offset)).is_ok() {
                                let mut entry_buf = vec![0u8; part_size.max(128)];
                                if reader.read_exact(&mut entry_buf).is_ok() {
                                    let type_guid: [u8; 16] = entry_buf[0..16].try_into().unwrap_or([0; 16]);
                                    if type_guid == GPT_BASIC_DATA_GUID {
                                        let first_lba = u64::from_le_bytes(entry_buf[32..40].try_into().unwrap_or([0; 8]));
                                        let part_offset = first_lba * 512;
                                        if part_offset < image_size && verify_ntfs_signature(reader, part_offset) {
                                            partitions.push(part_offset);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            // Standard MBR disk
            let mut cursor = std::io::Cursor::new(&mbr_buf[..]);
            if let Ok(mbr) = mbrman::MBR::read_from(&mut cursor, 512) {
                for (_, part) in mbr.iter() {
                    if !part.is_used() {
                        continue;
                    }
                    let part_offset = part.starting_lba as u64 * 512;
                    if part_offset < image_size && verify_ntfs_signature(reader, part_offset) {
                        partitions.push(part_offset);
                    }
                }
            }
        }
    }

    // Common fallback offsets (raw volume, 1MB alignment, 2048 sectors)
    if partitions.is_empty() {
        for &offset in &[0u64, 1024 * 1024, 2048 * 512, 63 * 512] {
            if offset < image_size && verify_ntfs_signature(reader, offset)
                && !partitions.contains(&offset) {
                    partitions.push(offset);
                }
        }
    }

    Ok(partitions)
}

/// Extracts execution artifacts (EVTX, Registry, Amcache, Users) from an NTFS partition of a disk
fn extract_artifacts_from_ntfs<R: Read + Seek>(
    reader: &mut R,
    partition_offset: u64,
    output_dir: &Path,
    part_idx: usize,
) -> Result<usize, String> {
    let mut part_reader = OffsetReader::new(reader, partition_offset);
    let part_dir = output_dir.join(format!("partition_{}", part_idx));
    extract_artifacts_from_volume(&mut part_reader, &part_dir)
}

/// Extracts execution artifacts (EVTX, Registry, Amcache, Users) from a volume-relative NTFS
/// reader: a partition of the live disk, or a Volume Shadow Copy view of it.
fn extract_artifacts_from_volume<R: Read + Seek>(volume: &mut R, part_dir: &Path) -> Result<usize, String> {
    let mut ntfs = ntfs::Ntfs::new(volume).map_err(|e| format!("Cannot parse NTFS: {}", e))?;
    ntfs.read_upcase_table(volume).map_err(|e| format!("Cannot read upcase table: {}", e))?;

    let root_dir = ntfs.root_directory(volume).map_err(|e| format!("Cannot read root directory: {}", e))?;

    fs::create_dir_all(part_dir).map_err(|e| e.to_string())?;

    let mut total_extracted = 0;

    // 1. Extract Windows EVTX logs (Windows\System32\winevt\Logs)
    if let Ok(evtx_dir) = navigate_to_path(&ntfs, &root_dir, volume, EVTX_LOGS_PATH) {
        if let Ok(count) = dump_files_matching(&ntfs, &evtx_dir, volume, &part_dir.join("Logs"), ".evtx") {
            total_extracted += count;
        }
    }

    // 2. Extract System Registry hives (Windows\System32\config: SYSTEM, SOFTWARE, SAM, SECURITY, and .LOG1/.LOG2)
    if let Ok(config_dir) = navigate_to_path(&ntfs, &root_dir, volume, REG_CONFIG_PATH) {
        if let Ok(count) = dump_registry_config_files(&ntfs, &config_dir, volume, &part_dir.join("config")) {
            total_extracted += count;
        }
    }

    // 3. Extract Amcache.hve and its transaction logs (Windows\AppCompat\Programs\Amcache.hve[.LOG1/.LOG2])
    if let Ok(amcache_dir) = navigate_to_path(&ntfs, &root_dir, volume, AMCACHE_PATH) {
        for suffix in [".hve", ".hve.log1", ".hve.log2"] {
            if let Ok(count) = dump_files_matching(&ntfs, &amcache_dir, volume, &part_dir.join("AppCompat"), suffix) {
                total_extracted += count;
            }
        }
    }

    // 4. Extract User hives (Users\<username>\NTUSER.DAT and UsrClass.dat)
    if let Ok(users_dir) = navigate_to_path(&ntfs, &root_dir, volume, &["Users"]) {
        if let Ok(count) = dump_user_hives(&ntfs, &users_dir, volume, &part_dir.join("Users")) {
            total_extracted += count;
        }
    }

    Ok(total_extracted)
}

/// Navigates through NTFS directories matching a path component array (case-insensitive)
fn navigate_to_path<'a, R: Read + Seek>(
    ntfs: &'a ntfs::Ntfs,
    root: &'a ntfs::NtfsFile<'a>,
    reader: &mut R,
    path_components: &[&str],
) -> Result<ntfs::NtfsFile<'a>, String> {
    let mut current_dir = root.clone();

    for &component in path_components {
        let index = current_dir.directory_index(reader).map_err(|e| e.to_string())?;
        let mut found_ref = None;

        let mut entries = index.entries();
        while let Some(entry_res) = entries.next(reader) {
            let entry = entry_res.map_err(|e| e.to_string())?;
            if let Some(Ok(key)) = entry.key() {
                if key.name().to_string_lossy().eq_ignore_ascii_case(component) {
                    found_ref = Some(entry.file_reference());
                    break;
                }
            }
        }

        match found_ref {
            Some(f_ref) => {
                current_dir = f_ref.to_file(ntfs, reader).map_err(|e| e.to_string())?;
            }
            None => return Err(format!("Directory not found: {}", component)),
        }
    }

    Ok(current_dir)
}

/// Dumps files matching an extension from an NTFS directory to disk
fn dump_files_matching<R: Read + Seek>(
    ntfs: &ntfs::Ntfs,
    dir: &ntfs::NtfsFile,
    reader: &mut R,
    dest: &Path,
    ext_suffix: &str,
) -> Result<usize, String> {
    let _ = fs::create_dir_all(dest);
    let index = dir.directory_index(reader).map_err(|e| e.to_string())?;
    let mut count = 0;

    let mut entries = index.entries();
    while let Some(Ok(entry)) = entries.next(reader) {
        if let Some(Ok(key)) = entry.key() {
            let name = key.name().to_string_lossy().to_string();
            if name.to_lowercase().ends_with(ext_suffix) {
                if let Ok(file) = entry.file_reference().to_file(ntfs, reader) {
                    if dump_ntfs_file_data(&file, reader, &dest.join(&name)).is_ok() {
                        count += 1;
                    }
                }
            }
        }
    }

    Ok(count)
}

/// Dumps SYSTEM, SOFTWARE, SAM, SECURITY, and associated transaction logs from Windows\System32\config
fn dump_registry_config_files<R: Read + Seek>(
    ntfs: &ntfs::Ntfs,
    dir: &ntfs::NtfsFile,
    reader: &mut R,
    dest: &Path,
) -> Result<usize, String> {
    let _ = fs::create_dir_all(dest);
    let index = dir.directory_index(reader).map_err(|e| e.to_string())?;
    let mut count = 0;

    let target_stems = ["SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"];

    let mut entries = index.entries();
    while let Some(Ok(entry)) = entries.next(reader) {
        if let Some(Ok(key)) = entry.key() {
            let name = key.name().to_string_lossy().to_string();
            let upper = name.to_uppercase();

            let matches = target_stems.iter().any(|&stem| {
                upper == stem
                    || upper == format!("{}.LOG", stem)
                    || upper == format!("{}.LOG1", stem)
                    || upper == format!("{}.LOG2", stem)
            });

            if matches {
                if let Ok(file) = entry.file_reference().to_file(ntfs, reader) {
                    if dump_ntfs_file_data(&file, reader, &dest.join(&name)).is_ok() {
                        count += 1;
                    }
                }
            }
        }
    }

    Ok(count)
}

/// Dumps NTUSER.DAT and UsrClass.dat across user profiles in Users directory
fn dump_user_hives<R: Read + Seek>(
    ntfs: &ntfs::Ntfs,
    users_dir: &ntfs::NtfsFile,
    reader: &mut R,
    dest: &Path,
) -> Result<usize, String> {
    let _ = fs::create_dir_all(dest);
    let index = users_dir.directory_index(reader).map_err(|e| e.to_string())?;
    let mut count = 0;

    let mut user_dirs = Vec::new();
    let mut entries = index.entries();
    while let Some(Ok(entry)) = entries.next(reader) {
        if let Some(Ok(key)) = entry.key() {
            let name = key.name().to_string_lossy().to_string();
            if name != "." && name != ".." && !name.starts_with('$') && key.is_directory() {
                user_dirs.push((name, entry.file_reference()));
            }
        }
    }

    for (username, u_ref) in user_dirs {
        if let Ok(user_dir) = u_ref.to_file(ntfs, reader) {
            // NTUSER.DAT (+ .LOG1 / .LOG2) in the profile root
            count += dump_named_hives(ntfs, &user_dir, reader, dest, &username, "NTUSER.DAT");

            // UsrClass.dat (+ .LOG1 / .LOG2) in AppData\Local\Microsoft\Windows
            if let Ok(classes_dir) = navigate_to_path(ntfs, &user_dir, reader, USRCLASS_PATH) {
                count += dump_named_hives(ntfs, &classes_dir, reader, dest, &username, "USRCLASS.DAT");
            }
        }
    }

    Ok(count)
}

/// Dumps every file in `dir` whose upper-cased name starts with `prefix` (hive + transaction logs)
/// as `<username>_<original name>` into `dest`.
fn dump_named_hives<R: Read + Seek>(
    ntfs: &ntfs::Ntfs,
    dir: &ntfs::NtfsFile,
    reader: &mut R,
    dest: &Path,
    username: &str,
    prefix: &str,
) -> usize {
    let mut count = 0;
    let index = match dir.directory_index(reader) {
        Ok(i) => i,
        Err(_) => return 0,
    };
    let mut entries = index.entries();
    while let Some(Ok(entry)) = entries.next(reader) {
        if let Some(Ok(key)) = entry.key() {
            let fname = key.name().to_string_lossy().to_string();
            if fname.to_uppercase().starts_with(prefix) {
                let out_name = format!("{}_{}", username, fname);
                if let Ok(file) = entry.file_reference().to_file(ntfs, reader) {
                    if dump_ntfs_file_data(&file, reader, &dest.join(&out_name)).is_ok() {
                        count += 1;
                    }
                }
            }
        }
    }
    count
}

/// Dumps raw data stream of an NTFS file to an output file path
fn dump_ntfs_file_data<R: Read + Seek>(file: &ntfs::NtfsFile, reader: &mut R, out_path: &Path) -> Result<(), io::Error> {
    let data_item = match file.data(reader, "") {
        Some(Ok(d)) => d,
        _ => return Err(io::Error::new(io::ErrorKind::NotFound, "No data attribute")),
    };

    let data_attr = data_item.to_attribute().map_err(|e| io::Error::other(e.to_string()))?;
    let data_val = data_attr.value(reader).map_err(|e| io::Error::other(e.to_string()))?;
    let mut attached = data_val.attach(reader);

    let mut out_file = File::create(out_path)?;
    let mut buf = [0u8; 65536];

    loop {
        match attached.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out_file.write_all(&buf[..n])?,
            Err(e) => return Err(e),
        }
    }

    Ok(())
}

/// Result of staging a disk image: the live volume artifacts plus one directory per Volume
/// Shadow Copy, each tagged with the snapshot creation time (`vss:2026-09-04T08:12:53Z`).
#[derive(Debug, Clone)]
pub struct ImageExtraction {
    pub live_dir: PathBuf,
    pub shadow_dirs: Vec<(PathBuf, String)>,
}

/// Unpacks forensic execution artifacts from an E01 or RAW disk image into a destination staging directory
pub fn unpack_disk_image(
    image_path: &Path,
    dest_staging: &Path,
    silent: bool,
) -> Result<ImageExtraction, Box<dyn std::error::Error>> {
    let stem = image_path.file_stem().and_then(|s| s.to_str()).unwrap_or("disk_image");
    let out_dir = dest_staging.join(stem);
    let live_dir = out_dir.join("live");
    let vss_root = out_dir.join("vss");
    fs::create_dir_all(&live_dir)?;

    let path_str = image_path.to_string_lossy().to_string();
    let lower = path_str.to_lowercase();

    log_message(silent, &format!("💿 Opening forensic disk image: {}", image_path.display()));

    let shadow_dirs = if lower.ends_with(".e01") || lower.ends_with(".ex01") {
        let ewf_reader = ewf::EwfReader::open(&path_str).map_err(|e| format!("Failed to open E01 image: {}", e))?;
        let total_size = ewf_reader.total_size();
        log_message(
            silent,
            &format!("  ├─ E01 acquired capacity: {:.2} GB", total_size as f64 / 1_073_741_824.0),
        );

        let mut buf_reader = BufReader::new(ewf_reader);
        process_seekable_image(&mut buf_reader, total_size, &live_dir, &vss_root, silent)?
    } else {
        let file = File::open(image_path)?;
        let total_size = file.metadata()?.len();
        log_message(
            silent,
            &format!("  ├─ RAW disk image capacity: {:.2} GB", total_size as f64 / 1_073_741_824.0),
        );

        let mut buf_reader = BufReader::new(file);
        process_seekable_image(&mut buf_reader, total_size, &live_dir, &vss_root, silent)?
    };

    Ok(ImageExtraction { live_dir, shadow_dirs })
}

/// Processes a seekable disk image: locates partitions, extracts artifacts from the live volume
/// and from every Volume Shadow Copy store. Returns the shadow copy directories with their tags.
fn process_seekable_image<R: Read + Seek>(
    reader: &mut R,
    image_size: u64,
    live_dir: &Path,
    vss_root: &Path,
    silent: bool,
) -> Result<Vec<(PathBuf, String)>, Box<dyn std::error::Error>> {
    let partitions = find_ntfs_partitions(reader, image_size).map_err(|e| format!("Partition scan error: {}", e))?;

    if partitions.is_empty() {
        return Err("No valid NTFS partitions found in disk image (check if BitLocker encrypted)".into());
    }

    log_message(
        silent,
        &format!("  ├─ Found {} NTFS partition(s). Extracting forensic execution artifacts...", partitions.len()),
    );

    let mut total_extracted = 0;
    let mut shadow_dirs: Vec<(PathBuf, String)> = Vec::new();

    for (idx, &part_offset) in partitions.iter().enumerate() {
        if verify_bitlocker_signature(reader, part_offset) {
            log_message(
                silent,
                &format!("  ⚠️ Partition {} at offset {:#x} is BitLocker encrypted (skipping)", idx + 1, part_offset),
            );
            continue;
        }

        match extract_artifacts_from_ntfs(reader, part_offset, live_dir, idx) {
            Ok(count) => {
                total_extracted += count;
                log_message(
                    silent,
                    &format!("  ├─ Partition {}: extracted {} execution artifacts (EVTX, Registry, Amcache)", idx + 1, count),
                );
            }
            Err(e) => {
                log_message(
                    silent,
                    &format!("  ⚠️ Warning: Partition {} extraction error: {}", idx + 1, e),
                );
            }
        }

        // Volume Shadow Copies: every store is a full historical view of the volume. Artifacts
        // deleted or rotated since the snapshot (cleared EVTX, old hive values) come back from here.
        let mut part_reader = OffsetReader::new(reader, part_offset);
        let vss = match VssVolume::new(&mut part_reader) {
            Ok(v) if v.store_count() > 0 => v,
            _ => continue,
        };
        log_message(
            silent,
            &format!("  ├─ Partition {}: {} Volume Shadow Copy store(s) detected, extracting each snapshot...", idx + 1, vss.store_count()),
        );

        for s in 0..vss.store_count() {
            let created_iso = vss
                .store_info(s)
                .ok()
                .and_then(|info| filetime_to_iso(info.creation_time))
                .map(|iso| format!("{}Z", &iso[..19]))
                .unwrap_or_else(|| format!("store{}", s));
            let compact: String = created_iso.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
            let store_dir = vss_root.join(format!("partition_{}", idx)).join(format!("vss{:02}_{}", s, compact));

            match vss.store_reader(&mut part_reader, s) {
                Ok(mut store_reader) => match extract_artifacts_from_volume(&mut store_reader, &store_dir) {
                    Ok(count) => {
                        total_extracted += count;
                        log_message(
                            silent,
                            &format!("  │   ├─ VSS store {} (created {}): extracted {} artifacts", s, created_iso, count),
                        );
                        shadow_dirs.push((store_dir, format!("vss:{}", created_iso)));
                    }
                    Err(e) => {
                        log_message(silent, &format!("  │   ⚠️ VSS store {} (created {}): {}", s, created_iso, e));
                    }
                },
                Err(e) => {
                    log_message(silent, &format!("  │   ⚠️ Cannot open VSS store {}: {}", s, e));
                }
            }
        }
    }

    log_message(
        silent,
        &format!(
            "  └─ Disk image extraction completed. Total staged artifacts: {} ({} shadow copies)",
            total_extracted,
            shadow_dirs.len()
        ),
    );

    Ok(shadow_dirs)
}
